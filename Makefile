CFLAGS += -Wall -O2
LDFLAGS += -Wall -O2
#CPPFLAGS += -DNDEBUG

APPS = udp_authdns_stress
OBJECTS = udp_authdns_stress.o

udp_authdns_stress: udp_authdns_stress.o

.PHONY: clean
clean:
	$(RM) $(APPS) $(OBJECTS)


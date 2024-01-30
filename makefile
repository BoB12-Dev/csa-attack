LDLIBS += -lpcap

all: csa_attack

deauth_attack: csa_attack.c

clean:
	rm -f csa_attack *.o
CC=gcc
LUDEV=-ludev
LCRYPT=-lcrypt
CFLAGS=-Wall

all: sield passwd-sield

sield: sield.o sield-log.o
	$(CC) $(CFLAGS) $(LUDEV) -o $@ $^

passwd-sield: sield-config.o sield-log.o sield-passwd-update.o sield-passwd-check.o
	$(CC) $(CFLAGS) $(LUDEV) $(LCRYPT) -o $@ $^

clean:
	rm -f *.o
	rm -f passwd-sield
	rm -f sield

CC=gcc
LUDEV=-ludev
LCRYPT=-lcrypt
CFLAGS=-Wall
GTK_CFLAGS=`pkg-config --cflags gtk+-2.0`
GTK_LDFLAGS=`pkg-config --libs gtk+-2.0` -rdynamic

all: sield passwd-sield

sield: sield.o sield-av.o sield-config.o sield-daemon.o sield-log.o sield-mount.o \
	sield-passwd-check.o sield-passwd-dialog-gtk2.o sield-udev-helper.o
	$(CC) $(CFLAGS) $(LUDEV) $(LCRYPT) $(GTK_LDFLAGS) -o $@ $^

passwd-sield: sield-config.o sield-log.o sield-passwd-update.o sield-passwd-check.o
	$(CC) $(CFLAGS) $(LUDEV) $(LCRYPT) -o $@ $^

sield-passwd-dialog-gtk2.o: sield-passwd-dialog-gtk2.c
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -c -o $@ $^

install:
	cp 999-sield-prevent-automount.rules /etc/udev/rules.d/

clean:
	rm -f *.o
	rm -f passwd-sield
	rm -f sield

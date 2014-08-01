CC=gcc
LUDEV=-ludev
LCRYPT=-lcrypt
CFLAGS=-Wall
GTK_CFLAGS=`pkg-config --cflags gtk+-2.0`
GTK_LDFLAGS=`pkg-config --libs gtk+-2.0` -rdynamic

all: sield passwd-sield sld

sield: sield.o sield-av.o sield-config.o sield-daemon.o sield-log.o sield-mount.o \
	sield-passwd-check.o sield-passwd-ask.o sield-passwd-cli.o sield-passwd-gui.o \
	sield-pid.o	sield-share.o sield-udev-helper.o
	$(CC) $(CFLAGS) $(LUDEV) $(LCRYPT) $(GTK_LDFLAGS) -o $@ $^

passwd-sield: sield-config.o sield-log.o sield-passwd-update.o \
	sield-passwd-check.o sield-passwd-cli-get.o
	$(CC) $(CFLAGS) $(LUDEV) $(LCRYPT) -o $@ $^

sld: sield-sld.o sield-log.o sield-config.o sield-passwd-cli-get.o
	$(CC) $(CFLAGS) $(LUDEV) -o $@ $^

sield-passwd-gui.o: sield-passwd-gui.c
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -c -o $@ $^

install:
	mkdir /etc/sield/
	cp sield.conf /etc/sield/
	cp sield sld passwd-sield /usr/bin/

uninstall:
	rm -f /usr/bin/sield
	rm -f /usr/bin/sld
	rm -f /usr/bin/passwd-sield
	rm -rf /etc/sield/

clean:
	rm -f *.o
	rm -f passwd-sield
	rm -f sield
	rm -f sld

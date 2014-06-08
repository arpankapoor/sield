CFLAGS=-Wall -ludev

sield: sield.o sield-log.o
	cc -Wall -ludev -o sield sield.o sield-log.o

sield.o sield-log.o: sield.h

clean:
	rm -f *.o
	rm -f sield

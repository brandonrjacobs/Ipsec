#ipsec_ah.mk
#
#!/bin/sh

all:	ipsec_ah inbound-IPSecAH outbound-IPSecAH

clean:
	rm -f inbound-IPSecAH outbound-IPSecAH
	rm -f ipsec_ah ipsec_ah.o md5.o libipsec_ah.o libmd5.a libipsec_ah.a

ipsec_ah:
	cc -c md5.c
	ar rc libmd5.a md5.o
	cc -c libipsec_ah.c
	ar rc libipsec_ah.a libipsec_ah.o
	cc -o ipsec_ah ipsec_ah.c -L. -lipsec_ah -lmd5
	sh if [ ! -e inbound-IPSecAH ]
	then
		ln -s ipsec_ah inbound-IPSecAH
	fi
	sh if [ ! -e outbound-IPSecAH ]
	then
		ln -s ipsec_ah outbound-IPSecAH
	fi

inbound-IPSecAH:
	ln -s ipsec_ah inbound-IPSecAH

outbound-IPSecAH:
	ln -s ipsec_ah outbound-IPSecAH


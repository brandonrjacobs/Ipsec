
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ifaddrs.h>
#include <signal.h>

#include "md5.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netipsec/ah.h>

#include <net/if.h>

#include <netdb.h>


unsigned short ip_checksum (struct ip *ip, int length);
void zero_mutable_fields (struct ip *ip_hdr);
void restore_mutable_fields (struct ip *old_hdr, struct ip *new_hdr);
int is_ip_option_mutable (unsigned char opt);
void hmac_md5 (const unsigned char *text, int text_len, const unsigned char *key, int key_len, unsigned char *digest);


/*
 * ipChecksum - compute the IP header checksum (16-bit)
 *
 * The algorithm to compute the IP checksum is byte-order independent but
 * the resultant checksum value needs to be byte-swapped on Little Endian
 * machines. When computing the checksum for an IP header, the checksum
 * field is zeroed first and the checksum is then computed. Once computed,
 * the checksum value is stored in the IP header. If the checksum of the
 * IP header is then computed after storing the checksum, the resulting
 * checksum should be 0 (this is verification that the checksum is correct).
 */

unsigned short ip_checksum(struct ip *ip, int length)
{
	unsigned char *data;
	long sum = 0;

	data = (unsigned char *) ip;

	while(length > 1) {
		sum += * (unsigned short *) data;
		data += 2;
		length -= 2;
	}

	if(length)
		sum += * (unsigned char *) data;

	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return(~sum);
}

void zero_mutable_fields (struct ip *ip_hdr)
{
    unsigned short len;
    unsigned char  *opt;
    unsigned short opt_len;

    // set the mutable fields to zero: TOS, Flags, Fragment Offset, TTL and Header Cheksum
		
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 0;
    ip_hdr->ip_sum = 0;

    // zero any mutable ipv4 options
		
    len     = (ip_hdr->ip_hl - 5) << 2;
    opt     = (unsigned char *) ip_hdr + 20;

    while (len > 0) {
        if ((opt[0] == 0) || (opt[0] == 1)) {
            opt_len = 1;
        } else {
            opt_len = opt[1];
        }

        if (is_ip_option_mutable (opt[0])) {
            // zero this option
            memset (opt, 0, opt_len);
        }

        opt += opt_len;
        len -= opt_len;
    }
}

int is_ip_option_mutable (unsigned char opt)
{
	/* RFC2402 defines which options are mutable or immutable */

	switch(opt)
	{
		case 3:		/* Loose source route */
		case 4:		/* Time stamp */
		case 7:		/* Record route */
		case 9:		/* Strict route */
		case 18:	/* Traceroute */
		{
			return(1);
		}

		default:
		{
			return(0);
		}
	}
}

void restore_mutable_fields (struct ip *old_hdr, struct ip *new_hdr)
{
    // TOS, Flags, Fragment Offset. Don't copy the old checksum, it will be re-calculated later
		
    new_hdr->ip_tos = old_hdr->ip_tos;
    new_hdr->ip_off = old_hdr->ip_off;
    new_hdr->ip_ttl = old_hdr->ip_ttl;

    // restore any ipv4 options zeroed previously
		
    if (old_hdr->ip_hl > 5) {
      memcpy ((char *) new_hdr + 20, (char *) old_hdr + 20, (old_hdr->ip_hl - 5) << 2);
    }
}

/*
 * HMAC MD5 routine for IPSEC AH
 *
 * assume digest points to a buffer of at lease 16 bytes. It's caller's responsibility to allocate the buffer
 */
 
void hmac_md5 (const unsigned char *text, int text_len, const unsigned char *key, int key_len, unsigned char *digest)
{
    md5_state_t state;
    unsigned char k_ipad[65];
    unsigned char k_opad[65];
    unsigned char tk[16];
    int i;

    /* if key is longer than 64 bytes reset it to key=MD5(key) */
		
    if (key_len > 64) {
        md5_state_t key_state;

        md5_init (&key_state);
        md5_append (&key_state, (const md5_byte_t *) key, key_len);
        md5_finish (&key_state, tk);

        key     = tk;
        key_len = 16;
    }

    /*
       the HMAC-MD5 transform looks like:
       MD5(K XOR opad ++ MD5(K XOR ipad ++ text))
       
       where ++ means concatenate,
       K is an n byte key,
       ipad is the byte 0x36 repeated 64 times (block size of MD5)
       opad is the byte 0x5c repeated 64 times.
       and text is the data being protected 
       */
			 
    bzero (k_ipad, sizeof (k_ipad));
    bzero (k_opad, sizeof (k_opad));
    bcopy (key, k_ipad, key_len);
    bcopy (key, k_opad, key_len);

    /* XOR key with k_ipad and k_opad */
		
    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /* inner MD5: MD5(K XOR ipad ++ text) */
		
    md5_init (&state);
    md5_append (&state, k_ipad, 64);
    md5_append (&state, text, text_len);
    md5_finish (&state, digest);

    /* outer MD5 */
		
    md5_init (&state);
    md5_append (&state, k_opad, 64);
    md5_append (&state, digest, 16);
    md5_finish (&state, digest);
}

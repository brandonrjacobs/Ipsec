
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ifaddrs.h>
#include <signal.h>
#include <md5.h>

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


#define	DIVERT_PORT_IN		2000
#define DIVERT_PORT_OUT		2001
#define BUFFER_SIZE		65535


static unsigned char ipPacket[BUFFER_SIZE];	/* network packet buffer, from recvfrom(2) */

static struct sockaddr_in *hostIP[8];		/* maximum 8 network interfaces - arbitrary */

static int hostIPCount = 0;

static int divertFd = -1;

static char progName[32];			/* argv[0] */

static int progMode = 0;			/* 0=inbound mode, 1=outbound mode */

static int verbose = 0;				/* Verbose mode - informational messages (-v option) */

static int debug = 0;				/* Debug mode - packet dump for debugging (-d option) */

/*
 * Program implements packet integrity protection via the IPSEC AH (authentication header) packet
 * which includes a hashed message authentication code. HMAC-MD5 is used with a pre-defined key
 * to generate the ICV. Use of a pre-defined key allows the program to run on different hosts to
 * verify the integrity of IP packets between them without having to implement dynamic key exchange
 * protocols. The SPI and Key are arguments to the program and the same SPI/Key combination are
 * used by all programs that wish to send/receive IP packets with IPSEC AH for integrity verification.
 *
 * inboundPacket()  - checks for AH header and if present, validates integrity checksum value
 * outboundPacket() - wraps the outbound packet payload with AH header and adjusts IP header fields
 */


/* Routines used */

void signalHandler     (int sig);
void getHostAddresses  ();
int  createDivertSocket(uint16_t port);
void processPackets    (int fd, u_int32_t spi, unsigned char *key);
void MD5Print          (unsigned char digest[16]);
void packetDump        (unsigned char *packet, int ip_length, int ah_length, int payload_len);
void protoID		   (unsigned char *payload, int protocol);

/* Dynamic pointer to the inbound or outbound packet handling routine */

int (*packetHandler)(struct ip *ipHeader, int protocol, u_int32_t spi, unsigned char *key, int *recvLen);

/* AH policy handling routines */

int  inboundPacket (struct ip *ipHeader, int protocol, u_int32_t spi, unsigned char *key, int *recvLen);
int  outboundPacket(struct ip *ipHeader, int protocol, u_int32_t spi, unsigned char *key, int *recvLen);
void reinjectPacket(int fd, int recvLen, struct sockaddr *saddr, socklen_t saddrLen);

/* Class provided ip_checksum routine modified to retun checksum and not place in IP header */

unsigned short ip_checksum (struct ip *ip, int length);

/* Class provided HMAC MD5 routine */

void hmac_md5 (const unsigned char *text, int text_len, const unsigned char *key, int key_len, unsigned char *digest);

/* Class routines for IP header mutable field handling */

void zero_mutable_fields (struct ip *ip_hdr);
void restore_mutable_fields (struct ip *old_hdr, struct ip *new_hdr);


/*
 *
 * Source file: ipsec_ah.c
 *
 *	Compile the above source file creating ipsec_ah executable
 *	Create  inbound-IPSecAH with "ln -s ipsec_ah  inbound-IPSecAH" command
 *	Create outbound-IPSecAH with "ln -s ipsec_ah outbound-IPSecAH" command
 *
 * inbound-IPSecAH  - verify IPSEC AH values for incoming packets
 * outbound-IPSecAH - wrap outbound packets with AH header containing HMAC-MD5 ICV for packet
 *
 * Arguments: -s SPI (pre-defined security parameter index)
 *	      -k key (pre-defined shared key for use with HMAC-MD5)
 *	      -v (verbose mode, recommended)
 *            -p port  (specifies the divert port, default is 2000 inbound, 2001 outbound)
 *	      -d (packet dump mode for debugging)
 *
 * Note: divert port must match the port specified in the ipfw rule
 *
 * Samples: inbound-IPSecAH -s 100 -k EncryptionKey -p 2000 [-v -d]
 *         outbound-IPSecAH -s 100 -k EncryptionKey -p 2001 [-v -d]
 *
 * Program depends on ipfw configuration - the following rules should be created for
 * ipfw and they should preceed any rules that would otherwise accept or reject ip
 * packets before they are diverted by the kernel to the inbound and outbound packet
 * programs.
 *
 *	ipfw add 100 divert 2000 ip from any to any in
 *	ipfw add 101 divert 2001 ip from any to any out
 *
 */

int main(int argc, char **argv)
{
	struct sigaction sigact;
	u_int32_t securityParameterIndex;
	uint16_t divertPort;
	unsigned char *hmacKey;
	char hostName[256];
	int opt;

	/* Set the program name for verbose mode and to determine inbound/outbound mode */

	strcpy(progName, argv[0]);

	/* Determine if the program is processing inbound or outbound packets */

	if(strstr(progName, "inbound"))
		progMode = 0;			/* inbound */
	else
		progMode = 1;			/* outbound */

	/* Assign packet handler and also default divert socket in case one is not specified */

	if(progMode)
	{
		packetHandler = &outboundPacket;
		divertPort = DIVERT_PORT_OUT;
	}
	else
	{
		packetHandler = &inboundPacket;
		divertPort = DIVERT_PORT_IN;
	}

	/* Obtain the name of the host */

	if(gethostname(hostName, sizeof(hostName) - 1))
	{
		fprintf(stderr, "%s: failed to obtain hostname - %d\n", progName, errno);
		exit(1);
	}

	if(verbose)
		printf("%s: host name is %s\n", progName, hostName);

	/* Process command line options */

	while((opt = getopt(argc, argv, "s:k:vdp:")) != -1)
	{
		switch (opt)
		{
			case 's':
				securityParameterIndex = atoi(optarg);
				break;

			case 'k':
				hmacKey = malloc(strlen(optarg) + 1);
				strcpy((char *) hmacKey, optarg);
				break;

			case 'v':
				verbose = 1;
				break;

			case 'd':
				debug = 1;
				break;

			/* Note: specified port must match the ipfw firewall divert rule port */

			case 'p':
				divertPort = atoi(optarg);
				break;

			case '?':
			default:
				printf("usage: inbound-IPSecAH/outbound-IPSecAH -s SPI -k <key string> [-v] [-p port]\n");
				exit(1);
		}
	}

	/* Output program arguments in verbose mode */

	if(verbose)
		printf("%s: Mode (%s), SPI (%d), Key (%s), Divert port (%d)\n",
			progName, progMode ? "outbound" : "inbound", 
			securityParameterIndex, hmacKey, divertPort);

	/* Signal handler for graceful exit/cleanup */

	sigact.sa_handler = signalHandler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGINT, &sigact, (struct sigaction *) NULL);

	/* Build the host IP address list for use in packet filtering */

	(void) getHostAddresses();

	/* Create and bind the divert socket */

	divertFd = createDivertSocket(divertPort);

	if(verbose)
		printf("%s: divert socket successfully bound, preparing to process packets\n", progName);

	/* Process network packets delivered to the divert socket */

	(void) processPackets(divertFd, securityParameterIndex, hmacKey);

	exit(0);
}


/*
 * signalHandler - graceful handling for program termination.
 */

void signalHandler(int sig)
{
	/* Close the divert socket */

	if(divertFd)
		close(divertFd);

	if(verbose)
		printf("%s: exiting\n", progName);

	exit(0);
}

/*
 * getHostAddresses - obtain the IP address(es) for the host to use later in packet filtering.
 *
 * returns: builds a global structure of AF_INET network address structure pointers
 */

void getHostAddresses()
{
	struct ifaddrs *ifaddrs;

	/* Get the host network interface structures to obtain host IP addresses */

	if(getifaddrs(&ifaddrs) == -1)		/* do not free structures; these are used later */
	{
		fprintf(stderr, "%s: failed to retrieve host network interface structures - %d\n",
			progName, errno);
		exit(1);
	}

	/*
	 * Store the host network interface IP addresses for use later. Ignore the localhost
	 * IP address since it is not used for network packets between this host and others
	 * on the network. Note that the host may have more than network interface and hence
	 * more than one IP address that needs to be factored into packet analysis for any
	 * diverted packets based on the security policy being implemented.
	 */

	while(ifaddrs != (struct ifaddrs *) 0)
	{
		struct sockaddr_in *saddr_in;
		char ifAddress[INET_ADDRSTRLEN];

		/*
		 * Ignore any interfaces that are not up (IFF_UP) or loopback interfaces (IFF_LOOPBACK) 
		 * as well as any interfaces not in the AF_INET family. Could easily be extended to
		 * support IPV6 networks.
		 */

		if(((ifaddrs->ifa_flags & IFF_UP) == 0) || (ifaddrs->ifa_flags & IFF_LOOPBACK) ||
		    (ifaddrs->ifa_addr->sa_family != AF_INET))
		{
			/* Bump to the next interface structure */

			ifaddrs = ifaddrs->ifa_next;
			continue;
		}

		/* Interface is up, is not a loopback interface, and is in the AF_INET family */

		if(verbose)
			printf("%s: interface %s, length %d, family %d\n", progName,
				ifaddrs->ifa_name, ifaddrs->ifa_addr->sa_len, ifaddrs->ifa_addr->sa_family);

		/* ifa_addr points to a sockaddr_in structure for AF_INET */

		saddr_in = (struct sockaddr_in *) ifaddrs->ifa_addr;

		inet_ntop(AF_INET, (void *) &saddr_in->sin_addr, ifAddress, INET_ADDRSTRLEN);

		if(verbose)
			printf("%s: interface/address: %s/%s\n", progName, ifaddrs->ifa_name, ifAddress);

		/* Store a pointer to the interface structure */

		hostIP[++hostIPCount] = (struct sockaddr_in *) ifaddrs->ifa_addr;

		/* Move to the next interface structure in the list */

		ifaddrs = ifaddrs->ifa_next;
	}
}


/*
 * createDivertSocket - create the divert socket and bind it on the specified port.
 *
 * argument: port on which to bind the divert socket
 * returns:  file descriptor for the divert socket
 */

int createDivertSocket (uint16_t port)
{
	int fd, sockOpt, sockOptLen;
	struct sockaddr_in divertSocket;

	if(verbose)
		printf("%s: using %d for divert port\n", progName, port);

	/* Create a divert socket */

	fd = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);

	if(fd == -1)
	{
		fprintf(stderr, "%s: failed to create divert socket - %d\n", progName, errno);
		exit(1);
	}

	/* Set socket option to allow broadcast packets on the divert socket (for reinjection) */

	sockOpt = 1;
	sockOptLen = sizeof(sockOpt);

	if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &sockOpt, sockOptLen) == -1)
		fprintf(stderr, "%s: failed to set SO_BROADCAST on divert socket - %d\n", progName, errno);

	/*
	 * It is possible due to TIME_WAIT and other network conditions that the port used by
	 * this program for packet diversion may remain bound even though the process that did
	 * the bind(2) has terminated. This will result in the bind(2) below failing even though
	 * our program is no longer able to receive diverted packets. Use the reuseport socket
	 * option to allow the program to successfully bind to the same port.
	 *
	 * Note: option may not be supported on all versions of FreeBSD
	 */

	if(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &sockOpt, sockOptLen) == -1)
		fprintf(stderr, "%s: failed to set SO_REUSEPORT on divert socket - %d\n", progName, errno);

	/* Bind the divert socket to the divert port - address for bind is not used */

	memset(&divertSocket, 0, sizeof(divertSocket));

	divertSocket.sin_family = AF_INET;
	divertSocket.sin_port = htons(port);
	divertSocket.sin_addr.s_addr = 0;

	if(bind(fd, (struct sockaddr *) &divertSocket, sizeof(struct sockaddr_in)))
	{
		fprintf(stderr, "%s: failed to bind the divert socket - %d\n", progName, errno);
		exit(1);
	}

	return(fd);
}


/*
 * processPackets - reads the divert socket and filters the packets received. All ICMP traffic is
 * rejected/discarded while all other packets associated with any protocol other than ICMP are
 * passed on by reinjecting into the divert socket to return to the kernel.
 */

void processPackets(int fd, u_int32_t spi, unsigned char *key)
{
	struct sockaddr saddr;
	socklen_t saddrLen;
	int packetCount;

	/* Read packets from the divert socket continuously */

	packetCount = 1;

	while(1)
	{
		struct ip *ipHeader;
		struct in_addr *srcAddr, *dstAddr;
		struct sockaddr_in *sockAddr;
		int recvLen, protocol;
		char ipSource[INET_ADDRSTRLEN], ipDestination[INET_ADDRSTRLEN];

		/* Prepare for the recvfrom() call to the divert socket */

		saddrLen = sizeof(struct sockaddr);

		/* Read the next packet from the network */

		recvLen = recvfrom(fd, ipPacket, BUFFER_SIZE, 0, &saddr, &saddrLen);

		if(verbose)
		{
			printf("%s: ********** Processing packet #%d **********\n", progName, packetCount++);
			printf("%s: network packet received from kernel, length %d\n", progName, recvLen);
		}

		if(recvLen == 1)
			continue;

		/* Determine the ipfw rule # that caused diversion of the packet */

		sockAddr = (struct sockaddr_in *) &saddr;

		if(verbose)
		{
			printf("%s: packet diverted by ipfw rule - %d\n", progName, sockAddr->sin_port);
			
			if(sockAddr->sin_addr.s_addr == INADDR_ANY)
				printf("%s: packet destination is INADDR_ANY\n",
					progName);
			else
				printf("%s: packet destination is %s\n",
					progName, sockAddr->sin_zero);
		}

		/*
	 	 * Extract the protocol ID from the IP header. This is the protocol of the portion
		 * of the packet that immediately follows the IP header. In the case of an inbound
		 * packet, this should be 51 (IPSEC AH). In the case of an outbound packet, it can
		 * be any legitimate protocol identifier (TCP, ICMP, UDP, ...).
		 */

		ipHeader = (struct ip *) ipPacket;

		protocol = ipHeader->ip_p;

		/* Source and destination addresses for the packet */

		srcAddr = &ipHeader->ip_src;
		dstAddr = &ipHeader->ip_dst;

		if(verbose)
		{
			/* Convert the source and destination IP addresses to strings */

			strcpy(ipSource,     inet_ntoa(ipHeader->ip_src));
			strcpy(ipDestination,inet_ntoa(ipHeader->ip_dst));

			printf("%s: protocol %d, src %s, dst %s\n",
				progName, protocol, ipSource, ipDestination);
		}

		/*
		 * The packet handler routine installed based on program invocation will
		 * process the inbound or outbound packet and perform functions that are
		 * specifically for the packet type. The packet processing routine will
		 * return a 1 if the packet is to be reinjected into the network stack.
		 * A return value of 0 indicates the packet is to be dropped.
		 */

		if(packetHandler(ipHeader, protocol, spi, key, &recvLen))
			reinjectPacket(fd, recvLen, &saddr, saddrLen);
	}
}


/*
 * inboundPacket
 *
 * This routine is called to process all diverted inbound packets. Packets are reinjected
 * in the protocol stack only if the following conditions are met:
 *
 * 1. Packet must have an IPSEC AH authentication header
 * 2. The AH header must have an SPI that matches the SPI configured for this program
 * 3. The ICV value in the AH header must match that computed by this program using HMAC-MD5 with
 *	the key value configured for this program
 * 4. AH header is stripped after verification and IP header length is adjusted accordingly
 *
 * Note: SPI and KEY are pre-defined values and passed to the program on the command line. This
 * avoids the complexity of implementing IPSEC protocols for key exchange and SA establishment.
 *
 */

int inboundPacket (struct ip *ipHeader, int protocol, u_int32_t spi, unsigned char *key, int *recvLen)
{
	struct ip ipHeaderCopy;
	struct newah *ah;
	unsigned char computedDigest[16], packetDigest[16], *icv;
	unsigned char *payload, *payloadMoved;
	int iphdr_len, ah_len, payload_len, packet_len;

	/* Packet length includes IP and AH headers along with payload */

	packet_len = ntohs(ipHeader->ip_len);

	if(verbose)
		printf("%s: inboundPacket IP hdr len (%d), packet len (%d), protocol (%d), checksum (%d)\n",
			progName, ipHeader->ip_hl * 4, packet_len,
			ipHeader->ip_p, ipHeader->ip_sum);

	/* Verify that the packet includes AH */

	if(ipHeader->ip_p != IPPROTO_AH)
	{
		printf("%s: inbound packet does not include AH (%d)\n", progName, ipHeader->ip_p);
		return(0);
	}

	/* Set the pointer to the AH in the packet, follows the IP header */

	iphdr_len = ipHeader->ip_hl * sizeof(u_int32_t);

	ah     = (struct newah *) ((char *) ipHeader + iphdr_len);
	ah_len = (ah->ah_len + 2) * sizeof(u_int32_t);

	if(verbose)
		printf("%s: *** IPSec AH Packet received ***, len (%d), spi (%d), proto (%d)\n",
			progName, ah_len, ntohl(ah->ah_spi), ah->ah_nxt);

	/* Verify that the AH security parameter index (SPI) matches */

	if(ntohl(ah->ah_spi) != spi)
	{
		printf("%s: inbound packet SPI does not match (%d - %d)\n", progName, ntohl(ah->ah_spi), spi);
		return(0);
	}

	/* Save protocol from the AH header - it needs to be restored to the IP header */

	protocol = ah->ah_nxt;

	/* Payload length includes everything in the packet but the IP header length */

	payload     = (unsigned char *) ipHeader + iphdr_len + ah_len;
	payload_len = ntohs(ipHeader->ip_len) - iphdr_len - ah_len;

	if(verbose)
	{
		protoID(payload, protocol);
		printf("%s: [AH] IP hdr len (%d), AH hdr len (%d), payload len (%d) read len (%d)\n",
			progName, iphdr_len, ah_len, payload_len, *recvLen);
	}

	if(debug)
		packetDump((unsigned char *) ipHeader, iphdr_len, ah_len, payload_len);
		
	/* Copy the IP header so it can be restored following ICV calculation */

	memcpy((char *) &ipHeaderCopy, (char *) ipHeader, iphdr_len);

	/* Zero out the mutable fields in the IP header so they do not factor into ICV */

	zero_mutable_fields(ipHeader);

	/* Message digest (ICV) follows the AH header */

	icv = (unsigned char *) ah + sizeof(struct newah);

	/* Copy the ICV from the packet and then zero the ICV field for new calculation */

	bcopy((char *) icv, (char *) packetDigest, sizeof(packetDigest));

	bzero((char *) icv, sizeof(packetDigest));

	/*
 	 * Compute the ICV for the inbound packet using HMAC-MD5
	 *
	 * IETF RFC2402 - Authentication Header ICV, Section 3.3
	 *
	 * RFC2402 dictates how the ICV in the AH header is to be calculated. The calculation
	 * should include all immutable fields of the IP header, AH header, and the IP datagram.
	 * Specifically excluded from the ICV calculation are the the following mutable fields
	 * from the IP header:
	 *
	 *	Service type, Fragment offset (and flags), TTL, Checksum
	 *
	 * The calculation also excludes the ICV itself. When calculating the ICV, mutable fields
	 * and the ICV are zeroed prior to the calculation. Following the calculation, all mutable
	 * fields can be restored to the IP header.
	 *
	 * For inbound processing, the ICV must first be saved and then the ICV portion of the
	 * packet must be zeroed. The mutable fields from the IP header must be saved and then
	 * zeroed at which point the ICV can be calculated and compared to the saved ICV from the AH
	 * header. If the ICV values match, the packet is reinjected. If the ICV values do not
	 * match, the packet has been modified in transit and is rejected.
	 */

	hmac_md5((unsigned char *) ipHeader, packet_len, key, strlen((char *) key), computedDigest);

	/* Compare the computed digest to the digest contained in the packet */

	if(memcmp((char *) packetDigest, (char *) computedDigest, sizeof(packetDigest)))
	{
		printf("%s: ICV mismatch for inbound packet: ", progName);
		MD5Print(packetDigest);
		printf(", packet rejected\n");

		return(0);
	}

	/* Restore the IP header to the values prior to ICV calculation */

	restore_mutable_fields(&ipHeaderCopy, ipHeader);

	/* Replace IPPROTO_AH with the protocol of the IP datagram (that followed AH header) */

	ipHeader->ip_p = protocol;

	/* Adjust the size field in the IP header to reflect removal of AH & digest */

	ipHeader->ip_len = htons(packet_len - ah_len);

	/* Recompute the IP checksum since packet length and protocol have been changed */

	ipHeader->ip_sum = 0;	/* zero checksum field in header */

	ipHeader->ip_sum = ip_checksum(ipHeader, iphdr_len);

	if(verbose)
		printf("%s: packet checksum (0x%04x), verified checksum (0x%04x)\n",
			progName, ipHeader->ip_sum, ip_checksum(ipHeader, iphdr_len));

	/* Compress the packet in the buffer to remove the AH header and digest */

	payloadMoved = (unsigned char *) ipHeader + iphdr_len;

	memmove(payloadMoved, payload, payload_len);

	if(debug)
		packetDump((unsigned char *) ipHeader, iphdr_len, 0, payload_len);
		
	/* Adjust byte count that controls amount of data reinjected into the network */

	*recvLen = packet_len - ah_len;

	/* Packet is OK - reinject into network for delivery as intended */

	if(verbose)
	{
		printf("%s: [Post-AH] IP hdr len (%d), AH hdr len (%d), payload len (%d) read len (%d)\n",
			progName, iphdr_len, ah_len, payload_len, *recvLen);
		printf("%s: inbound packet ICV matches, reinject into network with size (%d)\n",
			progName, *recvLen);
	}

	return(1);
}


/*
 * outboundPacket
 *
 * This routine is called to process all diverted outbound packets. Packets are reinjected
 * in the protocol stack after the following actions have been performed:
 *
 * 1. An IPSEC AH authentication header id created for the outbound packet
 * 2. The SPI configured for this program is stored in the AH header
 * 3. AH Header fields for next protocol, length, reserved, and sequence are filled in
 * 4. An integrity checksum value is computed via MD5 and encrypted using HMAC-MD5 and the
 *	Key argument to this program
 * 5. The ICV from step 4 is stored in the AH header along with any necessary padding
 * 6. The IPSEC AH header is inserted between the IP header and the protocol header that
 *	followed it in the unmodified packet as read from the divert socket
 * 7. IP header length field is updated to reflect the addition of the AH header
 *
 * Note: SPI and KEY are pre-defined values and passed to the program on the command line. This
 * avoids the complexity of implementing IPSEC protocols for key exchange and SA establishment.
 *
 */

int outboundPacket(struct ip *ipHeader, int protocol, u_int32_t spi, unsigned char *key, int *recvLen)
{
	struct ip ipHeaderCopy;
	struct newah ah, *ahHeader;
	unsigned char digest[16];
	unsigned char *payload, *payloadMoved;
	int iphdr_len, ah_len, payload_len;

	if(verbose)
		printf("%s: outboundPacket IP hdr len (%d), packet len (%d), protocol (%d), checksum (0x%x)\n",
			progName, ipHeader->ip_hl * 4, ntohs(ipHeader->ip_len),
			ipHeader->ip_p, ntohs(ipHeader->ip_sum));

	/* AH next protocol/packet field is set to protocol field from IP header */

	ah.ah_nxt = protocol;		/* protocol field from the IP header */
	ah.ah_reserve = htons(0);	/* reserved field */
	ah.ah_spi = htonl(spi);		/* security parameter index */
	ah.ah_seq = htonl(0);		/* unused for our purposes - SA datagram sequence # */

	/* Length field is count of 32-bit chunks in header ignoring first 64-bits */

	ah.ah_len = (sizeof(struct newah) / sizeof(u_int32_t)) - 2;

	/* HMAC-MD5 will generate a 16-byte encrypted digest, 4 32-bit chunks - padding not needed */

	ah.ah_len += (sizeof(digest) / sizeof(u_int32_t));

	/*
	 * Payload following IP header will be used in ICV generation. The size of the IP
	 * header may be 20 or 24 bytes depending on whether options are present. The IP
	 * header contains two length fields - one a 4-bit field that defines the size of
	 * the header itself and the second a 2-byte field that defines the size of the
	 * IP packet including the size of the Ip header. The field that defines the size
	 * IP header is in 32-bit chunks (not bytes).
	 *
	 * Note: IP and AH header lengths in packet are measured in 32-bit chunks (not in bytes)
	 */

	iphdr_len = ipHeader->ip_hl * sizeof(u_int32_t);
	ah_len = (ah.ah_len + 2) * sizeof(u_int32_t);

	/* Payload length includes everything in the packet but the IP header length */

	payload     = (unsigned char *) ipHeader + iphdr_len;
	payload_len = ntohs(ipHeader->ip_len) - iphdr_len;

	if(verbose)
	{
		protoID(payload, protocol);
		printf("%s: [Pre-AH] IP hdr len (%d), AH hdr len (%d), payload len (%d) read len (%d)\n",
			progName, iphdr_len, ah_len, payload_len, *recvLen);
	}

	if(debug)
		packetDump((unsigned char *) ipHeader, iphdr_len, 0, payload_len);
		
	/*
	 * The data buffer read from the network stack needs to be manipulated prior to
	 * reinjecting the packet into the network. The payload that follows the IP header
	 * needs to be moved so the AH header can be inserted. The length field in the AH
	 * header does not truly reflect the amount of data that actually exists in the
	 * header so calculate that value here. The true size of the AH header is needed
	 * for data copy operations and also for the sendTo() to reinject the packet. The
	 * memmove(3) function is used below since it is non-destructive. Moving the payload
	 * down in the packet would overlap with the existing payload so care must be taken
	 * on the move. Since the ICV has not yet been calculated, the ICV is zeroed and
	 * then the ICV is copied into the packet below just prior to being reinjected into
	 * the network stack.
	 */

	payloadMoved = (unsigned char *) ipHeader + iphdr_len + ah_len;

	memmove(payloadMoved, payload, payload_len);

	/*
	 * Copy the AH header into the packet buffer between the IP header and the payload. The
	 * data structure representing AH does not include the message digest since the length
	 * and format of the digest depends upon the algorithm used. Therefore, the fixed portion
	 * of the AH header is copied first and then the message digest is appended to the AH
	 * header in the packet buffer.
	 */

	ahHeader = (struct newah *) ((unsigned char *) ipHeader + iphdr_len);

	memcpy(ahHeader, (char *) &ah, sizeof(struct newah));		/* fixed portion of the AH */

	/* Zero the 16-byte ICV portion of the AH header */

	bzero((char *) ahHeader + sizeof(struct newah), sizeof(digest));

	/* Update the IP packet length in the IP header to reflect addition of AH header */

	*recvLen = ntohs(ipHeader->ip_len) + ah_len;

	if(verbose)
		printf("%s: [Post-AH] IP hdr len (%d), AH hdr len (%d), payload len (%d) read len (%d)\n",
			progName, ipHeader->ip_hl * 4, ah_len, payload_len, *recvLen);

	/*
 	 * Create the ICV for the packet using HMAC-MD5
	 *
	 * IETF RFC2402 - Authentication Header ICV, Section 3.3
	 *
	 * RFC2402 dictates how the ICV in the AH header is to be calculated. The calculation
	 * should include all immutable fields of the IP header, AH header, and the IP datagram.
	 * Specifically excluded from the ICV calculation are mutable fields of the IP header
	 * as these values can legitimately be modified during the transit of the packet. The
	 * calculation also excludes the ICV itself. When calculating the ICV, mutable fields
	 * and the ICV are zeroed prior to the calculation. Following the calculation, mutable
	 * fields can be restored and the ICV is copied into the packet before reinjection.
	 *
	 * Mutable fields in IP header: Service type, Flags, Fragment offset, TTL, Checksum
	 */

	ipHeader->ip_len = htons(*recvLen);	/* Update IP packet length to include AH */
	ipHeader->ip_p = IPPROTO_AH;		/* IP header protocol is now IPSec AH */

	/* Copy the IP header so it can be restored following ICV calculation */

	memcpy((char *) &ipHeaderCopy, (char *) ipHeader, iphdr_len);

	/* Zero out the mutable fields in the IP header so they do not factor into ICV */

	zero_mutable_fields(ipHeader);

	hmac_md5((unsigned char *) ipHeader, *recvLen, key, strlen((char *) key), digest);

	/* Restore the IP header mutable fields now that ICV has been calculated */

	restore_mutable_fields(&ipHeaderCopy, ipHeader);

	/* Recompute the IP checksum */

	ipHeader->ip_sum = htons(ip_checksum(ipHeader, iphdr_len));

	/* Copy the calculated message digest into the AH header - overwrites the zeroed ICV */

	memcpy((char *) ahHeader + sizeof(struct newah), (char *) digest, sizeof(digest));

	if(debug)
		packetDump((unsigned char *) ipHeader, iphdr_len, ah_len, payload_len);
		
	/* Packet has been modified to add an IPSEC AH header following IP header */

	if(verbose)
		printf("%s: AH header added to outbound packet, reinject into network with length (%d)\n",
			progName, *recvLen);

	return(1);
}


/*
 * reinjectPacket - send the packet back to the kernel stack to be forwarded to original destination.
 */

void reinjectPacket(int fd, int packetLen, struct sockaddr *saddr, socklen_t saddrLen)
{
	int sendLen;

	/* Reinject packet into the network stack */

	if(verbose)
		printf("%s: reinjecting packet with length %d\n", progName, packetLen);

	sendLen = sendto(fd, ipPacket, packetLen, 0, saddr, saddrLen);

	if(sendLen == -1)
		fprintf(stderr, "%s: error on packet reinject sendto() - %d\n", progName, errno);
}

/*
 * MD5Print - prints a 16-byte HMAC-MD5 digest as a 32-character hexadecimal string
 */

void
MD5Print(unsigned char digest[16])
{
	int n;

	for(n=0; n<16; n++)
		printf("%02x", digest[n]);
}

/*
 * MD5Print - prints a 16-byte HMAC-MD5 digest as a 32-character hexadecimal string
 */

#define PACKET_DUMP_COUNT	32

void
packetDump(unsigned char *packet, int ip_length, int ah_length, int payload_len)
{
	int packet_length, n;

	packet_length = ip_length + ah_length + payload_len;

	printf("%s: packet [001-%03d]: ", progName, PACKET_DUMP_COUNT);

	for(n=0; n < packet_length; n++)
	{
		int end;

		if((packet_length - n) < PACKET_DUMP_COUNT)
			end = n + (packet_length - n);
		else
			end = n + PACKET_DUMP_COUNT;

		if(n && ((n % PACKET_DUMP_COUNT) == 0))
			printf("\n%s: packet [%03d-%03d]: ", progName, n+1, end);

		printf("%02x", packet[n]);
	}

	printf("\n");
}

/*
 * protoID
 *
 * Identify the protocol in the IP datagram - the portion being encapsulated in the
 * AH header.
 */

void
protoID(unsigned char *packet, int protocol)
{
	/* Determine if the protocol is ICMP */

	switch(protocol)
	{
		case IPPROTO_ICMP:
		{
			struct icmp *icmp;
	
			/* Set pointer to ICMP payload in the IP packet - follows the IP header */

			icmp = (struct icmp *) packet;

			if(icmp->icmp_type == ICMP_ECHO)
				printf("%s: ICMP protocol, packet type - ICMP_ECHO\n",progName);
			else if(icmp->icmp_type == ICMP_ECHOREPLY)
				printf("%s: ICMP protocol, packet type - ICMP_ECHOREPLY\n", progName);
			else
				printf("%s: ICMP protocol, packet type - %d\n", progName, icmp->icmp_type);

			break;
		}

		case IPPROTO_ESP:
		{
			printf("%s: ESP encapsulation security protocol\n",progName);
			break;
		}

		case IPPROTO_AH:
		{
			printf("%s: AH authentication header protocol\n",progName);
			break;
		}

		case IPPROTO_TCP:
		{
			printf("%s: TCP protocol\n",progName);
			break;
		}

		case IPPROTO_UDP:
		{
			printf("%s: UDP protocol\n",progName);
			break;
		}
	}
}


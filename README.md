# Ipsec

# Main File is ipsec_ah.c
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

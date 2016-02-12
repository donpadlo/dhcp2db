/*
 * net.h
 *
 *  Created at: 03.09.2009
 *      Author: Chebotarev Roman
 */

#ifndef NET_H_
#define NET_H_

#pragma pack(1)

#define ETHER_HW_TYPE	1
#define IP4_MAXSTR_ALEN	(3 * 4 + 3)
#define	ETHER_ALEN		6

#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */

#define IP_HDR_LEN          5       /* IP header len in 32-bit words */
#define B_IP_HDR_LEN        5 * 4   /* IP header len in bytes */

#define MIN_TCP_PORT			1
#define	MAX_TCP_PORT			65535
#define MIN_UDP_PORT			MIN_TCP_PORT
#define	MAX_UDP_PORT			MAX_TCP_PORT

/* 10Mb/s ethernet header */
typedef struct eth_header
{
  u_int8_t  ether_dhost[ETHER_ALEN];	/* destination eth addr	*/
  u_int8_t  ether_shost[ETHER_ALEN];	/* source ether addr	*/
  u_int16_t ether_type;		        /* packet type ID field	*/
} __attribute__ ((__packed__)) ether_header_t;

/*
 * Structure of an internet header, naked of options.
 */
typedef struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t src_addr;
    uint32_t dst_addr;
    /*The options start here. */
} ip_header_t;

/* UDP header as specified by RFC 768, August 1980. */

typedef struct pseudo_hdr
{
	union
	{
		uint32_t	addr;
		struct	
		{
			uint16_t	b01;
			uint16_t	b23;
		} bytes;
	} src;

	union
	{
		uint32_t	addr;
		struct	
		{
			uint16_t	b01;
			uint16_t	b23;
		} bytes;
	} dst;
    unsigned char zero ;
    unsigned char proto;
    unsigned short length;
} __attribute__ ((__packed__)) pseudo_header_t;

typedef struct udphdr
{
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
} udp_header_t;

#define ETH_HEADER_LEN		sizeof(ether_header_t)
#define IP_HEADER_LEN		sizeof(ip_header_t)
#define	UDP_HEADER_LEN		sizeof(udp_header_t)

#define ARP_OP_REQ			htons(1)
#define	ARP_OP_RESP			htons(2)

/* ARP header */
typedef struct arp_header
{
    uint16_t	arp_hwtype;   /* Format of hardware address */
    uint16_t	arp_proto;   /* Format of protocol address */
    uint8_t		arp_hwlen;     /* Length of hardware address */
    uint8_t 	arp_palen;     /* Length of protocol address */
    uint16_t	arp_oper;      /* ARP opcode (command) */
} arp_header_t;

typedef struct arp_packet_net_header
{
	struct eth_header eth_head;
	struct arp_header arp_head;
} arp_neth_t;

typedef struct arp_data
{
	uint8_t		from_ether[ETHER_ALEN];
	uint32_t 	from_ip;
	uint8_t		to_ether[ETHER_ALEN];
	uint32_t	to_ip;
} arp_data_t;

typedef struct arp_packet
{
	arp_neth_t	header;
	arp_data_t	data;
} arp_packet_t;

typedef enum ethernet_protocols
{
	ETHER_ARP_T	=	0x0806,
	ETHER_IP4_T	=	0x0800,
	ETHER_IP6_T	=	0x86DD
} ether_proto_t;

#pragma pack(0)

#define DHCP_DATA_FROM_FULL_PACKET(d) \
	((dhcp_message_t*)(&((dhcp_full_packet_t*)(d))->dhcp_data))

#endif /* NET_H_ */

/*
 * net_dhcp.h
 *
 *  Created at: 04.09.2009
 *      Author: Chebotarev Roman
 */

#ifndef DHCP_H_
#define DHCP_H_

#define DEF_TTL             	64
#define DEFAULT_DHCP_SRVPORT	67
#define	DEFAULT_DHCP_CLPORT		68

#define DHCP_UDP_OVERHEAD   (20 +   /* IP header */           \
                 8)                 /* UDP header */
#define DHCP_SRVNAME_LEN	64
#define DHCP_FILENAME_LEN	128
#define DHCP_FIXED_NON_UDP	236
#define DHCP_FIXED_LEN		(DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
                        /* Everything but options. */
#define DHCP_MTU_MAX        1500
#define DHCP_OPTION_LEN     (DHCP_MTU_MAX - DHCP_FIXED_LEN)
#define DHCP_MAX_LEN		1472

#define BOOTP_MIN_LEN       300
#define DHCP_MIN_LEN        548
#define BOOTP_BROADCAST		htons(0x8000)
#define	STR_ETHER_ALEN		17

#pragma pack(1)

typedef struct dhcp_packet
{
  	uint8_t			op;			/* 0: Message opcode/type */
	uint8_t			hw_type;	/* 1: Hardware addr type (net/if_types.h) */
	uint8_t			hwaddr_len;	/* 2: Hardware addr length */
	uint8_t			hops;		/* 3: Number of relay agent hops from client */
	uint32_t		xid;		/* 4: Transaction ID */
	uint16_t		secs;		/* 8: Seconds since client started looking */
	uint16_t 		flags;		/* 10: Flag bits */
	struct in_addr	cli_iaddr;	/* 12: Client IP address (if already in use) */
	struct in_addr	you_iaddr;	/* 16: Client IP address */
	struct in_addr	srv_iaddr;	/* 18: IP address of next server to talk to */
	struct in_addr	gw_iaddr;	/* 20: DHCP relay agent IP address */
	unsigned char	cli_hwaddr [16];		/* 24: Client hardware address */
	char srv_name	[DHCP_SRVNAME_LEN];		/* 40: Server name */
	char boot_file	[DHCP_FILENAME_LEN];	/* 104: Boot filename */
	unsigned char	options[DHCP_OPTION_LEN];
				/* 212: Optional parameters
				   (actual length dependent on MTU). */
} dhcp_message_t;

#pragma pack(0)

/* BOOTP (rfc951) message types */
#define	BOOTREQUEST	1
#define BOOTREPLY	2

/* DHCP message types. */
enum dhcp_message_types
{
	DHCPDISCOVER	= 1,
	DHCPOFFER,		/* 2 */
	DHCPREQUEST,	/* 3 */
	DHCPDECLINE,	/* 4 */
	DHCPACK,		/* 5 */
	DHCPNAK,		/* 6 */
	DHCPRELEASE,	/* 7 */
	DHCPINFORM,		/* 8 */
        DHCPHISTORY	/*9*/
} dhcp_msg_t;

enum dhcp_options_codes
{
	DHCP_OPT_SUBNET_MASK		= 1,
	DHCP_OPT_REQUESTED_ADDRESS	= 50,
	DHCP_OPT_LEASE_TIME			= 51,
	DHCP_OPT_MAX_MESSAGE_SIZE	= 57,
	DHCP_OPT_MESSAGE_TYPE		= 53,
	DHCP_OPT_SERVER_ID			= 54,
	DHCP_OPT_REQUESTED_OPTS		= 55,
	DHCP_OPT_AGENT_OPTIONS		= 82,
	DHCP_OPT_END				= 255
};

typedef struct dhcp_full_packet
{
    struct eth_header eth_head;
    struct iphdr ip_header;
    struct udphdr udp_header;
    dhcp_message_t dhcp_data;
} dhcp_full_packet_t;

#endif /* DHCP_H_ */

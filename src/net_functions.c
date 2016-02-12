/*
 * net_functions.c
 *
 *  Created at: 03.09.2009
 *      Author: Chebotarev Roman
 */

#include "common_includes.h"
#include "db2dhcp_types.h"
#include "net.h"
#include "log.h"
#include "dhcp.h"
#include "misc_functions.h"
#include "dhcp_queue.h"
#include "net_functions.h"

/* Calculate CRC for data in 'buffer'. Return checksumm. */
static uint16_t rs_crc(const unsigned short *buffer, int length);


void assemble_net_header_dhcp
    (
    	dhcp_full_packet_t * dhcp_packet,
		const int data_len,
        const uint8_t * ether_src,
        uint32_t	src_ip,
        uint16_t	src_port,
		const uint8_t * giaddr_ether,
        uint16_t	dst_port,
		uint8_t		msg_type
    )
{
    /* Fill ethernet header */
	memcpy(dhcp_packet->eth_head.ether_shost, ether_src, sizeof(dhcp_packet->eth_head.ether_shost));

	if( (
			/* Set broadcast address if client set BROADCAST flag and DHCP relay is not used */
			(dhcp_packet->dhcp_data.flags & BOOTP_BROADCAST) && !dhcp_packet->dhcp_data.gw_iaddr.s_addr
		) 
			||
		(	/* or if this DHCPNAK message (see RFC2131) and DHCP relay is not used */
			(msg_type == DHCPNAK) && !dhcp_packet->dhcp_data.gw_iaddr.s_addr
		))
	{
		memset(dhcp_packet->eth_head.ether_dhost, 0xFF, sizeof(dhcp_packet->eth_head.ether_dhost));
	}
	else
	{
		if(giaddr_ether)
			memcpy(dhcp_packet->eth_head.ether_dhost,
					giaddr_ether, sizeof(dhcp_packet->eth_head.ether_dhost));
		else
			memcpy(dhcp_packet->eth_head.ether_dhost,
					dhcp_packet->dhcp_data.cli_hwaddr, sizeof(dhcp_packet->eth_head.ether_dhost));
	}

    dhcp_packet->eth_head.ether_type = htons(ETHERTYPE_IP);
    /* Fill IP header */
    bzero(&dhcp_packet->ip_header, sizeof(struct iphdr));
    dhcp_packet->ip_header.ihl = IP_HDR_LEN;
    dhcp_packet->ip_header.version = 4;
    dhcp_packet->ip_header.tos = 0x10;
    dhcp_packet->ip_header.tot_len = htons(B_IP_HDR_LEN + sizeof(struct udphdr) + data_len);
    dhcp_packet->ip_header.id = (uint16_t) rand();
    dhcp_packet->ip_header.frag_off = 0;
    dhcp_packet->ip_header.ttl = DEF_TTL;
    dhcp_packet->ip_header.protocol = IPPROTO_UDP;
    dhcp_packet->ip_header.check = 0;
    dhcp_packet->ip_header.src_addr = src_ip;
    if(dhcp_packet->dhcp_data.you_iaddr.s_addr && !(dhcp_packet->dhcp_data.flags & BOOTP_BROADCAST))
		dhcp_packet->ip_header.dst_addr = dhcp_packet->dhcp_data.gw_iaddr.s_addr ?
			dhcp_packet->dhcp_data.gw_iaddr.s_addr : dhcp_packet->dhcp_data.you_iaddr.s_addr;
    else
	{
		if(dhcp_packet->dhcp_data.gw_iaddr.s_addr)
			dhcp_packet->ip_header.dst_addr = dhcp_packet->dhcp_data.gw_iaddr.s_addr;
		else
			dhcp_packet->ip_header.dst_addr = ~0;	/* Set dst IP = 255.255.255.255 */
	}
    dhcp_packet->ip_header.check = rs_crc((unsigned short*)&dhcp_packet->ip_header, sizeof(struct iphdr));

	bzero(&dhcp_packet->udp_header, sizeof(struct udphdr));
    dhcp_packet->udp_header.source = src_port;
    dhcp_packet->udp_header.dest = dhcp_packet->dhcp_data.gw_iaddr.s_addr ? 
		src_port /* If DHCP relay is used */ : dst_port;
    dhcp_packet->udp_header.len = htons(sizeof(struct udphdr) + data_len);

    return;
}

void assemble_net_header_arp(struct arp_packet_net_header * net_header,
		const uint8_t * ether_src,
		uint16_t op_code)
{
    /* Fill ethernet header */
	memcpy(net_header->eth_head.ether_shost, ether_src, sizeof(net_header->eth_head.ether_shost));
	memset(net_header->eth_head.ether_dhost, 0xFF, sizeof(net_header->eth_head.ether_dhost));
    net_header->eth_head.ether_type = htons(ETHERTYPE_ARP);
    /* Fill ARP header */
    net_header->arp_head.arp_hwtype = htons(1);				/* Ethernet */
	net_header->arp_head.arp_proto = htons(ETHERTYPE_IP);
	net_header->arp_head.arp_hwlen = ETHER_ALEN;
	net_header->arp_head.arp_palen = IPV4_ALEN;
	net_header->arp_head.arp_oper = op_code;
}

int arp_who_has(dhcp_device_t *dev, uint32_t ip)
{
	arp_packet_t arp_pack;
	assemble_net_header_arp(&arp_pack.header, dev->ether_addr, ARP_OP_REQ);

	/* Fill "from" fields - set device Ethernet and IP addresses */
	memcpy(arp_pack.data.from_ether, dev->ether_addr, ETHER_ALEN);
	arp_pack.data.from_ip = dev->ipaddr;

	/* Fill "to" fields - set broacast for Ethernet address and ip for 'to_ip' field */
	memset(arp_pack.data.to_ether, 0xFF, ETHER_ALEN);
	arp_pack.data.to_ip = ip;

	/* Sending packet to network */
	char str_ipaddr[IP4_MAXSTR_ALEN + 1];
	iptos(ip, str_ipaddr);

	if(send_packet(dev, (uint8_t*)&arp_pack, sizeof(arp_pack)))
	{
		log_wr(DLOG, "Sending ARP who-has for check availability of IP address %s on %s.",
				str_ipaddr, dev->str_ipaddr);
		return OK;
	}

	log_wr(ELOG, "Can't send ARP who-has for check availability of IP address %s on %s.",
				str_ipaddr, dev->str_ipaddr);
	return FAIL;
}

inline int send_packet(dhcp_device_t * dhcp_dev, const uint8_t *snd_data, int data_len)
{
	int ret = pcap_inject(dhcp_dev->dev, snd_data, data_len);

	if(ret == -1)
    {
        log_wr(ELOG, "Can't send DHCP packet via interface '%s'. Error: %s",
        		dhcp_dev->str_name, pcap_geterr(dhcp_dev->dev));
        return FAIL;
    }

    return OK;
}

void packet_handler(u_char *out_packet, const struct pcap_pkthdr *h,
                                   const u_char *packet)
{
	if(h->len > DHCP_MTU_MAX)
	{
		log_wr(ELOG, "Received too long packet: %d. Can't dispatch!", h->len);
		return;
	}

    memcpy(out_packet, (u_char*)packet, h->len);
    return;
}

inline int get_packet(dhcp_device_t * dhcp_dev, uint8_t * ether_packet)
{
    int ret = 0;

	ret = pcap_dispatch(dhcp_dev->dev, 1, packet_handler, (u_char*)ether_packet);
	if(ret < 0)
	{
        log_wr(ELOG, "Can't get DHCP packet from interface '%s'. Error: %s",
        		dhcp_dev->str_name, pcap_geterr(dhcp_dev->dev));
		return -1;
	}

    return ret;
}

/* Opening and testing device */
dhcp_device_t * get_device(const char * if_name, int set_index)
{
	dhcp_device_t * dhcp_dev = calloc(1, sizeof(dhcp_device_t));
	if(!dhcp_dev)
	{
		log_wr(CLOG, "Can't allocate memory for DHCP device: %s", strerror(errno));
		exit(error_memory);
	}

    char errbuf[PCAP_ERRBUF_SIZE];

    dhcp_dev->dev = pcap_open_live(if_name, DHCP_MTU_MAX, 0, CAP_TIMEOUT, errbuf);

    if(dhcp_dev->dev == NULL)
    {
        log_wr(CLOG, "Opening device error: '%s'", errbuf);
        exit(error_opendev);
    }

	if(pcap_datalink(dhcp_dev->dev) != DLT_EN10MB)
	{
		log_wr(CLOG, "Can't work on this link layer type! Exit.");
		exit(error_invalid_dev);
	}

	strncpy(dhcp_dev->str_name, if_name, sizeof(dhcp_dev->str_name) - 1);

	char * error = fill_device_net(dhcp_dev);
	if(error)
	{
		log_wr(CLOG, "Can't fill device network field: %s", error);
		exit(error_config);
	}

	/* Creating queue for DHCPOFFERS */

	static const char *offers_queue_prefix = "Offers queue for device ";
	int qname_size = strlen(offers_queue_prefix) + strlen(if_name) + 1;

	char * offers_qname = malloc(qname_size);
	if(!offers_qname)
	{
		log_wr(CLOG, "Can't allocate memory for offers queue name on device '%s': %s",
				if_name, strerror(errno));
		exit(error_memory);
	}

	snprintf(offers_qname, qname_size, "%s%s", offers_queue_prefix, if_name);

	dhcp_dev->offers_queue = dhcp_queue_create(offers_qname, YES, DEFAULT_QUEUE_MAX_SIZE);

	if(dhcp_dev->offers_queue == NULL)
	{
		log_wr(CLOG, "Can't create offers queue on device '%s'.", if_name);
		exit(error_queue_init);
	}

	/* Creating queue for DHCPACK messages */

	static const char *ack_queue_prefix = "Ack queue for device ";
	qname_size = strlen(ack_queue_prefix) + strlen(if_name) + 1;
	char * ack_qname = malloc(qname_size);
	if(!ack_qname)
	{
		log_wr(CLOG, "Can't allocate memory for ack queue name on device '%s': %s",
				if_name, strerror(errno));
		exit(error_memory);
	}

	snprintf(ack_qname, qname_size, "%s%s", ack_queue_prefix, if_name);

	dhcp_dev->ack_queue = dhcp_queue_create(ack_qname, YES, DEFAULT_QUEUE_MAX_SIZE);

	if(dhcp_dev->ack_queue == NULL)
	{
		log_wr(CLOG, "Can't create ack queue on device '%s'.", if_name);
		exit(error_queue_init);
	}

	dhcp_dev->index = set_index;

    return dhcp_dev;
}

/* Original function here: http://minirighi.sourceforge.net/html/udp_8c.html#a0 */
uint16_t udp_checksum(const void * buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr) 
{
	const uint16_t *buf = buff;
	uint32_t sum;
	size_t length = len;

	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	/* Add the padding if the packet lenght is odd */
	if ( len & 1 )
		sum += *((uint8_t *)buf);

	/* Add the pseudo-header */
	pseudo_header_t phdr;
	phdr.src.addr = src_addr;
	phdr.dst.addr = dest_addr;
	phdr.zero = 0;
	phdr.proto = IPPROTO_UDP;
	phdr.length = htons(length);

	sum += phdr.src.bytes.b01;
	sum += phdr.src.bytes.b23;

	sum += phdr.dst.bytes.b01;
	sum += phdr.dst.bytes.b23;

	sum += htons(phdr.proto);
	sum += phdr.length;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	/* Return the one's complement of sum */
	sum = (uint16_t)~sum;
	if(sum == 0)
		sum = 0xFFFF;

	return (uint16_t) sum;
}

static uint16_t rs_crc(const unsigned short *buffer, int length)
{
    uint32_t crc = 0;
    /* Calculate CRC */
    while (length > 1)
    {
        crc += *buffer++;
        length -= sizeof (unsigned short);
    }
    if (length)
        crc += *(unsigned char*) buffer;

    crc = (crc >> 16) + (crc & 0xFFFF);
    crc += (crc >> 16);

    return (uint16_t)(~crc);
}

inline int network_subsystem_init(void)
{
#ifdef _WIN32
	WSADATA wsa_data;
	if ( WSAStartup( 0x202, &wsa_data) )
	{
		log_wr(CLOG, "WSAStartup error: %d\n ", WSAGetLastError ( ) );
		return  FAIL;
	}
#endif
	return OK;
}

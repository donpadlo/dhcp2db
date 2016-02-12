/*
 * net_functions.h
 *
 *  Created at: 03.09.2009
 *      Author: Chebotarev Roman
 */

#ifndef NET_FUNCTIONS_H_
#define NET_FUNCTIONS_H_

/* Return pcap network device if success. Otherwise - exit from programm. */
dhcp_device_t * get_device(const char * if_name, int set_index);

/* Create network header - ethernet + IP + UDP. Store in 'dhcp_packet'. */
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
    );

/* Get packet from network */
extern int get_packet(dhcp_device_t * dhcp_dev, uint8_t * ether_packet);

/* Send packet to network. 'data_len' - all packet data length , include network headers */
extern int send_packet(dhcp_device_t * dhcp_dev, const uint8_t *snd_data, int data_len);

/* Need called for activate network subsystem on WIN32 platforms */
extern int network_subsystem_init(void);

/* Send broadcast ARP who-has to network on device 'dev' from device Ethernet address and IP address == ip*/
int arp_who_has(dhcp_device_t *dev, uint32_t ip);

/* Calculate UDP checksum */
uint16_t udp_checksum(const void * buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr);

#endif /* NET_FUNCTIONS_H_ */

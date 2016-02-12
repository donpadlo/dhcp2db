/*
 * dhcp_cache.h
 *
 *  Created on: 09.01.2011
 *      Author: Roman Chebotarev
 *         Web: www.netpatch.ru
 */

#ifndef DHCP_CACHE_H_
#define DHCP_CACHE_H_

typedef struct dhcp_cache_node
{
	uint32_t			if_ipaddr;
	uint32_t			gw_ipaddr;
	uint8_t				*cli_ethaddr;
	uint8_t				*header_ethaddr;
	dhcp_full_packet_t	cached_response;
	size_t				dhcp_data_len;
	time_t				timestamp;
} dhcp_cache_node_t;

extern const time_t CACHE_FLUSH_PERIOD;

int dhcp_cache_init(time_t nodes_ttl);

dhcp_full_packet_t * dhcp_cache_find(const dhcp_parsed_message_t * request,
		dhcp_full_packet_t * response, size_t * dhcp_data_len);

int dhcp_cache_update(const dhcp_parsed_message_t * request, const dhcp_full_packet_t * response,
		uint16_t dhcp_data_len);

void dhcp_cache_flush_old(void);

#endif /* DHCP_CACHE_H_ */

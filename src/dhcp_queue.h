/*
 * dhcp_queue.h
 *
 *  Created at: 24.02.2010
 *      Author: Roman Chebotarev
 */

#ifndef DHCP_QUEUE_H_
#define DHCP_QUEUE_H_

/* Create and return DHCP queue structure */
dhcp_queue_t * dhcp_queue_create(const char * queue_name, int locked_queue, int max_size);
int dhcp_queue_add(dhcp_queue_t * queue, dhcp_parsed_message_t * dhcp_msg, int drop_oldes_on_overflow);
dhcp_queue_node_t * dhcp_queue_get(dhcp_queue_t * queue, time_t age, int blocked);
int dhcp_queue_remove(dhcp_queue_t * queue, dhcp_queue_node_t * node, int need_lock);
dhcp_queue_node_t * dhcp_queue_update_if_found(dhcp_queue_t * queue, dhcp_parsed_message_t * dhcp_msg);
dhcp_queue_node_t * dhcp_queue_find_by_ip(dhcp_queue_t * queue, uint32_t ip);
void dhcp_queue_free_node(dhcp_queue_node_t * node, dhcp_queue_t * queue, int need_lock);

#endif /* DHCP_QUEUE_H_ */

/*
 * dhcp_process.h
 *
 *  Created at: 27.08.2009
 *      Author: Chebotarev Roman
 */

#ifndef DHCP_PROCESS_H_
#define DHCP_PROCESS_H_

/* TODO need comment */
int run_dhcp_threads(dhcp_proc_thread_t **dhcp_threads, const server_configuration * config,
		request_handler_thread_t **db_clients);
/* TODO need comment */
void * dhcp_process(void * args);
/* TODO need comment */
uint8_t * get_dhcp_option_ptr(const dhcp_message_t *request, const uint16_t packet_len,
        const uint8_t req_option, uint16_t * option_len);
/* Return constant pointer to string of DHCP message type name */
const char * dhcp_str_type(uint8_t type);


#endif /* DHCP_PROCESS_H_ */

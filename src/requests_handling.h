/*
 * requests_handling.h
 *
 *  Created at: 17.09.2009
 *      Author: Chebotarev Roman
 */

#ifndef REQUESTS_HANDLING_H_
#define REQUESTS_HANDLING_H_

enum option_indexes
{
	OPT_CODE,
	OPT_LEN,
	OPT_VALUE
};

typedef enum packet_flags
{
	PFLAG_DNT_CACHE	= 0x00000001
} packet_flags_t;

int run_requests_handlers(request_handler_thread_t **db_threads, const server_configuration * config);
void print_dhcp_header_offsets(void);

#endif /* REQUESTS_HANDLING_H_ */

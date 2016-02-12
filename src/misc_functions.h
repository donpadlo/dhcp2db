/*
 * misc_functions.h
 *
 *  Created at: 06.03.2010
 *      Author: Roman Chebotarev
 *         Web: www.netpatch.ru
 */

#ifndef MISC_FUNCTIONS_H_
#define MISC_FUNCTIONS_H_

char * interfaces_discover(const int num);
extern void free_query_result(query_result_t * result);
/* TODO need comment */
extern char * etheraddr_bin_to_str(const uint8_t * bin_addr, char * str_addr);
/* TODO need comment */
extern char * hex_to_str(int count, const uint8_t *bin_addr, char * str_addr);
uint8_t * str_to_hex(int count, char * hex_str, uint8_t * hex_addr);
/* TODO need comment */
char * fill_device_net(dhcp_device_t * device);
/* Convert a numeric IP address to a string */
char *iptos(const uint32_t in, char * out_buffer);
/* TODO need comment */
uint32_t get_ip_by_ifname(pcap_if_t * if_list_start, char * if_name);
/* Get item from query results by code */
extern result_item_t * get_result_value(query_result_t * result, uint16_t need_code);
extern char * gethostname_error(void);
/* Convert network mask to CIDR notation */
uint32_t to_cidr(uint32_t mask);

#ifdef _WIN32

struct timezone
{
  int  tz_minuteswest; /* minutes W of Greenwich */
  int  tz_dsttime;     /* type of dst correction */
};

inline int gettimeofday(struct timeval *tv, struct timezone *tz);

inline int inet_aton(char * str_ip, struct in_addr * dst);

#endif	/* _WIN32 */

extern uint32_t make_default_netmask(const uint32_t addr);

#endif /* MISC_FUNCTIONS_H_ */

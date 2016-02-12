/*
 * misc_functions.c
 *
 *  Created at: 06.03.2010
 *      Author: Roman Chebotarev
 *         Web: www.netpatch.ru
 */

#include <pcap.h>
#include "db2dhcp_types.h"
#include "log.h"
#include "misc_functions.h"

static const char hex_digits[] = "0123456789ABCDEF";

/* Print pcap device information */
static void ifprint(const pcap_if_t *dev);

char * fill_device_net(dhcp_device_t * device)
{
	static char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap_lookupnet(device->str_name, &device->network, &device->netmask, errbuf) == -1)
		return errbuf;
	return NULL;
}

char * interfaces_discover(const int num)
{
	if(!num)
		printf("Available interfaces:\n");

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *dev_list_start = 0, * dev_ptr = 0;
	char * if_name = 0;
    int32_t ret = pcap_findalldevs(&dev_list_start, errbuf);

    if(ret == -1)
    {
        fprintf(stderr, "Discovering interfaces error: %s\n", errbuf);
        exit(error_listing_dev);
    }

    if(!dev_list_start)
    {
        fprintf(stderr, "No network devices found.\n");
        exit(error_listing_dev);
    }

	int i = 1;
    for(dev_ptr = dev_list_start; dev_ptr; dev_ptr = dev_ptr->next)
	{
		if(num)
		{
			if(!strcmp("any", dev_ptr->name))
				continue;
			if((i == num))
			{
				if_name = strdup(dev_ptr->name);
				if(!if_name)
				{
					fprintf(stderr, "Can't allocate memory for interface name '%s'. Quit.\n", dev_ptr->name);
					exit(error_memory);
				}
				pcap_freealldevs(dev_list_start);
				return if_name;

			}
			++i;
		}
		else
		{
			if(strcmp("any", dev_ptr->name))
			{
				printf("%d:", i++);
				ifprint(dev_ptr);
			}
		}
	}

	pcap_freealldevs(dev_list_start);

	if(num)	/* Suitable device not found */
		return 0;

	exit(error_config);
}

static void ifprint(const pcap_if_t *dev)
{
	pcap_addr_t *pcap_addr;
	/* Name */
	printf("%s", dev->name);
	/* Description */
	if (dev->description)
		printf("\n  descr: %s", dev->description);
	/* IP addresses */
	char addr_buf[IP4_MAXSTR_ALEN + 1];
	for(pcap_addr = dev->addresses; pcap_addr; pcap_addr = pcap_addr->next)
	{
		if(!pcap_addr->addr)
		continue;
		switch(pcap_addr->addr->sa_family)
		{
			case AF_INET:
				if (pcap_addr->addr)
					printf("\n  IPv4 addresss: %s",
							iptos(((struct sockaddr_in *)pcap_addr->addr)->sin_addr.s_addr, addr_buf));
				if (pcap_addr->netmask)
					printf("/%d ", to_cidr(((struct sockaddr_in *)pcap_addr->netmask)->sin_addr.s_addr));
				if (pcap_addr->broadaddr)
					printf(" bcast: %s",
							iptos(((struct sockaddr_in *)pcap_addr->broadaddr)->sin_addr.s_addr, addr_buf));
				if (pcap_addr->dstaddr)
					printf(" dst addr: %s",
							iptos(((struct sockaddr_in *)pcap_addr->dstaddr)->sin_addr.s_addr, addr_buf));
			break;
			case AF_INET6:
				/* fprintf(stderr, "Error: IPv6 address unsupported yet.\n"); */
			break;
			default:
				/* fprintf(stderr, "Error: unknown address family.\n"); */
			break;
		}
	}
	printf("\n");
}

/* Convert network mask to CIDR notation */
uint32_t to_cidr(uint32_t mask)
{
	mask = ntohl(mask);
	int i;
	for(i = 0; i < 33; ++i)
		if(mask & (1 << i))
			break;
	return (i == 33)? 0 : 32 - i;
}

inline result_item_t * get_result_value(query_result_t * result, uint16_t need_code)
{
	int i;

	for (i = 0; i < result->count; ++i)
		if(result->items[i].code == need_code)
			return &result->items[i];

	return NULL;
}

inline void free_query_result(query_result_t * result)
{
	int i;
	for (i = 0; i < result->count; ++i)
		free(result->items[i].data);
	free(result->items);
	free(result);
}

inline char * etheraddr_bin_to_str(const uint8_t * bin_addr, char * str_addr)
{
	if(!bin_addr || !str_addr)
		return NULL;

	int i, j;
	for(i = j = 0; i < 6; ++i, j += 3)
	{
		str_addr[j] = hex_digits[bin_addr[i] >> 4];
		str_addr[j + 1] = hex_digits[bin_addr[i] & 0x0F];
		str_addr[j + 2] = ':';
	}
	str_addr[STR_ETHER_ALEN] = '\0';

	return str_addr;
}

inline char * hex_to_str(int count, const uint8_t *bin_addr, char * str_addr)
{
	int i, j;
	for(i = j = 0; i < count; ++i, j += 2)
	{
		str_addr[j] = hex_digits[bin_addr[i] >> 4];
		str_addr[j + 1] = hex_digits[bin_addr[i] & 0x0F];
	}
	return str_addr;
}

uint8_t * str_to_hex(int count, char * hex_str, uint8_t * hex_addr)
{
	int i, j;
	char c, *pt;
	for(i = j = 0; i < count; ++i, j += 2)
	{
		c = toupper(hex_str[j]);
		pt = strchr(hex_digits, c);
		if(!pt)
			return NULL;
		hex_addr[i] = (pt - hex_digits) << 4;

		c = toupper(hex_str[j + 1]);
		pt = strchr(hex_digits, c);
		if(!pt)
			return NULL;
		hex_addr[i] |= pt - hex_digits;
	}
	return hex_addr;
}

char *iptos(const uint32_t in, char * out_buffer)
{
    uint8_t * p = (uint8_t *)&in;
    bzero(out_buffer, IP4_MAXSTR_ALEN + 1);
    snprintf(out_buffer, IP4_MAXSTR_ALEN + sizeof('\0'), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return out_buffer;
}

uint32_t get_ip_by_ifname(pcap_if_t * if_list_start, char * if_name)
{
	pcap_if_t * if_ptr = if_list_start;
	while(if_ptr)
	{
		if( !strcmp(if_ptr->name, if_name))
			break;
		if_ptr = if_ptr->next;
	}

	if(!if_ptr)
	{
		log_wr(CLOG, "Invalid interface name for get device IP address: %s.", if_name);
		return FAIL;
	}
	if(!if_ptr->addresses)
	{
		log_wr(CLOG, "Interface with name '%s' hasn't primary IP addresses.\n", if_name);
		return FAIL;
	}
	if(!if_ptr->addresses->addr)
	{
		log_wr(CLOG, "Interface with name '%s' hasn't primary IP addresses.\n", if_name);
		return FAIL;
	}
	if(if_ptr->addresses->addr->sa_family != AF_INET
#if		__linux__
		&& if_ptr->addresses->addr->sa_family != AF_PACKET
#elif	__FreeBSD__		
		&& if_ptr->addresses->addr->sa_family != AF_LINK
#endif
	)
	{
		log_wr(CLOG, "Invalid address family of primary IP address on interface '%s'. Family ID: %d",
			if_name, if_ptr->addresses->addr->sa_family);
		return FAIL;
	}

	uint32_t min_addr = ~0;
	while(if_ptr->addresses)
	{
		if(if_ptr->addresses->addr->sa_family == AF_INET)
		{
			if(((struct sockaddr_in *)if_ptr->addresses->addr)->sin_addr.s_addr < min_addr)
				min_addr = ((struct sockaddr_in *)if_ptr->addresses->addr)->sin_addr.s_addr;
		}
		if_ptr->addresses = if_ptr->addresses->next;
	}

	if(min_addr == ~0)
	{
		log_wr(CLOG, "Invalid IP address on interface '%s'\n", if_name);
		return FAIL;
	}

	return min_addr;
}

#ifdef _WIN32
/* Unfortunately, Windows - a wretched system for network programming :( */
inline int inet_aton(char * str_ip, struct in_addr * dst)
{
	static const char limited_broadcast[] = "255.255.255.255";
	if( (dst->s_addr = inet_addr(str_ip)) == INADDR_NONE )
	{	/* Check for broadcast first */
		if(strcmp(str_ip, limited_broadcast))
			return FAIL;
	}
	return OK;
}

inline char * gethostname_error(void)
{
	char *str_error;
	switch(WSAGetLastError())
	{
	case WSAEFAULT:
		str_error = "Not enough memory for store hostname value.";
		break;
	case WSANOTINITIALISED:
		str_error = "WSAStartup must be called before gethostname().";
		break;
	case WSAENETDOWN:
		str_error = "The network subsystem has failed.";
		break;
	case WSAEINPROGRESS:
		str_error = "A blocking Windows Sockets 1.1 call is in progress, or the service provider is still processing a callback function.";
		break;
	default:
		str_error = "Unknown error.";
		break;
	}
	return str_error;
}

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	/*
	 * Thanks scor7910 for idea of this function:
	 * http://social.msdn.microsoft.com/forums/en/vcgeneral/thread/430449b3-f6dd-4e18-84de-eebd26a8d668/
	 */

	if (NULL != tv)
	{
		FILETIME ft;
		unsigned __int64 tmpres = 0;

		GetSystemTimeAsFileTime(&ft);

		tmpres = ((unsigned __int64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

		tmpres /= 10;  /* Convert into microseconds */
		tv->tv_sec = (long)(tmpres / 1000000UL);
		tv->tv_usec = (long)(tmpres % 1000000UL);
	}

	if (NULL != tz)
	{
		static int tzflag;

		if (!tzflag)
		{
			_tzset();
			tzflag++;
		}
		tz->tz_minuteswest = _timezone / 60;
		tz->tz_dsttime = _daylight;
	}

	return 0;
}

#else
inline char * gethostname_error(void)
{
	return strerror(errno);
}
#endif	/* _WIN32*/


inline uint32_t make_default_netmask(const uint32_t addr)
{
    if(addr <= 0x7FFFFFFF)
        return 0xFF000000;
    if(addr <= 0xBFFF0000)
        return 0xFFFF0000;
    if(addr <= 0xDFFFFF00)
        return 0xFFFFFF00;
    return 0xFFFFFFFF;
}


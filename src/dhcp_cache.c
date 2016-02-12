/*
 * dhcp_cache.c
 *
 *  Created on: 09.01.2011
 *      Author: Roman Chebotarev
 *         Web: www.netpatch.ru
 */

#include "common_includes.h"
#include "db2dhcp_types.h"
#include "log.h"
#include "misc_functions.h"
#include "dhcp_cache.h"
#include "dhcp_process.h"

static pthread_rwlock_t cache_lock;
static time_t cache_node_ttl;
static time_t cache_now;
static time_t cache_last_flush;

const time_t CACHE_FLUSH_PERIOD = 60;

inline static void cache_rdlock(void);
inline static void cache_wrlock(void);
inline static void cache_unlock(void);

#include"rbtree.h"

typedef struct dhcp_cache_flushing_queue
{
	rb_red_blk_node * node;
	struct dhcp_cache_flushing_queue * next;
} dhcp_fqueue_t;

static rb_red_blk_tree *cache;

void node_print(const void* node) { }

void info_print(void * node) { }

void info_destroy(void * node){
  free((dhcp_cache_node_t*)node);
}

void node_destroy(void * node) { }

static int cmp_nodes(const void * n1, const void * n2)
{
	dhcp_cache_node_t *r1 = (dhcp_cache_node_t*) n1;
	dhcp_cache_node_t *r2 = (dhcp_cache_node_t*) n2;

	int ret;

	if( (ret = memcmp(&r1->if_ipaddr, &r2->if_ipaddr, sizeof(r1->if_ipaddr))) )
		return ret;

	if( (ret = memcmp(&r1->gw_ipaddr, &r2->gw_ipaddr, sizeof(r1->gw_ipaddr))) )
		return ret;

	if( (ret = memcmp(r1->header_ethaddr, r2->header_ethaddr, ETHER_ALEN)) )
		return ret;

	return memcmp(r1->cli_ethaddr, r2->cli_ethaddr, ETHER_ALEN);
}

int dhcp_cache_init(time_t nodes_ttl)
{
    int err;
    if( (err = pthread_rwlock_init(&cache_lock, NULL) ) )
    {
        log_wr(CLOG, "Can't init rw_lock for DHCP cache: '%s'", strerror(err));
        return FAIL;
    }

    cache_node_ttl = nodes_ttl;
    cache_last_flush = time(NULL);

	cache = RBTreeCreate(cmp_nodes, node_destroy, info_destroy, node_print, info_print);

    return cache ? OK : FAIL;
}

dhcp_fqueue_t * search_obsolete_nodes(rb_red_blk_node* x, dhcp_fqueue_t * deleting_queue)
{
	char str_ether[STR_ETHER_ALEN + 1];
	char str_ipaddr[2][IP4_MAXSTR_ALEN + 1];

	if (x != cache->nil) 
	{
		deleting_queue = search_obsolete_nodes(x->left, deleting_queue);
		dhcp_cache_node_t * node = x->info;

		if(node->timestamp + cache_node_ttl < cache_now)
		{
			etheraddr_bin_to_str(node->cli_ethaddr, str_ether);
			iptos(node->cached_response.dhcp_data.you_iaddr.s_addr, str_ipaddr[0]);

			log_wr(DLOG, "Adding DHCP cache node %s/%s%s%s%s to deleting queue - TTL exceeded.",
					str_ether, str_ipaddr[0],
				node->gw_ipaddr ? " (relay: " : "",
				node->gw_ipaddr ? iptos(node->gw_ipaddr, str_ipaddr[1]) : "",
				node->gw_ipaddr ? ")" : "");

			dhcp_fqueue_t * del_node = calloc(1, sizeof(dhcp_fqueue_t));
			if(!del_node)
			{
				log_wr(CLOG, "Can't allocate memory for adding node to deleting queue: '%s'", strerror(errno));
				exit(error_memory);
			}
			
			del_node->node = x;

			if(deleting_queue)
			{
				del_node->next = deleting_queue;
				deleting_queue = del_node;
			}
			else	/* Empty queue */
				deleting_queue = del_node;
		}
		deleting_queue = search_obsolete_nodes(x->right, deleting_queue);
	}

	return deleting_queue;
}


void dhcp_cache_flush_old(void)
{
	cache_wrlock();

	cache_now = time(NULL);

	if(cache_last_flush + CACHE_FLUSH_PERIOD > cache_now)
	{
		cache_unlock();
		return;
	}

	log_wr(DLOG, "Flushing cache: last flush ts - %lu, flush period - %lu, now is %lu.",
			cache_last_flush, CACHE_FLUSH_PERIOD, cache_now);

	size_t num_del = 0;

	dhcp_fqueue_t * deleting_queue = search_obsolete_nodes(cache->root->left, NULL);


	char str_ether[STR_ETHER_ALEN + 1];
	char str_ipaddr[2][IP4_MAXSTR_ALEN + 1];

	dhcp_fqueue_t * q_ptr;
	dhcp_cache_node_t * del_node;
	uint32_t gw_ipaddr;

	/* Removing him's if exists */
	while(deleting_queue)
	{
		del_node = deleting_queue->node->info;

		etheraddr_bin_to_str(del_node->cli_ethaddr, str_ether);
		iptos(del_node->cached_response.dhcp_data.you_iaddr.s_addr, str_ipaddr[0]);
		gw_ipaddr = del_node->gw_ipaddr;

		RBDelete(cache, deleting_queue->node);

		log_wr(DLOG, "Cache node for %s/%s%s%s%s deleted.", str_ether, str_ipaddr[0],
				gw_ipaddr ? " (relay: " : "",
				gw_ipaddr ? iptos(gw_ipaddr, str_ipaddr[1]) : "",
				gw_ipaddr ? ")" : "");
		++num_del;

		q_ptr = deleting_queue->next;
		free(deleting_queue);
		deleting_queue = q_ptr;
	}
  	
	log_wr(DLOG, "Cache flushed. Total %u nodes deleted.", num_del);

	cache_last_flush = cache_now;

	cache_unlock();

	return;
}


int dhcp_cache_update(const dhcp_parsed_message_t * request, const dhcp_full_packet_t * response,
		uint16_t dhcp_data_len)
{
	char str_ether[STR_ETHER_ALEN + 1];
	char str_ipaddr[2][IP4_MAXSTR_ALEN + 1];

	etheraddr_bin_to_str(request->raw_dhcp_msg->cli_hwaddr, str_ether);
	iptos(response->dhcp_data.you_iaddr.s_addr, str_ipaddr[0]);

	dhcp_cache_node_t s_data;
	s_data.if_ipaddr = request->dhcp_dev->ipaddr;
	s_data.gw_ipaddr = request->raw_dhcp_msg->gw_iaddr.s_addr;
	s_data.cli_ethaddr = (typeof(s_data.cli_ethaddr))request->raw_dhcp_msg->cli_hwaddr;
	s_data.header_ethaddr = (typeof(s_data.header_ethaddr))request->from_ether;

	rb_red_blk_node *f_node;

	cache_wrlock();
	time_t now = time(NULL);

	dhcp_cache_node_t * cached_node = NULL;
	if ( ( f_node = RBExactQuery(cache, &s_data) ) ) 
	{
		cached_node = f_node->info;
		log_wr(DLOG, "Update cached data for client %s/%s.", str_ether, str_ipaddr[0]);
		cached_node->timestamp = now;
		memcpy(&cached_node->cached_response, response, sizeof(*response));
	} 
	else 
	{	/* Node not found in cache. Add. */
		cached_node = calloc(1, sizeof(dhcp_cache_node_t));
		if(!cached_node)
		{
			log_wr(CLOG, "Can't allocate memory for new DHCP cache node: '%s'", strerror(errno));
			exit(error_memory);
		}

		memcpy(&cached_node->cached_response, response, sizeof(cached_node->cached_response));
		cached_node->if_ipaddr = request->dhcp_dev->ipaddr;
		cached_node->gw_ipaddr = request->raw_dhcp_msg->gw_iaddr.s_addr;
		cached_node->cli_ethaddr = cached_node->cached_response.dhcp_data.cli_hwaddr;
		cached_node->header_ethaddr = cached_node->cached_response.eth_head.ether_dhost;
		cached_node->timestamp = now;

		f_node = RBTreeInsert(cache, cached_node, cached_node);

		log_wr(DLOG, "Added response for client %s/%s%s%s%s to DHCP cache.", str_ether, str_ipaddr[0],
					cached_node->gw_ipaddr ? " (relay: " : "",
					cached_node->gw_ipaddr ? iptos(cached_node->gw_ipaddr, str_ipaddr[1]) : "",
					cached_node->gw_ipaddr ? ")" : "");
	}

	/* Set DHCPACK message type for cached response */
	uint16_t type_len;
	uint8_t * cached_response_type = get_dhcp_option_ptr(&cached_node->cached_response.dhcp_data,
			cached_node->cached_response.udp_header.len, DHCP_OPT_MESSAGE_TYPE, &type_len);
	if(!cached_response_type)
	{
		log_wr(CLOG, "Invalid DHCP message cached (%s/%s): DHCP message type option not found.",
				str_ether, str_ipaddr);
		RBDelete(cache, f_node);
		free(cached_node);

		cache_unlock();

		return 0;
	}

	cached_node->dhcp_data_len = dhcp_data_len;

	*cached_response_type = DHCPACK;

	cache_unlock();

	return 1;
}

dhcp_full_packet_t * dhcp_cache_find(const dhcp_parsed_message_t * request,
		dhcp_full_packet_t * response, size_t * dhcp_data_len)
{
	/* Lock cache for read */
	cache_rdlock();

	dhcp_cache_node_t s_data;
	s_data.if_ipaddr = request->dhcp_dev->ipaddr;
	s_data.gw_ipaddr = request->raw_dhcp_msg->gw_iaddr.s_addr;
	s_data.cli_ethaddr = (typeof(s_data.cli_ethaddr))request->raw_dhcp_msg->cli_hwaddr;
	s_data.header_ethaddr = (typeof(s_data.header_ethaddr))request->from_ether;
	
	rb_red_blk_node *f_node;

	dhcp_cache_node_t * cached_node = NULL;
	if ( ( f_node = RBExactQuery(cache, &s_data) ) ) 
	{
		cached_node = f_node->info;
		*dhcp_data_len = cached_node->dhcp_data_len;
		memcpy(response, &cached_node->cached_response, *dhcp_data_len);
	} else 
	{
		response = NULL;
		*dhcp_data_len = 0;
	}

	cache_unlock();

	return response;
}

inline static void cache_rdlock(void)
{
    int err;
    if( (err = pthread_rwlock_rdlock(&cache_lock)) )
    {
        log_wr(CLOG, "Error on pthread_rdlock_wrlock() for lock DHCP cache: '%s'",
        		strerror(err));
        exit(error_abnormal);
    }
}

inline static void cache_wrlock(void)
{
    int err;
    if( (err = pthread_rwlock_wrlock(&cache_lock)) )
    {
        log_wr(CLOG, "Error on pthread_rwlock_wrlock() for lock DHCP cache: '%s'",
        		strerror(err));
        exit(error_abnormal);
    }
}

inline static void cache_unlock(void)
{
    int err;
    if( (err = pthread_rwlock_unlock(&cache_lock)) )
    {
        log_wr(CLOG, "Error on pthread_rwlock_unlock() for unlock DHCP cache: '%s'",
        		strerror(err));
        exit(error_abnormal);
    }
}


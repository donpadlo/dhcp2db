/*
 * dhcp_queue.c
 *
 *  Created at: 24.02.2010
 *      Author: Roman Chebotarev
 */

#include "common_includes.h"
#include "db2dhcp.h"
#include "db2dhcp_types.h"
#include "log.h"
#include "misc_functions.h"

#include "dhcp_queue.h"
/* TODO 20 Убрать лишние функции из заголовков - прототипы вернуть в .c файлы, объявить их как static */

static inline unsigned long int timestamp_diff(const struct timeval * tv_orig,
		const struct timeval * tv_now);

dhcp_queue_t * dhcp_queue_create(const char * queue_name, int locked_queue, int max_size)
{
	dhcp_queue_t *queue = calloc(1, sizeof(dhcp_queue_t));
	if(!queue)
	{
		log_wr(CLOG, "Can't allocate memory for queue %s: %s", queue_name, strerror(errno));
		return NULL;
	}

	queue->name = (char*)queue_name;
	queue->max_size = max_size;

	if(locked_queue)
	{
		queue->lock_get = malloc(sizeof(*queue->lock_get));
		if(!queue->lock_get)
		{
			log_wr(CLOG, "Can't allocate memory for mutex in queue '%s'.", queue_name);
			return NULL;
		}

		if(pthread_mutex_init(queue->lock_get, NULL))
		{
			log_wr(CLOG, "Can't init mutex for lock get in queue '%s'.", queue_name);
			return NULL;
		}

		queue->cond_get = malloc(sizeof(*queue->cond_get));
		if(!queue->cond_get)
		{
			log_wr(CLOG, "Can't allocate memory for wait condition in queue '%s'.", queue_name);
			return NULL;
		}
		if ( pthread_cond_init(queue->cond_get, NULL) )
		{
			log_wr(CLOG, "Can't init condition for blocking SQL client threads in queue '%s': %s",
				queue_name, strerror(errno));
			return NULL;
		}
	}

	return queue;
}

int dhcp_queue_add(dhcp_queue_t * queue, dhcp_parsed_message_t * dhcp_msg, int drop_oldest_on_overflow)
{
	if(queue->lock_get)
		pthread_mutex_lock(queue->lock_get);

	if(queue->count == queue->max_size)
	{
		if(!drop_oldest_on_overflow)
		{
			log_wr(ELOG, "Queue '%s' is overflow. Max size reached: %d", queue->name, queue->max_size);
			pthread_mutex_unlock(queue->lock_get);
			return FAIL;
		}
		dhcp_queue_node_t * oldest = queue->first;
		if(!dhcp_queue_remove(queue, oldest, NO))
		{
			log_wr(CLOG, "Queue '%s' is overflow, but I can't remove oldest node.", queue->name);
			pthread_mutex_unlock(queue->lock_get);
			return FAIL;
		}
		log_wr(DLOG, "Removing oldest node from DHCP queue '%s'", queue->name);
		dhcp_queue_free_node(oldest, queue, NO);
	}

	if(!queue->count)	/* Empty queue */
	{
		log_wr(DLOG, "Adding DHCP message to empty queue '%s'", queue->name);
		queue->first = queue->last = calloc(1, sizeof(dhcp_queue_node_t));
		if(!queue->first)
		{
			log_wr(CLOG, "Can't allocate memory for node in queue '%s': %s", queue->name, strerror(errno));
			return FAIL;
		}
	}
	else
	{
		log_wr(DLOG, "Adding DHCP message to queue.");
		queue->last->next = calloc(1, sizeof(dhcp_queue_node_t));
		if(!queue->last)
		{
			log_wr(CLOG, "Can't allocate memory for node in queue '%s': %s", queue->name, strerror(errno));
			return FAIL;
		}
		queue->last->next->prev = queue->last;
		queue->last = queue->last->next;
	}

	queue->last->dhcp_req = dhcp_msg;
	queue->last->next = NULL;
	queue->last->processed = 0;

	gettimeofday(&queue->last->ts, NULL);	/* Set current timestamp for new node */

	++queue->count;
	++queue->new_requests;

	log_wr(DLOG, "Queue (%s) length now is: %d, new requests: %d", queue->name, queue->count, queue->new_requests);

	if(queue->cond_get)
	{
		if(pthread_cond_signal(queue->cond_get))	/* Waking up any SQL thread */
		{
			log_wr(CLOG, "Can't send change condition signal to SQL threads for queue '%s': %s", queue->name, strerror(errno));
			return FAIL;
		}
	}

	if(queue->lock_get)
		pthread_mutex_unlock(queue->lock_get);

	return OK;
}

dhcp_queue_node_t * dhcp_queue_get(dhcp_queue_t * queue, time_t age_usecs, int blocked)
{
	if(queue->lock_get)
		pthread_mutex_lock(queue->lock_get);

	if(!blocked && !queue->new_requests)
	{
		pthread_mutex_unlock(queue->lock_get);
		return NULL;
	}

	if(queue->lock_get && queue->cond_get)
	{
		while(!queue->new_requests)
			pthread_cond_wait(queue->cond_get, queue->lock_get);
	}
	if(!age_usecs)
		log_wr(DLOG, "Trying to get DHCP request from queue '%s'.", queue->name);

	dhcp_queue_node_t * pt = queue->first;

    struct timeval now;
	if(age_usecs)
		gettimeofday(&now, NULL);
	time_t diff;
	while(pt)
	{
		if(!pt->processed)
		{
			if(age_usecs && ((diff = timestamp_diff(&pt->ts, &now)) < age_usecs) )
				goto _next_node;

			pt->processed = 1;
			++pt->used_by;
			--queue->new_requests;
			break;
		}

_next_node:
		pt = pt->next;
	}

	if(!pt && !age_usecs)
		log_wr(ELOG, "No now requests found in queue '%s'.", queue->name);

	if(queue->lock_get)
		pthread_mutex_unlock(queue->lock_get);

    return pt;
}

dhcp_queue_node_t * dhcp_queue_find_by_ip(dhcp_queue_t * queue, uint32_t ip)
{
	if(queue->lock_get)
		pthread_mutex_lock(queue->lock_get);

	dhcp_queue_node_t * node = queue->first;

	while(node)
	{
		if(DHCP_DATA_FROM_FULL_PACKET(node->dhcp_req->raw_dhcp_msg)->you_iaddr.s_addr == ip)
			break;
		node = node->next;
	}

	if(queue->lock_get)
		pthread_mutex_unlock(queue->lock_get);

	return node;
}

dhcp_queue_node_t * dhcp_queue_update_if_found(dhcp_queue_t * queue, dhcp_parsed_message_t * dhcp_msg)
{
	if(queue->lock_get)
		pthread_mutex_lock(queue->lock_get);

	dhcp_queue_node_t * node = queue->first;

	uint8_t * cli_hw = dhcp_msg->raw_dhcp_msg->cli_hwaddr;
	typeof(dhcp_msg->dhcp_dev->network) cli_network = dhcp_msg->dhcp_dev->network;

	while(node)
	{
		if(!memcmp(node->dhcp_req->raw_dhcp_msg->cli_hwaddr, cli_hw, ETHER_ALEN) &&
				node->dhcp_req->dhcp_dev->network == cli_network &&
				node->dhcp_req->raw_dhcp_msg->gw_iaddr.s_addr == dhcp_msg->raw_dhcp_msg->gw_iaddr.s_addr)
		{	/* Updating node */
			log_wr(DLOG, "Updating node with xid %u to xid %u",
				node->dhcp_req->raw_dhcp_msg->xid, dhcp_msg->raw_dhcp_msg->xid);
			if(node->dhcp_req->length < dhcp_msg->length)
			{
				log_wr(DLOG, "Realloc memory for updating node with xid %d", dhcp_msg->raw_dhcp_msg->xid);
				if( ! (node->dhcp_req->raw_dhcp_msg = realloc(node->dhcp_req->raw_dhcp_msg, dhcp_msg->length)) )
				{
					log_wr(CLOG, "Can't realloc memory for updating queue node: %s", strerror(errno));
					exit(error_memory);
				}
				node->dhcp_req->length = dhcp_msg->length;
			}
			memcpy(node->dhcp_req->raw_dhcp_msg, dhcp_msg->raw_dhcp_msg, dhcp_msg->length);
			memcpy(node->dhcp_req->from_ether, dhcp_msg->from_ether, sizeof(node->dhcp_req->from_ether));
			node->dhcp_req->length = dhcp_msg->length;
			break;
		}
		node = node->next;
	}

	if(queue->lock_get)
		pthread_mutex_unlock(queue->lock_get);

	return node;
}

int dhcp_queue_remove(dhcp_queue_t * queue, dhcp_queue_node_t * node, int need_lock)
{
	if(need_lock && queue->lock_get)
		pthread_mutex_lock(queue->lock_get);

	int ret = OK;

	if(node->removed)
		goto _removed;	/* Already removed from queue by other thread  */

	if(!queue->count)
	{
		log_wr(ELOG, "Can't remove node from empty queue '%s'.", queue->name);
		ret = FAIL;
		goto _removed;
	}

	if(queue->count == 1)
	{
		queue->first = queue->last = NULL;
		queue->new_requests = 0;
	}
	else
	{
		if(node->prev)
		{
			if(node->next)
				node->prev->next = node->next;
			else	/* This is last node */
			{
				queue->last = node->prev;
				node->prev->next = NULL;
			}
		}

		if(node->next)
		{
			if(node->prev)
				node->next->prev = node->prev;
			else	/* This is first node */
			{
				queue->first = node->next;
				node->next->prev = NULL;
			}
		}

	}

	--queue->count;
	node->removed = 1;

	log_wr(DLOG, "DHCP request removed from queue '%s'. Queue len now is: %d, new requests: %d",
			queue->name, queue->count, queue->new_requests);

_removed:

	if(need_lock && queue->lock_get)
		pthread_mutex_unlock(queue->lock_get);

	return ret;
}

/* Safe free memory from node */
void dhcp_queue_free_node(dhcp_queue_node_t * node, dhcp_queue_t * queue, int need_lock)
{
	if(need_lock && queue->lock_get)
		pthread_mutex_lock(queue->lock_get);

	if( (--node->used_by) == 0)	/* Node already unused, delete it! */
	{
		if(node->dhcp_req->raw_dhcp_msg)
			free(node->dhcp_req->raw_dhcp_msg);
		if(node->dhcp_req)
			free(node->dhcp_req);
		free(node);
	}

	if(need_lock && queue->lock_get)
		pthread_mutex_unlock(queue->lock_get);
}

static inline unsigned long int timestamp_diff(const struct timeval * tv_orig, const struct timeval * tv_now)
{
	if(tv_orig->tv_sec == tv_now->tv_sec)
		return tv_now->tv_usec - tv_orig->tv_usec;
	else
		return
			1000000 - tv_orig->tv_usec
			+ (tv_now->tv_sec - tv_orig->tv_sec - 1) * 1000000
			+ tv_now->tv_usec;

}

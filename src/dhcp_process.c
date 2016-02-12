/*
 * dhcp_process.c
 *
 *  Created at: 27.08.2009
 *      Author: Chebotarev Roman
 */

#include "common_includes.h"
#include "db2dhcp_types.h"
#include "net.h"
#include "dhcp.h"
#include "log.h"
#include "dhcp_queue.h"
#include "net_functions.h"
#include "misc_functions.h"

#include "dhcp_process.h"

extern int server_shutdown_flag;

static void * dummy_reader(void * args);
static int set_dhcp_filter(dhcp_device_t * dhcp_dev, const dhcp_proc_args_t * config);
static int make_dummy_socket(uint16_t port);
static dhcp_parsed_message_t * parse_dhcp_message(dhcp_device_t * dhcp_dev, const uint8_t * ether_packet);
static int get_dhcp_option(const dhcp_message_t *request, const uint16_t packet_len,
                        const int req_option, void * option_value, int value_size);

const uint8_t magic_cookie[] = {99, 130, 83, 99};

static const char DHCP_ARP_FILTER[] =
	"(udp and (src port %d or src port %d) "	/* Source port may be equal server port if DHCP relay is used */
	"and dst port %d)"							/* Set DHCP server port */
	" or (arp[6:2] == 0x02)";					/* Set ARP type 'ARP is-at'*/

static const time_t OFFER_CHECK_TIMEOUT = 800000;	/* usecs */


int run_dhcp_threads(dhcp_proc_thread_t **dhcp_threads, const server_configuration * config,
		request_handler_thread_t **db_clients)
{
	/* Make dummy socket for suppress ICMP-port unreacheble messagess on unicast DHCP messages */
	CHECK_VALUE(make_dummy_socket(config->dhcp_server_port), "Can't create dummy socket.", 0);

    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *dev_list_start = NULL;
	if(pcap_findalldevs(&dev_list_start, errbuf) == -1)
	{
		log_wr(CLOG, "Can't get execute interface listing: %s", errbuf);
		return FAIL;
	}

	int i;
	struct timespec sleep_time; 
	sleep_time.tv_sec = 0;
	sleep_time.tv_nsec = 200000;

	for(i = 0; i < config->if_count; ++i)
	{
		dhcp_threads[i] = (dhcp_proc_thread_t * ) malloc(sizeof(dhcp_proc_thread_t));
		CHECK_VALUE(dhcp_threads[i], "Can't allocate memory for DHCP process thread.", 0);

		dhcp_threads[i]->execution = dhcp_process;
		dhcp_threads[i]->dhcp_args.if_name = config->interfaces[i];
		dhcp_threads[i]->dhcp_args.if_index = i;
		dhcp_threads[i]->dhcp_args.dhcp_srv_port = config->dhcp_server_port;
		dhcp_threads[i]->dhcp_args.dhcp_cli_port = config->dhcp_client_port;
		dhcp_threads[i]->dhcp_args.ether_addr = config->ether_addresses[i];
		dhcp_threads[i]->dhcp_args.dhcp_queue = config->dhcp_queue;
		dhcp_threads[i]->dhcp_args.sql_threads_count = config->db_clients_count;
		dhcp_threads[i]->dhcp_args.listen_device = get_device(config->interfaces[i], i);

		dhcp_threads[i]->dhcp_args.primary_ipaddr = get_ip_by_ifname(dev_list_start, config->interfaces[i]);
		if(!dhcp_threads[i]->dhcp_args.primary_ipaddr)
			return FAIL;

		if(pthread_create(&dhcp_threads[i]->thread_id, NULL, dhcp_process, &dhcp_threads[i]->dhcp_args))
		{
			log_wr(ELOG, "Can't create thread for processing DHCP.");
			return FAIL;
		}

		/* Sleep 200 milliseconds to avoid very strange bug in FreeBSD - segfault is occured if 
		 * two (or more) threads set pcap filter (in dhcp_process() function) at the same time */
		nanosleep(&sleep_time, NULL);
	}

	pcap_freealldevs(dev_list_start);

	return 1;
}

void * dhcp_process(void * args)
{
	dhcp_proc_args_t * config = (dhcp_proc_args_t *) args;

	dhcp_device_t * dhcp_dev = config->listen_device;

	/* Fill some service fields */
	dhcp_dev->ether_addr = config->ether_addr;
	dhcp_dev->cli_port_htons = htons(config->dhcp_cli_port);
	dhcp_dev->srv_port_htons = htons(config->dhcp_srv_port);
	dhcp_dev->ipaddr = config->primary_ipaddr;

	etheraddr_bin_to_str(config->ether_addr, dhcp_dev->str_ether_addr);
	iptos(dhcp_dev->ipaddr, dhcp_dev->str_ipaddr);
	iptos(dhcp_dev->network, dhcp_dev->str_network);
	iptos(dhcp_dev->netmask, dhcp_dev->str_netmask);
	snprintf(dhcp_dev->str_ipaddr_int, sizeof(dhcp_dev->str_ipaddr_int), "%u", ntohl(dhcp_dev->ipaddr));
	snprintf(dhcp_dev->str_network_int, sizeof(dhcp_dev->str_network_int), "%u", ntohl(dhcp_dev->network));
	snprintf(dhcp_dev->str_netmask_int, sizeof(dhcp_dev->str_netmask_int), "%u", ntohl(dhcp_dev->netmask));
	snprintf(dhcp_dev->str_netmask_cidr, sizeof(dhcp_dev->str_netmask_cidr), "%d", to_cidr(dhcp_dev->netmask));
	snprintf(dhcp_dev->str_srv_port, sizeof(dhcp_dev->str_srv_port), "%hu", ntohs(dhcp_dev->srv_port_htons));
	snprintf(dhcp_dev->str_cli_port, sizeof(dhcp_dev->str_cli_port), "%hu", ntohs(dhcp_dev->cli_port_htons));

	log_wr(NLOG, "Starting DHCP listener thread on interface '%s', ether '%s'...",
			config->if_name, dhcp_dev->str_ether_addr);

	/* Set DHCP filter to device */
	int ret = set_dhcp_filter(dhcp_dev, config);
	if(ret)
		exit(ret);

	char str_ether[STR_ETHER_ALEN + 1];
	uint8_t ether_packet[DHCP_MTU_MAX];

	/* Start processing packets */
	log_wr(NLOG, "DHCP listener thread started. Waiting clients.");

	dhcp_parsed_message_t * client_request;
	dhcp_queue_node_t * server_resp;
	char str_ipaddr[3][IP4_MAXSTR_ALEN + 1];
	dhcp_message_t * dhcp_msg_ptr;
	dhcp_queue_t * q_p;
	while(1)
	{
		if( (server_resp = dhcp_queue_get(dhcp_dev->offers_queue, OFFER_CHECK_TIMEOUT, NO)) )
			q_p = dhcp_dev->offers_queue;
		else if( (server_resp = dhcp_queue_get(dhcp_dev->ack_queue, 0, NO)) )
			q_p = dhcp_dev->ack_queue;

		if(server_resp)
		{
			dhcp_msg_ptr = DHCP_DATA_FROM_FULL_PACKET(server_resp->dhcp_req->raw_dhcp_msg);
			if( send_packet(dhcp_dev,
					(uint8_t*)server_resp->dhcp_req->raw_dhcp_msg,
					server_resp->dhcp_req->length) )
			{
				uint32_t relay = dhcp_msg_ptr->gw_iaddr.s_addr;

				log_wr(NLOG, "Sending %s (%d) to %s/%s via %s%s%s%s",
						dhcp_str_type(server_resp->dhcp_req->message_type),
						server_resp->dhcp_req->message_type,
						etheraddr_bin_to_str(dhcp_msg_ptr->cli_hwaddr, str_ether),
						iptos(dhcp_msg_ptr->you_iaddr.s_addr, str_ipaddr[0]),
						iptos(dhcp_dev->ipaddr, str_ipaddr[1]),
						relay ? " (relay " : "",
						relay ? iptos(relay, str_ipaddr[2]) : "",
						relay ? ")" : ""
						);
			}
			else {	/* Fail to send DHCP packet. Nothin to do. */}

			dhcp_queue_remove(q_p, server_resp, YES);
			dhcp_queue_free_node(server_resp, q_p, YES);
		}

		/* Get packet from network */
		ret = get_packet(dhcp_dev, ether_packet);
		if(ret < 0)
		{
			log_wr(ELOG, "Can't read DHCP packet from ethernet device '%s'", config->if_name);
			continue;
		}

		if(server_shutdown_flag)
		{
			int sqln;
			for(sqln = 0; sqln < config->sql_threads_count; ++sqln)	/* Adding shutdown message for each */
				if(!dhcp_queue_add(config->dhcp_queue, SQL_THREADS_SHUTDOWN, NO))	/* SQL thread */
				{
					log_wr(CLOG, "Can't allocate memory for gracefull shutting down server: '%s'", strerror(errno));
					exit(error_memory);
				}
			/* Exit from thread now! */
			log_wr(DLOG, "DHCP thread finished.");
			return 0;
		}

		if(!ret)
			continue;	/* Timeout */

		ether_header_t * eth_p = (ether_header_t *)ether_packet;
		switch( ntohs(eth_p->ether_type) )
		{
		case ETHER_ARP_T:
		{
			arp_packet_t * arp_pack = (arp_packet_t*) ether_packet;
			log_wr(DLOG, "Got ARP as-it from %s/%s. Check offers queue.",
					iptos(arp_pack->data.from_ip, str_ipaddr[0]),
					etheraddr_bin_to_str(arp_pack->data.from_ether, str_ether));
			dhcp_queue_node_t * node = dhcp_queue_find_by_ip(dhcp_dev->offers_queue, arp_pack->data.from_ip);
			if(node)		/* Found in offers queue */
			{
				dhcp_message_t * offer_msg = DHCP_DATA_FROM_FULL_PACKET(node->dhcp_req->raw_dhcp_msg);
				if(memcmp(offer_msg->cli_hwaddr, arp_pack->data.from_ether, ETHER_ALEN))
				{ 
					char str_ether_alien[STR_ETHER_ALEN + 1];
					log_wr(ELOG, "IP address %s for client %s on %s already used in this network "
							"by other host (%s). Can't offer this address.",
							iptos(offer_msg->you_iaddr.s_addr, str_ipaddr[0]),
							etheraddr_bin_to_str(offer_msg->cli_hwaddr, str_ether),
							dhcp_dev->str_ipaddr,
							etheraddr_bin_to_str(arp_pack->data.from_ether, str_ether_alien)
					);
					dhcp_queue_remove(dhcp_dev->offers_queue, node, YES);
					dhcp_queue_free_node(node, NULL, NO);
				}
			}

			break;
		}
		case ETHER_IP4_T:
		{
			if(! ( client_request = parse_dhcp_message(dhcp_dev, ether_packet) ) )
				continue;
			
			uint32_t relay = client_request->raw_dhcp_msg->gw_iaddr.s_addr;
			log_wr(NLOG, "Got %s (%d) message from client %s on "
#ifndef	_WIN32	/* Don't print interface name in Windows - too long for screen size */
				"%s/"
#endif
					"%s%s%s%s",
					dhcp_str_type(client_request->message_type),
					client_request->message_type,
					etheraddr_bin_to_str(client_request->raw_dhcp_msg->cli_hwaddr, str_ether),
#ifndef	_WIN32	/* Don't print interface name in Windows - too long for screen size */
				dhcp_dev->str_name,
#endif
					dhcp_dev->str_ipaddr,
					relay ? " (relay " : "",
					relay ? iptos(relay, str_ipaddr[2]) : "",
					relay ? ")" : "");

			if(dhcp_queue_update_if_found(config->dhcp_queue, client_request))
			{
				log_wr(WLOG, "Found old request for %s on %s in DHCP queue. Updating old request.",
					etheraddr_bin_to_str(client_request->raw_dhcp_msg->cli_hwaddr, str_ether),
					client_request->dhcp_dev->str_ipaddr);
				continue;
			}
			else if(!dhcp_queue_add(config->dhcp_queue, client_request, YES))
			{
				free(client_request->raw_dhcp_msg);
				free(client_request);
			}

			break;
		}
		case ETHER_IP6_T:
			log_wr(DLOG, "Got IPv6 packet but IPv6 is not supported now.");
			break;
		default:
			log_wr(ELOG, "Got unknown Ethernet packet type: 0x%04x",
					ntohs(eth_p->ether_type));
			break;
		}

	}

	return 0;
}

static dhcp_parsed_message_t * parse_dhcp_message(dhcp_device_t * dhcp_dev, const uint8_t * ether_packet)
{
	ether_header_t * ether_hdr = (ether_header_t *) ether_packet;
	udp_header_t * udp_hdr = (udp_header_t *) (ether_packet + ETH_HEADER_LEN + IP_HEADER_LEN);
	dhcp_message_t * message = (dhcp_message_t*) (ether_packet + ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN);

	if(message->op != BOOTREQUEST)
		return FAIL;	/* Ignore all others messages */

	int message_len = ntohs(udp_hdr->len) - UDP_HEADER_LEN;

	uint8_t * msg_type_ptr = get_dhcp_option_ptr(message, message_len, DHCP_OPT_MESSAGE_TYPE, NULL);
	CHECK_VALUE(msg_type_ptr, "Invalid DHCP message - message type not found or invalid.", 0);

	uint8_t message_type = *msg_type_ptr;

	CHECK_VALUE(get_dhcp_option(message, message_len,
					DHCP_OPT_MESSAGE_TYPE, &message_type, sizeof(message_type)) > 0,
				"Invalid DHCP message - message type not found or invalid.", 0);

	switch(message_type)
	{
	case DHCPDISCOVER:
	case DHCPREQUEST:
	case DHCPRELEASE:
	case DHCPINFORM:
	case DHCPDECLINE:
		goto type_ok;
		break;
	default:
		log_wr(WLOG, "Invalid DHCP message type from client: %s (%d)",
				dhcp_str_type(message_type), message_type);
		return FAIL;
	}
type_ok: ;

	dhcp_parsed_message_t * out_message = calloc(1, sizeof(dhcp_parsed_message_t));
	if(!out_message)
	{
		log_wr(CLOG, "Can't allocate memory for queued DHCP message: %s", strerror(errno));
		exit(error_memory);
	}
	out_message->raw_dhcp_msg = malloc(message_len);
	if(!out_message->raw_dhcp_msg)
	{
		log_wr(CLOG, "Can't allocate memory for original DHCP message");
		exit(error_memory);
	}
	memcpy(out_message->raw_dhcp_msg, message, message_len);

	/* Check for max message size for client */
	if(get_dhcp_option(message, message_len, DHCP_OPT_MAX_MESSAGE_SIZE,
			&out_message->max_msg_size, sizeof(out_message->max_msg_size)) < 0)
		return FAIL;

	uint32_t server_id;
	if(get_dhcp_option(message, message_len, DHCP_OPT_SERVER_ID,
				&server_id, sizeof(server_id)) < 0)
		return FAIL;

	out_message->max_msg_size = ntohl(out_message->max_msg_size);

	/* Check for DHCP option 82 for save pointer to him if found */
	out_message->option82_ptr = get_dhcp_option_ptr(message, message_len, DHCP_OPT_AGENT_OPTIONS, NULL);
	out_message->option82_len = out_message->option82_ptr ? *(out_message->option82_ptr - 1) : 0;

	memcpy(out_message->from_ether, ether_hdr->ether_shost, ETHER_ALEN);
	out_message->length = message_len;
	out_message->message_type = message_type;
	out_message->dhcp_dev = dhcp_dev;

	return out_message;
}

static int make_dummy_socket(uint16_t port)
{
	static int dummy_socket;
    dummy_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(dummy_socket == -1)
    {
        perror("socket(): ");
        exit(-1);
    }

    struct sockaddr_in udp_sock;
    bzero(&udp_sock, sizeof(udp_sock));
    udp_sock.sin_family = AF_INET;
    udp_sock.sin_port = htons(port);
    udp_sock.sin_addr.s_addr = INADDR_ANY;

    if( bind(dummy_socket, (const struct sockaddr *) & udp_sock, sizeof(udp_sock)) )
    {
        log_wr(CLOG, "bind(): %s", strerror(errno));
        return FAIL;
    }

	pthread_t dummy_reader_thread;
    if(pthread_create(&dummy_reader_thread, NULL, dummy_reader, &dummy_socket))
	{
		log_wr(ELOG, "Can't create thread for reading from dummy socket.");
		return FAIL;
	}

    return OK;
}

static void * dummy_reader(void * args)
{
	log_wr(DLOG, "Dummy socket reader started.");
	uint8_t dummy_data[DHCP_MAX_LEN];
	int dummy_socket = * (int*)args;

	while(1)
	{
		if( recv(dummy_socket, dummy_data, sizeof(dummy_data), 0) == -1 && errno)
		{
			log_wr(ELOG, "Error reading from dummy socket: \"%s\". "
					"Sleepeng 2 seconds before next recv().", strerror(errno));
			sleep(2);
		}
	}

	return NULL;
}

static int set_dhcp_filter(dhcp_device_t * dhcp_dev, const dhcp_proc_args_t * config)
{
	char dhcp_filter[sizeof(DHCP_ARP_FILTER) + 3 * 5];
	bzero(dhcp_filter, sizeof(dhcp_filter));
    snprintf(dhcp_filter, sizeof(dhcp_filter), DHCP_ARP_FILTER,
    		config->dhcp_cli_port, config->dhcp_srv_port, config->dhcp_srv_port);
    struct bpf_program fp;

    if(pcap_compile(dhcp_dev->dev, &fp, dhcp_filter, 1, 0) == -1)
    {
        log_wr(CLOG, "pcap_compile error: %s\nFilter expression is: '%s'\n",
        		pcap_geterr(dhcp_dev->dev), dhcp_filter);
        pcap_close(dhcp_dev->dev);
        return error_pcap_compile;
    }

    if(pcap_setfilter(dhcp_dev->dev, &fp) == -1)
    {
        perror("pcap_setfilter");
        pcap_close(dhcp_dev->dev);
        return error_pcap_setfilter;
    }

    pcap_freecode(&fp);

    return 0;
}

uint8_t * get_dhcp_option_ptr(const dhcp_message_t *dhcp_msg, const uint16_t msg_len,
        const uint8_t req_option, uint16_t * option_len_ptr)
{
    /* Calculate start address for field "options" in DHCP packet */
    uint8_t *option = (uint8_t *)dhcp_msg + sizeof (dhcp_message_t) - DHCP_OPTION_LEN;
    /* End options equal end packet */
    const uint8_t * opt_end = (const uint8_t *)dhcp_msg + msg_len;
    /* Check "Magic cookie" in first 4 bytes options-field */
    if(memcmp(option, magic_cookie, sizeof(magic_cookie)))
        return NULL;

    option += sizeof(magic_cookie);
    int opt_len;

    while((option < opt_end) && (*option != DHCP_OPT_END))
    {
    	opt_len = *(option + 1);
        if((option + opt_len) > opt_end)
        {
            log_wr(WLOG, "WARNING! Invalid value in DHCP-option length. Attempting DoS?");
            return NULL;
        }

        if(*option == req_option)
        {
        	if(option_len_ptr)
        		*option_len_ptr = opt_len;
        	return option + 2;	/* Return pointer to option value */
        }
        else option += *(option + 1) + 2;
    }

    return NULL;
}

static int get_dhcp_option(const dhcp_message_t *dhcp_msg, const uint16_t msg_len,
                        const int req_option, void * option_value, int value_size)
{
    /* Calculate start address for field "options" in DHCP packet */
    uint8_t *option = (uint8_t *)dhcp_msg + sizeof (dhcp_message_t) - DHCP_OPTION_LEN;
    /* End options equal end packet */
    const uint8_t * opt_end = (const uint8_t *)dhcp_msg + msg_len;
    /* Check "Magic cookie" in first 4 bytes options-field */
    if(memcmp(option, magic_cookie, sizeof(magic_cookie)))
        return -1;
    option += sizeof(magic_cookie);
    int opt_len;

    while((option < opt_end) && (*option != DHCP_OPT_END))
    {
    	opt_len = *(option + 1);
        if((option + opt_len) > opt_end)
        {
            log_wr(WLOG, "WARNING! Invalid value in DHCP-option length. Attempting DoS?");
            return -1;
        }

        if(*option == req_option)
        {
            if(opt_len > value_size)
            {
            	log_wr(WLOG, "WARNING! Option's length is more than was expected "
							"(opcode: %d opt_len: %d > expected_len: %d). Attempting DoS?",
            			*option, opt_len, value_size);
            	return -1;
            }

            memcpy(option_value, option + 2, opt_len);
            return opt_len;
        }
        else option += *(option + 1) + 2;
    }
    return 0;
}

const char * dhcp_str_type(uint8_t type)
{
	static char * dhcp_types[] =
	{
		"",
		"DHCPDISCOVER",
		"DHCPOFFER",
		"DHCPREQUEST",
		"DHCPDECLINE",
		"DHCPACK",
		"DHCPNAK",
		"DHCPRELEASE",
		"DHCPINFORM",
		"DHCPHISTORY"
	};

	if(!type || (type > sizeof(dhcp_types)/sizeof(dhcp_types[0])))
		return "UNKNOWN";

	return dhcp_types[type];
}


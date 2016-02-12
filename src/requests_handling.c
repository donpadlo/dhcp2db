/*
 * requests_handling.c
 *
 *  Created at: 17.09.2009
 *      Author: Chebotarev Roman
 */

#include "common_includes.h"
#include "db2dhcp_types.h"
#include "dhcp_queue.h"
#include "misc_functions.h"
#include "net_functions.h"
#include "log.h"
#include "dhcp_process.h"
#include "requests_handling.h"
#include "dhcp_cache.h"

#define UNLESS_FAIL(cond, err_msg) \
	if(!(cond))															\
	{																	\
		log_wr(ELOG, "Invalid DHCP response generated: %s. "			\
			"Check you query and database.", err_msg);					\
		return FAIL;													\
	}

extern int server_shutdown_flag;

static void * requests_handler_thread(void * args);

/* Pointer to connect for suitable connect handler (MySQL, PostgreSQL, etc...) */
static void * (*connect_to_db)(const char * host, const char * user,
		const char * passwd,	const char * db_name, uint16_t port);
static void * (*exec_query)(void * dbh, const char *sql_st, int st_len);
static void (*disconnect_from_db)(void * dbh);

static dhcp_query_templ_t * dupe_query_template(dhcp_query_templ_t * templ_orig);
static query_result_t * process_client_message_hist(void * dbh,dhcp_parsed_message_t * dhcp_req,const handler_args_t * config);
static query_result_t * process_client_message(void * dbh,
		dhcp_parsed_message_t * dhcp_req, const handler_args_t * config);
static int parse_option_variable(query_var_t * var, dhcp_parsed_message_t * dhcp_req);
static uint8_t * get_cond_var_value(query_var_t * var, dhcp_parsed_message_t * dhcp_req, uint16_t * value_len);
static uint8_t * get_var_value(query_var_t * var, dhcp_parsed_message_t * dhcp_req, uint16_t * value_len);
static int make_dhcp_response(dhcp_parsed_message_t * client_message, query_result_t * query_data,
		dhcp_full_packet_t * dhcp_packet, packet_flags_t * flags);
static uint8_t * set_dhcpnak(dhcp_message_t * msg, uint32_t server_id);

static int item_uint1_to_bin(char * value_pt, int value_size, uint8_t * dst, int max_size);
static int item_uint4_to_bin(char * value_pt, int value_size, uint8_t * dst, int max_size);
static int item_hex_to_bin(char * value_pt, int value_size, uint8_t * dst, int max_size);
static int item_string_to_bin(char * value_pt, int value_size, uint8_t * dst, int max_size);
static int item_ipaddrs_to_binary(char * value, int value_size, uint8_t * dst, int max_size);
static int item_binary_to_binary(char * value_pt, int value_size, uint8_t * dst, int max_size);

typedef int (*item_data_handler)(char * , int, uint8_t * , int );
static const item_data_handler item_data_handlers[] =
{
		NULL,
		item_uint1_to_bin,
		item_uint4_to_bin,
		item_hex_to_bin,
		item_string_to_bin,
		item_ipaddrs_to_binary,
		item_binary_to_binary
};

extern const uint8_t magic_cookie[4];

#define DHCP_FIELD_SIZE(field) \
	sizeof(((dhcp_message_t*)0)->field)
#define FIELD_DESCR(descr, field) \
	{descr, CALC_OFFSET(dhcp_message_t, field), DHCP_FIELD_SIZE(field)}

dhcp_hfield_descr_t header_fields[] =
{
	{"", 0, 0},
	FIELD_DESCR("BOOTP operator", op),
	FIELD_DESCR("Hardware type", hw_type),
	FIELD_DESCR("Hardware address length", hwaddr_len),
	FIELD_DESCR("Hops count", hops),
	FIELD_DESCR("XID", xid),
	FIELD_DESCR("Seconds since client started looking", secs),
	FIELD_DESCR("Flags", flags),
	FIELD_DESCR("Client IP address", cli_iaddr),
	FIELD_DESCR("You IP address", you_iaddr),
	FIELD_DESCR("Server IP address", srv_iaddr),
	FIELD_DESCR("Gateway IP address", gw_iaddr),
	FIELD_DESCR("Client hardware address", cli_hwaddr),
	FIELD_DESCR("Server name", srv_name),
	FIELD_DESCR("Boot file name", boot_file),
	FIELD_DESCR("Options", options)
};

/* TODO 00 Нужно уметь обрабатывать как минимум эти ситуации:
 *
 * Серверы получают широковещательное сообщение DHCPREQUEST от клиента. Серверы, не выбранные сообщением
 * DHCPREQUEST, используют сообщение как уведомления о том, что клиент отверг предложение сервера.
 *
 * Кроме того, было бы неплохо потом доработать следующее:
 *
 * Клиент должен включить опцию 'maximum DHCP message size', чтобы позволить серверу знать,
 * максимальный размер его DHCP-сообщений. Параметры, присланные в ответ клиенту,
 * могут иметь размер больший, чем выделено для опций в сообщении DHCP.
 * В этом случае, два дополнительных опционных флага (которые должны присутствовать в поле 'опции'
 * сообщения) индицируют, что для опций должны использоваться поля 'file' и 'sname'.
 *
 * В сам сервер необходимо:
 * 1. Добавить глобальный счётчик ошибок и выдачу статистики.
 * 2. Попробовать сделать аллокатор памяти на манер nginx'а - не факт что надо. Главное проверить
 * 		что бы не тёк.
 * 3. Обработать ситуации сопровождаемые CLOG'ом - скорее всего нужно завершать сервер.
 * 4. Защита от перегрузок - счётчики запросов на отдельного клиента,
 * 		интерфейс в целом и суммарно на весь сервер.
 * */

/* Database initializing */
int run_requests_handlers(request_handler_thread_t **handler_threads, const server_configuration * config)
{
	int i;
	log_wr(NLOG, "Starting request handler threads (using DBM %s) ...", config->dbm->name);

	connect_to_db = config->dbm->connect_to_db;
	exec_query = config->dbm->query;
	disconnect_from_db = config->dbm->disconnect;

	for(i = 0; i < config->db_clients_count; ++i)
	{
		handler_threads[i] = (request_handler_thread_t *) malloc(sizeof(request_handler_thread_t));
		CHECK_VALUE(handler_threads[i], "Can't allocate memory for child thread.", 0);

		handler_threads[i]->args.host = config->db_server_address;
		handler_threads[i]->args.user = config->db_user_name;
		handler_threads[i]->args.passwd = config->db_user_password;
		handler_threads[i]->args.db_name = config->db_name;
		handler_threads[i]->args.port = config->db_server_port;

		handler_threads[i]->args.dhcp_queue = config->dhcp_queue;
		handler_threads[i]->args.cache_used = config->cache_ttl ? 1 : 0;

		handler_threads[i]->args.discover_template_q = config->discover_template;
		handler_threads[i]->args.history_template_q = config->history_template;
		handler_threads[i]->args.request_template_q = config->request_template;
		handler_threads[i]->args.release_template_q = config->release_template;

		log_wr(DLOG, "Starting requests handler thread #%d", i + 1);
		if(pthread_create(&handler_threads[i]->thread_id, NULL,
				requests_handler_thread, &handler_threads[i]->args))
		{
			log_wr(ELOG, "Can't create requests handler thread.");
			return FAIL;
		}

		if(i < config->db_clients_count)
		{
			log_wr(DLOG, "Sleep 1 second before next connection to database.");
			sleep(1);
		}
	}

	log_wr(NLOG, "All (%d) request handlers started.", config->db_clients_count);

	return 1;
}

static uint8_t * set_dhcpnak(dhcp_message_t * msg, uint32_t server_id)
{
	uint8_t * opt_pt = msg->options + sizeof(magic_cookie);
	opt_pt[OPT_CODE] = DHCP_OPT_MESSAGE_TYPE;
	opt_pt[OPT_LEN] = 1;
	opt_pt[OPT_VALUE] = DHCPNAK;

	opt_pt += 3;
	opt_pt[OPT_CODE] = DHCP_OPT_SERVER_ID;
	opt_pt[OPT_LEN] = sizeof(server_id);
	memcpy(&opt_pt[OPT_VALUE], &server_id, sizeof(server_id));

	msg->you_iaddr.s_addr = 0;
	msg->cli_iaddr.s_addr = 0;
	msg->srv_iaddr.s_addr = server_id;


	return (opt_pt + 2 /* type and size */ + sizeof(server_id));
}

static int item_uint1_to_bin(char * value_pt, int value_size, uint8_t * dst, int max_size)
{
	uint32_t val;
	if(value_pt[0] && value_pt[1] &&						/* strlen of value >= 2 */
			!strncmp(value_pt, "0x", strlen("0x")))	/* Hex digit prefix found */
	{
		if(sscanf(value_pt + strlen("0x"), "%x", &val) != 1)
		{
			log_wr(ELOG, "Invalid value \"%s\" for UINT1 type.", value_pt);
			return FAIL;
		}
	}
	else if(sscanf(value_pt, "%u", &val) != 1)
	{
		log_wr(ELOG, "Invalid value \"%s\" for UINT1 type.", value_pt);
		return FAIL;
	}

	if(val > (uint8_t)~0)
	{
		log_wr(ELOG, "Too big value \"%s\" (converted to %u) for UINT1 type.", value_pt, val);
		return FAIL;
	}

	if(max_size < sizeof(uint8_t))
	{
		log_wr(ELOG, "To small destination for UINT1 type. Destination size: %d, need: %d",
				max_size, sizeof(uint8_t));
		return FAIL;
	}

	*dst = (uint8_t) val;

	return sizeof(uint8_t);
}

static int item_uint4_to_bin(char * value_pt, int value_size, uint8_t * dst, int max_size)
{
	uint32_t val;
	if(value_pt[0] && value_pt[1] &&						/* strlen of value >= 2 */
			!strncmp(value_pt, "0x", strlen("0x")))	/* Hex digit prefix found */
	{
		if(sscanf(value_pt + strlen("0x"), "%x", &val) != 1)
		{
			log_wr(ELOG, "Invalid value \"%s\" for UINT4 type.", value_pt);
			return FAIL;
		}
	}
	else if(sscanf(value_pt, "%u", &val) != 1)
	{
		log_wr(ELOG, "Invalid value \"%s\" for UINT4 type.", value_pt);
		return FAIL;
	}

	if(max_size < sizeof(uint32_t))
	{
		log_wr(ELOG, "To small destination for UINT4 type. Destination size: %d, need: %d",
				max_size, sizeof(uint32_t));
		return FAIL;
	}

	*((uint32_t *)dst) = htonl(val);

	return sizeof(uint32_t);
}

static int item_hex_to_bin(char * value_pt, int value_size, uint8_t * dst, int max_size)
{
	if(value_pt[0] && value_pt[1] &&						/* strlen of value >= 2 */
			!strncmp(value_pt, "0x", strlen("0x")))	/* Hex digit prefix found */
		value_pt += 2;

	int hex_len = strlen(value_pt);
	if(!hex_len)
	{
		log_wr(ELOG, "Empty value for HEX type.");
		return FAIL;
	}

	if(hex_len % 2)
	{
		log_wr(ELOG, "Odd number of chars in hex value: \"%value\".", value_pt);
		return FAIL;
	}

	hex_len /= 2;
	if(hex_len > max_size)
	{
		log_wr(ELOG, "Destination too small for hex value: \"%s\". Destination size: %d, need: %d",
				value_pt, max_size, hex_len);
		return FAIL;
	}

	str_to_hex(hex_len, value_pt, dst);

	return hex_len;

}

static int item_string_to_bin(char * value_pt, int value_size, uint8_t * dst, int max_size)
{
	int val_len = strlen(value_pt);

	if(val_len > max_size)
	{
		log_wr(ELOG, "Destination too small for string value: \"%s\". Destination size: %d, need: %d",
				value_pt, max_size, val_len);
		return FAIL;
	}

	memcpy(dst, value_pt, val_len);

	return val_len;
}

static int item_ipaddrs_to_binary(char * value, int value_size, uint8_t * dst, int max_size)
{
	char * value_pt = value;
	char *pt = strchr(value_pt, ',');
	int remain = max_size;
	struct in_addr addr;
	uint8_t * dst_pt = dst;

	do
	{
		if(pt)
			*pt = '\0';

		if(!inet_aton(value_pt, &addr))
		{
			if(pt)
				*pt = ',';
			log_wr(ELOG, "Invalid IP address value for IPADDRS type: \"%s\", value: \"%s\"",
					value_pt, value);
			return FAIL;
		}

		if(sizeof(addr.s_addr) > remain)
		{
			if(pt)
				*pt = ',';
			log_wr(ELOG, "Destination too small for IPADDRS value(s): \"%s\". Destination size: %d, need: %d",
					value, max_size, sizeof(addr.s_addr));
			return FAIL;
		}

		remain -= sizeof(addr.s_addr);

		*((typeof(addr.s_addr)*)dst_pt) = addr.s_addr;

		dst_pt += sizeof(addr.s_addr);

		if(!pt)
			break;

		*pt = ',';
		value_pt = pt + 1;
		pt = strchr(value_pt, ',');
	}
	while(*value_pt);

	return dst_pt - dst;
}

static int item_binary_to_binary(char * value_pt, int value_size, uint8_t * dst, int max_size)
{
	if(value_size > max_size)
	{
		log_wr(ELOG, "Destination too small for BINARY data value. Destination size: %d, value size: %d, need: %d",
				max_size, value_size, value_size);
		return FAIL;
	}

	memcpy(dst, value_pt, value_size);

	return value_size;
}

static int make_dhcp_response(dhcp_parsed_message_t * client_message, query_result_t * query_data,
		dhcp_full_packet_t * dhcp_packet, packet_flags_t * flags)
{
	uint8_t msg_type_ptr = 0;
	*flags = 0;
	bzero(dhcp_packet, sizeof(*dhcp_packet));

	int lease_time_set = 0;
	uint32_t server_id = 0;

	int packet_data_len = sizeof(dhcp_packet->dhcp_data) -
		sizeof(dhcp_packet->dhcp_data.options);	/* DHCP header without options length */

	int i, code, type, ret;
	uint8_t * opt_pt = dhcp_packet->dhcp_data.options;
	int opt_size_remain;
	char str_ether[STR_ETHER_ALEN + 1];
	char str_ipaddr[IP4_MAXSTR_ALEN + 1];

	if(client_message->max_msg_size)
		opt_size_remain = client_message->max_msg_size - /* Options size remain == difference between max size and */
			( (uint8_t*)((dhcp_message_t*)NULL)->options -	/* size all fields of DHCP header without */
			(uint8_t*)((dhcp_message_t*)NULL) ); 	/* size 'options' field */
	else
		opt_size_remain = sizeof(dhcp_packet->dhcp_data.options);

	opt_size_remain -= sizeof(magic_cookie) +	/* and without sizeof 'magic cookie' */
		3 +	/* 3 - sizeof DHCP message type option */
		1	/* 1 - sizeof DHCP options trailer */; 

	if(opt_size_remain <= 0)
	{
		log_wr(ELOG, "Client set too small maximum DHCP message size: %d. "
				"Can't generate packet for him.", client_message->max_msg_size);
		return FAIL;
	}

	memcpy(opt_pt, magic_cookie, sizeof(magic_cookie));
	opt_pt += sizeof(magic_cookie) +
		3 /* 3 - sizeof DHCP message type option */;
	
	uint8_t * start_options = dhcp_packet->dhcp_data.options + sizeof(magic_cookie);

	for(i = 0; i < query_data->count; ++i)
	{
		type = query_data->items[i].type;
		if(type < 1 ||
			(type > sizeof(item_data_handlers) / sizeof(item_data_handlers[0]) - 1)
			)
		{
			log_wr(ELOG, "Invalid data type in item: %d", type);
			continue;
		}

		code = query_data->items[i].code;

		if(code > START_HEADER_CODES &&
						code < END_HEADER_CODES)
		{	/* Found value for DHCP packet header */
			if(!item_data_handlers[type](
						query_data->items[i].data,
						query_data->items[i].len,
						((uint8_t*) &dhcp_packet->dhcp_data) +
							header_fields[code - START_HEADER_CODES].offset,
						header_fields[code - START_HEADER_CODES].maxlen)
					)
			{
				log_wr(ELOG, "Can't fill header field \"%s\".",
						header_fields[code - START_HEADER_CODES].description);
				bzero(((uint8_t*) &dhcp_packet->dhcp_data) +
							header_fields[code - START_HEADER_CODES].offset,
						header_fields[code - START_HEADER_CODES].maxlen);
			}
		}
		else if(code > START_OPTION_CODES &&
			code < END_OPTION_CODES)
		{	/* Found value for 'options' field */
			if(opt_size_remain < 3)	/* 3 = 1 (option code) + 1 (option len) + 1 (minimal value size) */
			{
				log_wr(ELOG, "DHCP options field overflow.");
				continue;
			}

			opt_pt[OPT_CODE] = query_data->items[i].code - START_OPTION_CODES;

			opt_size_remain -= 2;	/* 2 - code and length */

			if( !(ret = item_data_handlers[type](query_data->items[i].data, query_data->items[i].len,
					&opt_pt[OPT_VALUE], opt_size_remain)))
			{
				log_wr(ELOG, "Can't add DHCP option with code %d", query_data->items[i].code);
				return FAIL;
			}
			else
			{

				if(opt_pt[OPT_CODE] == DHCP_OPT_MESSAGE_TYPE)
				{
					/* Return bytes for opt_size_remain because place for this option 
					 * reserved in start of option field */
					opt_size_remain += 2;

					msg_type_ptr = opt_pt[OPT_VALUE];
					uint8_t * msg_type = start_options;
					msg_type[OPT_CODE] = opt_pt[OPT_CODE];
					msg_type[OPT_LEN] = 1;
					msg_type[OPT_VALUE] = opt_pt[OPT_VALUE];

					opt_pt[OPT_CODE] = 0;	/* Zeroing option code on end of options */ 
					opt_pt[OPT_LEN] = 0;	/* Zeroing option length on end of options */ 
					opt_pt[OPT_CODE] = 0;	/* Zeroing option value on end of options */ 

					--opt_pt;				/* Return last option pointer to prevous value */
				}
				else
				{
					switch(opt_pt[OPT_CODE])
					{
					case DHCP_OPT_LEASE_TIME:
						if(ret != sizeof(uint32_t))
						{
							log_wr(ELOG, "Invalid length of option 'Lease time': %d", opt_pt[OPT_LEN]);
							return FAIL;
						}
						lease_time_set = 1;
						break;
					case DHCP_OPT_SERVER_ID:
						if(ret != sizeof(server_id))
						{
							log_wr(ELOG, "Invalid length of option 'Server ID': %d", opt_pt[OPT_LEN]);
							return FAIL;
						}
						memcpy(&server_id, &opt_pt[OPT_VALUE], sizeof(server_id));
						break;
					}
					opt_pt[OPT_LEN] = ret;
					opt_size_remain -= ret;	/* 2 - 1 (option code) + 1 (option len) */
					opt_pt += 2 + ret;
				}
			}
		}
		else if(code > START_INTERNAL_CODES &&
				code < END_INTERNAL_CODES)
		{
			switch(code)
			{
			case INTERNAL_DNTCACHE:
				if(query_data->items[i].len)
					*flags |= PFLAG_DNT_CACHE;
				break;
			default:
				log_wr(ELOG, "Invalid internal attribute code in query result: %u.", code);
			break;
			}
		}
		else
			log_wr(ELOG, "Invalid value code in query result.");
	}

	/* Check for minimal set of needed values */
	if(!dhcp_packet->dhcp_data.you_iaddr.s_addr)
	{
		if(client_message->message_type == DHCPINFORM)
		{
			log_wr(NLOG, "Succefull send DHCPINFORM data do DB from client %s from subnet %s/%s",
					etheraddr_bin_to_str(client_message->raw_dhcp_msg->cli_hwaddr, str_ether),
					client_message->dhcp_dev->str_network, client_message->dhcp_dev->str_netmask_cidr);
			return 0;
		}

		uint32_t relay = client_message->raw_dhcp_msg->gw_iaddr.s_addr;
		log_wr(WLOG, "Can't obtain IP address from DB for client %s on interface %s%s%s%s.",
					etheraddr_bin_to_str(client_message->raw_dhcp_msg->cli_hwaddr, str_ether),
					client_message->dhcp_dev->str_ipaddr, 
					relay ? " (relay: " : "",
					relay ? iptos(relay, str_ipaddr) : "",
					relay ? ")" : "");

		return FAIL;
	}

	if(!lease_time_set)
		log_wr(WLOG, "Option 'DHCP lease time' is not set, may be problems with ISC DHCP client (dhclient)!");

	if(!server_id)
	{
		log_wr(DLOG, "Option 'DHCP server ID' is not set. Set server ID = %s (interface IP address).",
				client_message->dhcp_dev->str_ipaddr);
		if(opt_size_remain < 1 + 1 + sizeof(server_id))	/* 1 - (opt code) + 1 (opt len) + sizeof(server_id)*/
		{
			log_wr(ELOG, "DHCP option field overflow. Can't add 'Server ID' option.");
			return FAIL;
		}
		server_id = client_message->dhcp_dev->ipaddr;
		opt_pt[OPT_CODE] = DHCP_OPT_SERVER_ID;
		opt_pt[OPT_LEN] = sizeof(server_id);
		memcpy(&opt_pt[OPT_VALUE], &server_id, sizeof(server_id));
		opt_pt += 2 + opt_pt[OPT_LEN];
	}

	if(!msg_type_ptr)	/* DHCP message type not found in data from DB */
	{
		uint8_t * msg_type = start_options;

		switch(client_message->message_type)
		{
		case DHCPDISCOVER:
			msg_type[OPT_CODE] = DHCP_OPT_MESSAGE_TYPE;
			msg_type[OPT_LEN] = 1;
			msg_type[OPT_VALUE] = DHCPOFFER;
			break;
		case DHCPREQUEST:
		{
			uint32_t * requested_ip;
			uint16_t opt_len;
			uint32_t offered_ip = dhcp_packet->dhcp_data.you_iaddr.s_addr;

			if( ! (requested_ip = (uint32_t *)get_dhcp_option_ptr(client_message->raw_dhcp_msg,
					client_message->length,	DHCP_OPT_REQUESTED_ADDRESS, &opt_len))
				&& !client_message->raw_dhcp_msg->cli_iaddr.s_addr)
			{
				log_wr(ELOG, "Can't extract value of \"Requested IP address\" or \"Client IP address\" from message.");
				return FAIL;
			}

			if(!requested_ip)
				requested_ip = (uint32_t*)&client_message->raw_dhcp_msg->cli_iaddr.s_addr;
			else if(sizeof(*requested_ip) != opt_len)
			{
				log_wr(ELOG, "Invalid requested IP address value length: %d, but need: %d",
						opt_len, sizeof(*requested_ip));
				return FAIL;
			}


			if( client_message->raw_dhcp_msg->cli_iaddr.s_addr &&
				(client_message->raw_dhcp_msg->cli_iaddr.s_addr & client_message->dhcp_dev->netmask) !=
				(offered_ip & client_message->dhcp_dev->netmask)
				)
			{
				log_wr(ILOG, "Ignore DHCPREQUEST because client %s required IP address for other subnet.",
					etheraddr_bin_to_str(client_message->raw_dhcp_msg->cli_hwaddr, str_ether));
					return FAIL;
			}

			if(*requested_ip != offered_ip)
				opt_pt = set_dhcpnak(&dhcp_packet->dhcp_data, server_id);
			else
			{
				msg_type[OPT_CODE] = DHCP_OPT_MESSAGE_TYPE;
				msg_type[OPT_LEN] = 1;
				msg_type[OPT_VALUE] = DHCPACK;
			}

			break;
		}
		default:
			log_wr(ELOG, "Can't set message type for client type %s", dhcp_str_type(client_message->message_type));
			return FAIL;
		}
	}

	/* Filling some other fields */

	/* BOOTP reply type */
	dhcp_packet->dhcp_data.op = BOOTREPLY;
	if(client_message->raw_dhcp_msg->hwaddr_len > sizeof(dhcp_packet->dhcp_data.cli_hwaddr))
	{
		log_wr(ELOG, "Too long client hardware address in message: %d, maximum size if: %d",
			client_message->raw_dhcp_msg->hwaddr_len, sizeof(dhcp_packet->dhcp_data.cli_hwaddr));
		return FAIL;
	}
			
	/* Set hw address */
	if(!dhcp_packet->dhcp_data.hw_type)
		dhcp_packet->dhcp_data.hw_type = ETHER_HW_TYPE;
	dhcp_packet->dhcp_data.hwaddr_len = ETHER_ALEN;
	memcpy(dhcp_packet->dhcp_data.cli_hwaddr, client_message->raw_dhcp_msg->cli_hwaddr,
			client_message->raw_dhcp_msg->hwaddr_len);
	
	/* Echoing option-82 from client message if exist */
	if(client_message->option82_ptr)
	{
		if(opt_size_remain < 2 /* Option code & option size */ + client_message->option82_len)
		{
			log_wr(ELOG, "DHCP option field overflow. Can't add 'Relay Agent' (82) option.");
			return FAIL;
		}

		opt_pt[OPT_CODE] = DHCP_OPT_AGENT_OPTIONS;
		opt_pt[OPT_LEN] = client_message->option82_len;
		memcpy(&opt_pt[OPT_VALUE], client_message->option82_ptr, client_message->option82_len);

		opt_pt += 2 + client_message->option82_len;
		opt_size_remain -= 2 + client_message->option82_len;		
	}

	/* Set xid from client message */
	dhcp_packet->dhcp_data.xid = client_message->raw_dhcp_msg->xid;

	/* Set broadcast flag if client requested broadcast response from server */
	dhcp_packet->dhcp_data.flags |= client_message->raw_dhcp_msg->flags & BOOTP_BROADCAST;

	/* Set end of DHCP options*/
	*opt_pt = DHCP_OPT_END;
	++opt_pt;
	packet_data_len += opt_pt - dhcp_packet->dhcp_data.options;

	if(client_message->raw_dhcp_msg->gw_iaddr.s_addr)
	{
		if(!dhcp_packet->dhcp_data.gw_iaddr.s_addr)
			dhcp_packet->dhcp_data.gw_iaddr.s_addr = client_message->raw_dhcp_msg->gw_iaddr.s_addr;
	}

	/* Assemble network headers for packet */
	assemble_net_header_dhcp(dhcp_packet, packet_data_len,
			client_message->dhcp_dev->ether_addr,
			client_message->dhcp_dev->ipaddr,
			client_message->dhcp_dev->srv_port_htons, 
			client_message->raw_dhcp_msg->gw_iaddr.s_addr ? /* Set Ethernet destination to DHCP relay */
				client_message->from_ether : NULL,			/* if relay is used */
			client_message->dhcp_dev->cli_port_htons,
			msg_type_ptr
			);

	return packet_data_len;
}

static dhcp_query_templ_t * dupe_query_template(dhcp_query_templ_t * templ_orig)
{
	dhcp_query_templ_t * templ = calloc(1, sizeof(dhcp_query_templ_t));
	if(!templ)
	{
		log_wr(CLOG, "Can't allocate memory for template query.");
		return NULL;
	}
	*templ = *templ_orig;

	templ->vars = calloc(templ->vars_size, sizeof(templ->vars[0]));
	if(!templ->vars)
	{
		log_wr(CLOG, "Can't allocate memory for query variables.");
		return NULL;
	}

	query_var_t * var;
	int i;
	for(i = 0; i < templ->vars_count; ++i)
	{
		var = calloc(1, sizeof(query_var_t));
		if(!var)
		{
			log_wr(CLOG, "Can't allocate memor for local copy of variable.");
			return NULL;
		}
		*var = *(templ_orig->vars[i]);
		templ->vars[i] = var;
	}

	return templ;
}
static query_result_t * process_client_message_hist(void * dbh,dhcp_parsed_message_t * dhcp_req,const handler_args_t * config){
    dhcp_query_templ_t * query_template;    
    query_template = config->history_template_q;
    log_wr(ILOG, "-send data to table history..");    
	int i, var_len;
	query_var_t * var;
	char * var_str_type;
	int q_len = query_template->total_slices_length;
	log_wr(DLOG, "Parsing DHCP message and preparing SQL statement.");
	for(i = 0; i < query_template->slices_count; ++i)
	{
		if(i < query_template->vars_count )
		{
			var = query_template->vars[i];
			switch(var->type)
			{
			case var_server:
				var_str_type = "internal server";
				q_len += strlen(var->string_value);
				break;
			case var_device:
				var->string_value = (char*) ( ((uint8_t*)dhcp_req->dhcp_dev) + var->offset);
				q_len += strlen(var->string_value);
				var_str_type = "network device";
				break;
			case var_config_header:
				hex_to_str(var->length, (uint8_t*)(dhcp_req->raw_dhcp_msg) + var->offset, var->string_value);
				q_len += var->length * 2;
				var_str_type = "DHCP header";
				break;
			case var_config_options:
				var_len = parse_option_variable(var, dhcp_req);
				/*if (!var_len)
					return NULL;*/
				q_len += var_len;
				var_str_type = "DHCP options";
				break;
			default:
				log_wr(ELOG, "Unknown variable type: %d", var->type);
				continue;
			break;
			}
			log_wr(DLOG, "Found %s variable: %s = \"%s\"", var_str_type, var->name, var->string_value);
		}
	}

	/* If no cached query */
	if(!query_template->cached_query)
	{
		query_template->cached_query = malloc(q_len + 1);
		if(!query_template->cached_query)
		{
			log_wr(CLOG, "Can't allocate memory for preparing SQL statement. Statement length: %d.", q_len + 1);
			return NULL;
		}
	}
	/* If not enough memory for new query */
	else if(query_template->cached_query_size <= q_len)
	{
		query_template->cached_query = realloc(query_template->cached_query, q_len + 1);
		if(!query_template->cached_query)
		{
			log_wr(CLOG, "Can't reallocate memory for preparing SQL statement. Statement length: %d.", q_len + 1);
			return NULL;
		}
	}

	if(query_template->cached_query_size)
		log_wr(DLOG, "Prevous SQL statement: \"%s\"", query_template->cached_query);
	query_template->cached_query_size = q_len + 1;
	query_template->cached_query[0] = '\0';

	for(i = 0; i < query_template->slices_count; ++i)
	{
		strncat(query_template->cached_query, query_template->slices[i],
				query_template->cached_query_size - strlen(query_template->cached_query) - 1);
		if(i < query_template->vars_count )
		{
			strncat(query_template->cached_query, query_template->vars[i]->string_value,
					query_template->cached_query_size - strlen(query_template->cached_query) - 1);
		}
	}

	log_wr(DLOG, "Executing SQL statement \"%s\"", query_template->cached_query);

	return exec_query(dbh, query_template->cached_query,
			query_template->cached_query_size - 1);	/* -1 - for truncate '\0' symbol */
    
    return NULL;
};
static query_result_t * process_client_message(void * dbh, dhcp_parsed_message_t * dhcp_req,
		const handler_args_t * config)
{
	/* Processing DHCP message */
	dhcp_query_templ_t * query_template;

	switch(dhcp_req->message_type)
	{
	case DHCPREQUEST:	/* DHCPREQUEST more often than DHCPOFFER, because he first */
		query_template = config->request_template_q;
		break;
	case DHCPDISCOVER:
		query_template = config->discover_template_q;
		log_wr(ILOG, "-send req WHO IS mister PUTIN..");
		break;
	case DHCPHISTORY:
		query_template = config->history_template_q;
		log_wr(ILOG, "-send data to table history..");
		break;		
	case DHCPRELEASE:
		if(config->release_template_q)	/* If not set - ignore DHCPRELEASE */
		{
			query_template = config->release_template_q;
			break;
		}
		log_wr(NLOG, "DHCPRELEASE query is omitted. Ignore this message.");
		return NULL;
	default:
		log_wr(NLOG, "Ignore this message.");
		return NULL;
	}

	int i, var_len;
	query_var_t * var;
	char * var_str_type;
	int q_len = query_template->total_slices_length;
	log_wr(DLOG, "Parsing DHCP message and preparing SQL statement.");
	for(i = 0; i < query_template->slices_count; ++i)
	{
		if(i < query_template->vars_count )
		{
			var = query_template->vars[i];
			switch(var->type)
			{
			case var_server:
				var_str_type = "internal server";
				q_len += strlen(var->string_value);
				break;
			case var_device:
				var->string_value = (char*) ( ((uint8_t*)dhcp_req->dhcp_dev) + var->offset);
				q_len += strlen(var->string_value);
				var_str_type = "network device";
				break;
			case var_config_header:
				hex_to_str(var->length, (uint8_t*)(dhcp_req->raw_dhcp_msg) + var->offset, var->string_value);
				q_len += var->length * 2;
				var_str_type = "DHCP header";
				break;
			case var_config_options:
				var_len = parse_option_variable(var, dhcp_req);
				/*if (!var_len)
					return NULL;*/
				q_len += var_len;
				var_str_type = "DHCP options";
				break;
			default:
				log_wr(ELOG, "Unknown variable type: %d", var->type);
				continue;
			break;
			}
			log_wr(DLOG, "Found %s variable: %s = \"%s\"", var_str_type, var->name, var->string_value);
		}
	}

	/* If no cached query */
	if(!query_template->cached_query)
	{
		query_template->cached_query = malloc(q_len + 1);
		if(!query_template->cached_query)
		{
			log_wr(CLOG, "Can't allocate memory for preparing SQL statement. Statement length: %d.", q_len + 1);
			return NULL;
		}
	}
	/* If not enough memory for new query */
	else if(query_template->cached_query_size <= q_len)
	{
		query_template->cached_query = realloc(query_template->cached_query, q_len + 1);
		if(!query_template->cached_query)
		{
			log_wr(CLOG, "Can't reallocate memory for preparing SQL statement. Statement length: %d.", q_len + 1);
			return NULL;
		}
	}

	if(query_template->cached_query_size)
		log_wr(DLOG, "Prevous SQL statement: \"%s\"", query_template->cached_query);
	query_template->cached_query_size = q_len + 1;
	query_template->cached_query[0] = '\0';

	for(i = 0; i < query_template->slices_count; ++i)
	{
		strncat(query_template->cached_query, query_template->slices[i],
				query_template->cached_query_size - strlen(query_template->cached_query) - 1);
		if(i < query_template->vars_count )
		{
			strncat(query_template->cached_query, query_template->vars[i]->string_value,
					query_template->cached_query_size - strlen(query_template->cached_query) - 1);
		}
	}

	log_wr(DLOG, "Executing SQL statement \"%s\"", query_template->cached_query);

	return exec_query(dbh, query_template->cached_query,
			query_template->cached_query_size - 1);	/* -1 - for truncate '\0' symbol */
}

static int get_var_value_as_offset(query_var_t * var, dhcp_parsed_message_t * dhcp_msg, uint16_t * offset)
{
	uint16_t value_len;
	uint8_t * var_val;
	if(var->condition)
		var_val = get_cond_var_value(var, dhcp_msg, &value_len);
	else
		var_val = get_var_value(var, dhcp_msg, &value_len);

	if(!var_val)
	{
		log_wr(ELOG, "Can't get value as offset for variable \"%s\"", var->name);
		return FAIL;
	}

	*offset = 0;
	memcpy(offset, var_val, (value_len > sizeof(*offset) ? sizeof(*offset) : value_len));
	if(value_len > 1)
		*offset = ntohs(*offset);

	return OK;
}

static uint8_t * get_cond_var_value(query_var_t * var, dhcp_parsed_message_t * dhcp_req, uint16_t * value_len)
{
	dhcp_var_cond_t * cond = var->condition;
	uint16_t	cond_offset;
	uint16_t	cond_size;
	uint8_t		* cond_value;
	uint16_t	offset;
	uint16_t	length;
	uint16_t	opt_len;
	uint8_t * opt_val = get_dhcp_option_ptr(dhcp_req->raw_dhcp_msg,
			dhcp_req->length, var->code, &opt_len);
	if(!opt_val)
	{
		log_wr(DLOG, "Can't extract value for variable \"%s\" (code %d).",
				var->name, var->code);
		return NULL;
	}

	while(cond)
	{
		if(cond->offset_var)
		{
			if(!get_var_value_as_offset(cond->offset_var, dhcp_req, &cond_offset))
			{
				log_wr(ELOG, "Can't extract offset from variable \"%s\" for parsing condition from variable \"%s\"",
						cond->offset_var->name, var->name);
				return NULL;
			}
		}
		else
			cond_offset = cond->offset;

		if(cond->value_var)
		{
			if(cond->value_var->condition)
			{
				if( !(cond_value = get_cond_var_value(cond->value_var, dhcp_req, &cond_size)) )
				{
					log_wr(DLOG, "Can't extract value from variable \"%s\" for parsing condition from variable \"%s\"",
							cond->offset_var->name, var->name);
					return NULL;
				}
			}
			else
			{
				if( !(cond_value = get_var_value(cond->value_var, dhcp_req, &cond_size)) )
				{
					log_wr(DLOG, "Can't extract value from variable \"%s\" for parsing condition from variable \"%s\"",
							cond->offset_var->name, var->name);
					return NULL;
				}
			}
		}
		else
		{
			cond_size = cond->size;
			cond_value = cond->value;
		}
		/* Check condition offset and size */
		if(cond_offset + cond_size > opt_len)
		{
			log_wr(WLOG, "Condition offset (%d) + condition size (%d) > option length (%d). Variable: \"%s\"",
					cond_offset, cond_size, opt_len, var->name);
			if(cond->next_condition)
			{
				cond = cond->next_condition;
				continue;
			}
			else
			{
				if(cond->false_value)
				{	/* If exists false constant value - return him */
					*value_len = cond->false_length;
					return cond->false_value;
				}

				offset = cond->false_offset;
				length = cond->false_length;
			}
		}
		else
		{
			/* Check condition */
			if(memcmp(cond_value, opt_val + cond_offset, cond_size))
			{	/* False */
				if(cond->next_condition)
				{
					cond = cond->next_condition;
					continue;
				}

				if(cond->false_value)
				{	/* If exists false constant value - return him */
					*value_len = cond->false_length;
					return cond->false_value;
				}

				offset = cond->false_offset;
				length = cond->false_length;
			}
			else
			{	/* True */
				if(cond->true_value)
				{	/* If exists true constant value - return him */
					*value_len = cond->true_length;
					return cond->true_value;
				}

				offset = cond->true_offset;
				length = cond->true_length;
			}
		}

		/* Check value offset and length */

		if(offset + length > opt_len)
		{
			log_wr(ELOG, "Value offset (%d) + value length (%d) from condition > option length (%d).",
					offset, length, opt_len);
			return NULL;
		}

		*value_len = length ? length : opt_len - offset;
		return opt_val + offset;
	}
	return NULL;
}

static uint8_t * get_var_value(query_var_t * var, dhcp_parsed_message_t * dhcp_req, uint16_t * value_len)
{
	uint16_t opt_len;
	uint8_t * opt_val = get_dhcp_option_ptr(dhcp_req->raw_dhcp_msg,
				dhcp_req->length, var->code, &opt_len);
	if(!opt_val)
	{
		log_wr(DLOG, "Can't extract value for variable \"%s\" (code %d).",
				var->name, var->code);
		return NULL;
	}

	if(var->offset)
	{
		if(var->offset > opt_len - 1)
		{
			log_wr(ELOG, "Invalid offset for variable \"%s\". Offset (%d) more or equal option lenght (%d).",
					var->name, var->offset, opt_len);
			return NULL;
		}
		if(var->length && (var->offset + var->length > opt_len))
		{
			log_wr(ELOG, "Invalid length for variable \"%s\". Offset (%d) + length (%d) > option length (%d)",
					var->name, var->offset, var->length, opt_len);
			return NULL;
		}
	}

	if(var->length)
		* value_len = var->length;
	else
	{
		if(var->offset)
			*value_len = opt_len - var->offset;
		else
			*value_len = opt_len;
	}

	return opt_val + var->offset;
}

static int parse_option_variable(query_var_t * var, dhcp_parsed_message_t * dhcp_req)
{
	uint8_t * opt_val = NULL;

	int chars_count;
	uint16_t bytes_retrieve = 0;
	if(var->condition)
		opt_val = get_cond_var_value(var, dhcp_req, &bytes_retrieve);
	else
		opt_val = get_var_value(var, dhcp_req, &bytes_retrieve);

	/*if(!opt_val)
		return FAIL;*/

	chars_count = sizeof(char) * bytes_retrieve * 2 + 1;

	/* If memory not allocated */
	if(!var->string_value)
	{
		var->string_value = malloc(chars_count);
		if(!var->string_value)
		{
			log_wr(CLOG, "Can't allocate memory for store variable value. "
					"Variable name: %s (code %d), need butes: %d.",
					var->name, var->code, chars_count);
			var->string_value_size = 0;
			exit(error_memory);
		}
	}
	/* If memory allocated, but not enought size for store value */
	else if(var->string_value_size < chars_count)
	{
		var->string_value = realloc(var->string_value, chars_count);
		if(!var->string_value)
		{
			log_wr(CLOG, "Can't reallocate memory for store variable value. "
					"Variable name: %s (code %d), need butes: %d.",
					var->name, var->code, chars_count);
			var->string_value_size = 0;
			exit(error_memory);
		}
	}

	/* Store string variable value */
	var->string_value_size = chars_count;
	hex_to_str(bytes_retrieve, opt_val ? opt_val : (uint8_t*)"", var->string_value);
	var->string_value[var->string_value_size - 1] = '\0';

	return chars_count - 1;
}

static void * requests_handler_thread(void * args)
{
	log_wr(DLOG, "Requests handler thread started.");
	handler_args_t * config = (handler_args_t*) args;
	void * dbh;
	if(! (dbh = connect_to_db(config->host, config->user, config->passwd,
			config->db_name, config->port)) )
	{
		if(server_shutdown_flag)
			return NULL;	/* Already shutdown */
		log_wr(CLOG, "Can't work without database connection(s)!");
		exit(error_run_db_clients);
	}

	int i;
	dhcp_query_templ_t ** templates[] =
	{
			&config->discover_template_q,
			&config->history_template_q,
			&config->request_template_q,
			&config->release_template_q
	};

	dhcp_query_templ_t * new_templ;
	for(i = 0; i < sizeof(templates) / sizeof(templates[0]); ++i)
	{
		if(!*templates[i])
			continue;

		new_templ = dupe_query_template(*templates[i]);
		if(!new_templ)
			exit(error_run_db_clients);
		*templates[i] = new_templ;
	}


	dhcp_queue_node_t * client_message_node;
	query_result_t * q_result;
	query_result_t * q_result_h;
	dhcp_full_packet_t dhcp_packet;
	size_t dhcp_data_len;
	char str_ether[STR_ETHER_ALEN + 1];
	char str_ipaddr[IP4_MAXSTR_ALEN + 1];
	uint8_t message_type;
	const uint8_t cached_type = DHCPACK;
	time_t last_cache_flush_ts = time(NULL);
	time_t now;
	size_t full_out_packet_len;
	packet_flags_t pflags;

	while(1)
	{
		/* Get any unprocessed request from queue */
		client_message_node = dhcp_queue_get(config->dhcp_queue, 0, YES);
		if(!client_message_node)
			continue;
		
		/* Check for shutdown */
		if(client_message_node->dhcp_req == SQL_THREADS_SHUTDOWN)
		{
			log_wr(DLOG, "Got shutdown message from queue. Close database connection.");
			disconnect_from_db(dbh);
			log_wr(DLOG, "Database client finished.");
			return NULL;
		}

		if(config->cache_used)
		{
			/* Check cache for obsolete nodes */
			now = time(NULL);
			if(last_cache_flush_ts + CACHE_FLUSH_PERIOD < now)
			{
				dhcp_cache_flush_old();
				last_cache_flush_ts = now;
			}

			if(client_message_node->dhcp_req->message_type == DHCPREQUEST &&
					/* Check our cache */
					(dhcp_cache_find(client_message_node->dhcp_req, &dhcp_packet, &full_out_packet_len)))
			{
				message_type = cached_type;
				etheraddr_bin_to_str(client_message_node->dhcp_req->raw_dhcp_msg->cli_hwaddr, str_ether);
				iptos(client_message_node->dhcp_req->raw_dhcp_msg->gw_iaddr.s_addr ? 
						client_message_node->dhcp_req->raw_dhcp_msg->gw_iaddr.s_addr :
						client_message_node->dhcp_req->dhcp_dev->ipaddr, 
					str_ipaddr);

				log_wr(NLOG, "Found response for client %s %s %s in DHCP cache.",
						str_ether, 
						client_message_node->dhcp_req->raw_dhcp_msg->gw_iaddr.s_addr ? "from relay" : "on",
						str_ipaddr);

				/* Update DHCP xid in cached response */
				dhcp_packet.dhcp_data.xid = client_message_node->dhcp_req->raw_dhcp_msg->xid;
			}
			else
				goto _cache_miss;
		}
		else
		{	/* Not found in cache, send query to database */
_cache_miss:
			q_result = process_client_message(dbh, client_message_node->dhcp_req, config);			
			q_result_h = process_client_message_hist(dbh, client_message_node->dhcp_req,config);
			if (q_result_h!=NULL){
			    log_wr(WLOG, "--History write to BD!");
			};
			if(!q_result || !q_result->count)
			{
				if(q_result)	/* Query success, but empty response */
				{
					log_wr(WLOG, "Can't obtain any configuration information for clients on interface %s/%s from DB. "
						"No free DHCP leases or DB is not configured for this interface?",
						client_message_node->dhcp_req->dhcp_dev->str_ipaddr,
						client_message_node->dhcp_req->dhcp_dev->str_netmask_cidr);
					free_query_result(q_result);
				}
				goto _finish_process_msg;
			}

			dhcp_data_len = make_dhcp_response(client_message_node->dhcp_req, q_result,
					&dhcp_packet, &pflags);
			/* DHCP message type already on this offset */
			message_type = (dhcp_packet.dhcp_data.options + sizeof(magic_cookie))[OPT_VALUE];	
			free_query_result(q_result);

			if(dhcp_data_len)
			{
				full_out_packet_len = sizeof(dhcp_packet) - sizeof(dhcp_packet.dhcp_data) + dhcp_data_len;
				/* Caching our response if needed */
				if(config->cache_used)	/* If parameter "DHCPCacheTTL" in configuration != 0 */
				{
					if(pflags & PFLAG_DNT_CACHE)	/* Don't cache if attribute INTERNAL_DNTCACHE (2001) */
													/* set in database for this client/subnet */
					{
						etheraddr_bin_to_str(client_message_node->dhcp_req->from_ether, str_ether);
						iptos(client_message_node->dhcp_req->dhcp_dev->ipaddr, str_ipaddr);
						log_wr(DLOG, "Don't caching response for client %s/%s "
								"because attribute INTERNAL_DNTCACHE is set in DB.",
								str_ether, str_ipaddr);
					}
					else
					{	/* Caching response for this client */
						if(!dhcp_cache_update(client_message_node->dhcp_req, &dhcp_packet, full_out_packet_len))
						{
							log_wr(ELOG, "Can't add message to cache.");
						}
					}
				}
			}
			else
				goto _finish_process_msg;

		}

		/* Set UDP checksum */
		dhcp_packet.udp_header.check = udp_checksum(&dhcp_packet.udp_header, 
										ntohs(dhcp_packet.udp_header.len),
										dhcp_packet.ip_header.src_addr, dhcp_packet.ip_header.dst_addr);

		dhcp_parsed_message_t * out_msg = calloc(1, sizeof(dhcp_parsed_message_t));
		if(!out_msg)
		{
			log_wr(CLOG, "Can't allocate memory for creating out message: %s", strerror(errno));
			exit(error_memory);
		}

		out_msg->length = full_out_packet_len;
		out_msg->raw_dhcp_msg = malloc(out_msg->length);
		if(!out_msg->raw_dhcp_msg)
		{
			log_wr(CLOG, "Can't allocate for create raw out message: %s", strerror(errno));
			exit(error_memory);
		}
		memcpy(out_msg->raw_dhcp_msg, &dhcp_packet, out_msg->length);
		out_msg->message_type = message_type;


		if(!dhcp_queue_add(
				message_type == DHCPOFFER ?	/* Choose valid queue for response */
					client_message_node->dhcp_req->dhcp_dev->offers_queue :
					client_message_node->dhcp_req->dhcp_dev->ack_queue,
				out_msg, YES))
		{
			log_wr(ELOG, "Can't add DHCP response to %s queue.",
					message_type == DHCPOFFER ? "offers" : "ack");
		}
		else if(!client_message_node->dhcp_req->raw_dhcp_msg->gw_iaddr.s_addr && 
				message_type == DHCPOFFER)	/* WARN: need check type over message_type variable */
		{									/* because out_msg data may be already free'd from other thread */
			/* Sending ARP who-has for testing IP address is free */
			if(!arp_who_has(client_message_node->dhcp_req->dhcp_dev,
					DHCP_DATA_FROM_FULL_PACKET(out_msg->raw_dhcp_msg)->you_iaddr.s_addr))
			{
				/* TODO Наверное нужно вести подсчёт ошибок */
			}
		}

_finish_process_msg:

		dhcp_queue_remove(config->dhcp_queue, client_message_node, YES);
		dhcp_queue_free_node(client_message_node, config->dhcp_queue, YES);
	}

	return NULL;
}

void print_dhcp_header_offsets(void)
{
	int i;
	printf("|---------------------------------------------------|\n");
	printf("|          DHCP header fields offset table          |\n");
	printf("|------------------------------------------|--------|\n");
	printf("|                 Field                    | Offset |\n");
	printf("|------------------------------------------|--------|\n");
	for(i = 1; i < sizeof(header_fields) / sizeof(header_fields[0]); ++i)
	{
		printf("| %-40s |   %-4d |\n", header_fields[i].description, header_fields[i].offset);
	}
	printf("|------------------------------------------|--------|\n");

	return;
}


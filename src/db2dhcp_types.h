/*
 * db2dhcp_types.h
 *
 *  Created at: 31.08.2009
 *      Author: Roman Chebotarev
 */

#ifndef DB2DHCP_TYPES_H_
#define DB2DHCP_TYPES_H_

#include "common_includes.h"
#include "net.h"
#include "dhcp.h"

/*#pragma pack(1)*/

#define IPV4_ALEN			4	/* 4 bytes */

#define	CAP_TIMEOUT			10		/* Waiting 100 microseconds for avoid CPU overload (microsecs) */
#define IPTOSBUFFERS		12
#define STR_MAX_IP4_ALEN	15		/* 12 digits + 3 delimiters */
#define STR_MIN_IP4_ALEN	7		/* 4 digit + 3 delimiters */
#define DEFAULT_QUEUE_MAX_SIZE	100

#define CALC_OFFSET(struct_type, field) \
	((const uint8_t *)&(((struct_type*)0)->field)) - \
			(const uint8_t *)0

#define DB_RECONNECT_TIME	4
#define	SQL_THREADS_SHUTDOWN	NULL

/*Defined errors codes*/

enum error_codes
{
	error_euid				= 10,
	error_network_subsystem	= 11,
	error_signal			= 20,
	error_log				= 30,
	error_memory			= 40,
	error_config			= 50,
	error_queue_init		= 51,
	error_run_db_clients	= 60,
	error_run_dhcp_procs	= 70,
	error_dbm_type			= 80,
	error_opendev			= 90,
	error_listing_dev		= 100,
	error_pcap_compile		= 110,
	error_pcap_setfilter	= 120,
	error_sendpacket		= 130,
	error_getpacket			= 140,
	error_setnonblock		= 150,
	error_invalid_dev		= 160,
	error_mutex_init		= 170,
	error_condition_init	= 171,
	error_abnormal			= 255
};

typedef enum dbm_types
{
	db_pgsql = 1,
	db_mysql,
	db_firebird,
	db_oracle
} dbm_t;

typedef struct dbm_option
{
	char 			*name;
	enum dbm_types 	type;
	uint16_t 		default_port;
	void * (*connect_to_db)(const char * host, const char * user,
			const char * passwd,	const char * db_name, uint16_t port);
	void * (*query)(void * dbh, const char *sql_st, int st_len);
	void (*disconnect)(void * dbh);
} dbm_description;

enum columns
{
	CODE_INDEX,	/*	0	*/
	TYPE_INDEX,	/*	1	*/
	VALUE_INDEX	/*	2	*/
};

#if __WORDSIZE == 64
#define MAX_UINT4_STRSIZE	sizeof("18446744073709551615")
#else
#define MAX_UINT4_STRSIZE	sizeof("4294967295")
#endif

/* Struct which define DHCP interface */
struct dhcp_queue_type;

typedef struct dhcp_device
{
	pcap_t				* dev;
	uint8_t				*ether_addr;
	uint32_t			ipaddr;
	uint32_t			network;
	uint32_t			netmask;
	uint16_t			srv_port_htons;
	uint16_t			cli_port_htons;
	int					index;

	char				str_name[MAX_NETDEV_NAME_SIZE];
	char				str_ether_addr[STR_ETHER_ALEN + 1];
	char				str_ipaddr[IP4_MAXSTR_ALEN + 1];
	char				str_network[IP4_MAXSTR_ALEN + 1];
	char				str_netmask[IP4_MAXSTR_ALEN + 1];
	char				str_netmask_cidr[3];
	char				str_ipaddr_int[MAX_UINT4_STRSIZE];
	char				str_network_int[MAX_UINT4_STRSIZE];
	char				str_netmask_int[MAX_UINT4_STRSIZE];
	char				str_srv_port[6];
	char				str_cli_port[6];

	struct dhcp_queue_type *offers_queue;
	struct dhcp_queue_type *ack_queue;
} dhcp_device_t;

/* Struct for transmitting client DHCP message data from dhcp_process thread to DB client */
typedef struct dhcp_parsed_msg_info
{
	dhcp_device_t	*dhcp_dev;
	dhcp_message_t	*raw_dhcp_msg;
	uint8_t			message_type;
	int				max_msg_size;
	int				length;
	uint8_t			option82_len;
	uint8_t			* option82_ptr;
	uint8_t			from_ether[ETHER_ALEN];
} dhcp_parsed_message_t;

typedef struct dhcp_queue_node
{
	struct dhcp_queue_node	*next;
	struct dhcp_queue_node	*prev;
	dhcp_parsed_message_t	*dhcp_req;
	int						processed;	/* Not zero if node in processed by SQL thread */
	int						removed;	/* Not zero if node removed from queue */
	int						used_by;	/* Counter of threads which used node */
	struct timeval			ts;
} dhcp_queue_node_t;

typedef struct dhcp_queue_type
{
	char				* name;
	dhcp_queue_node_t	* first;
	dhcp_queue_node_t	* last;
	int					count;
	int					new_requests;
	int					max_size;
	pthread_mutex_t		*lock_get;
	pthread_cond_t		*cond_get;	/* Condition variable for blocking SQL threads */
} dhcp_queue_t;

typedef struct dhcp_trhread_args
{
	dhcp_queue_t		*dhcp_queue;
	int					sql_threads_count;
	uint32_t			primary_ipaddr;
	uint16_t			dhcp_srv_port;
	uint16_t			dhcp_cli_port;
	char 				*if_name;
	char				if_index;
	uint8_t				*ether_addr;
	dhcp_device_t		*listen_device;
} dhcp_proc_args_t;

/* Struct for launching DHCP thread on interface */
typedef struct dhcp_process_thrd
{
	pthread_t			thread_id;
	dhcp_proc_args_t	dhcp_args;
	void				*(*execution)(void * );
} dhcp_proc_thread_t;

/* Enum of data types for correct interpretation data from DB */
enum dhcp_options_data_types
{
	UINT1 = 1,	/* 1 - one byte */
	UINT4,		/* 2 - any other integer data (always use 4 bytes) */
	HEX,		/* 3 - hex string data */
	STRING,		/* 4 - string data */
	IPADDRS,	/* 5 - list of IP address. One or more addresses, comma separated. */
	BINARY		/* 6 - binary data without string conversion */
};

/* All codes used into DHCP packets - include 'options' field,
 * DHCP packet header fields and codes for internal server usage */
enum dhcp_options_db_codes
{
	START_OPTION_CODES 	= 0,	/* Minimal value of DHCP option code - 1 */
	END_OPTION_CODES	= 255,	/* Code 255 - DHCP options trailer */

	START_HEADER_CODES	= 1000,
	DHCP_OP				/* 1001 */	= START_HEADER_CODES + 1,
	DHCP_HWTYPE,		/* 1002 */
	DHCP_HWALEN,		/* 1003 */
	DHCP_HOPS,			/* 1004 */
	DHCP_XID,			/* 1005 */
	DHCP_SECS,			/* 1006 */
	DHCP_FLAGS,			/* 1007 */
	DHCP_CLIADDR,		/* 1008 */
	DHCP_YOUADDR,		/* 1009 */
	DHCP_SRVADDR,		/* 1010 */
	DHCP_GWADDR,		/* 1011 */
	DHCP_CLIHWADDR,		/* 1012 */
	DHCP_SRVNAME,		/* 1013 */
	DHCP_BOOTFILE,		/* 1014 */
	DHCP_OPTIONS,		/* 1015 Must be not used - content field 'options' parsed directly */
	END_HEADER_CODES,	/* 1016 */

	START_INTERNAL_CODES	= 2000,
	INTERNAL_DNTCACHE		= START_INTERNAL_CODES + 1,	/* 2001 */
	END_INTERNAL_CODES
};

typedef struct dhcp_header_field_description
{
	char		*description;
	uint16_t	offset;
	uint16_t	maxlen;
} dhcp_hfield_descr_t;

/* Struct's for retrieving data from *SQL clients after executing SQL statement */

typedef struct query_result_item
{
	int			len;
	uint16_t	code;
	uint32_t	type;
	void		*data;
} result_item_t;

typedef struct db_query_result
{
	size_t			count;
	result_item_t	*items;
} query_result_t;

typedef enum dhcp_var_types
{
	var_server = 1,		/* Internal variables (hostname, host-ip, etc...) */
	var_device,			/* Ethernet device paramert (see dhcp_device_t) */
	var_config_header,	/* Variable value make from DHCP header field */
	var_config_options	/* Variable value make from DHCP options header field */
} var_type_t;

struct query_variable;

typedef struct dhcp_variable_condition
{
	struct query_variable	*offset_var;
	uint16_t	offset;
	uint16_t	size;
	struct query_variable	*value_var;
	uint8_t		*value;
	uint8_t		*true_value;
	uint16_t	true_offset;
	uint16_t	true_length;
	uint8_t		*false_value;
	uint16_t	false_offset;
	uint16_t	false_length;
	struct dhcp_variable_condition * next_condition;
} dhcp_var_cond_t;

typedef struct query_variable
{
	var_type_t	type;
	char		*name;
	uint16_t	code;
	uint16_t	offset;
	uint16_t	length;
	int			string_value_size;	/* Memory size already allocated to saving variable value */
	char		*string_value;
	dhcp_var_cond_t	* condition;
} query_var_t;

typedef struct dhcp_query_template
{
	int			slices_size;
	int			slices_count;
	int			total_slices_length;
	char		**slices;
	int			vars_size;
	int			vars_count;
	query_var_t	**vars;
	int			cached_query_size;
	char		*cached_query;
} dhcp_query_templ_t;

typedef struct variables_container
{
	int				size;
	int				count;
	query_var_t		*variables;

} vars_container_t;

/* TODO need comments */
typedef struct db_thread_args
{
	char			*host;
	char			*user;
	char			*passwd;
	char			*db_name;
	uint16_t		port;

	dhcp_queue_t	*dhcp_queue;
	int				cache_used;
	dhcp_query_templ_t	*history_template_q;
	dhcp_query_templ_t	*discover_template_q;
	dhcp_query_templ_t	*request_template_q;
	dhcp_query_templ_t	*release_template_q;
} handler_args_t;

/* TODO need comments */
typedef struct hadnler_thread
{
	pthread_t		thread_id;
	handler_args_t	args;
} request_handler_thread_t;

typedef struct configuration
{
	/* Command line options */
	int		discover;		/* Dicsover and print network interfaces on host */
	int		daemon;			/* If true - program run in daemon mode. Default - true */
	char	*filename;
	int		debug_mode;
	int		log_stdout;
	int		quet_mode;
	int		if_count;
	char	**interfaces;
	int		print_header_offsets;

	/* Options from configuration file */

	/* Common functions */
	char		*log_file_name;
#ifndef _WIN32
	char		*user;
	uid_t		uid;
#endif
	/* Database client options */
	char		*db_server_address;
	int			db_server_port;
	char		*db_user_name;
	char		*db_user_password;
	char		*db_name;
	int			db_clients_count;
	char		*query_discover;
	char		*query_history;
	char		*ip_bind;
	char		*query_request;
	char		*query_release;
	dbm_description * dbm;
	/* DHCP process options */
	int			max_qps_host;
	int			max_qps_total;
	int			dhcp_server_port;
	int			dhcp_client_port;
	time_t		cache_ttl;

	/* Internal options */
	uint8_t				**ether_addresses;		/* Ethernet address of interfaces from '*interfaces' */
	dhcp_queue_t		*dhcp_queue;
	vars_container_t	vars_container;

	dhcp_query_templ_t	*discover_template;
	dhcp_query_templ_t	*history_template;
	dhcp_query_templ_t	*ip_bind_template;
	dhcp_query_templ_t	*request_template;
	dhcp_query_templ_t	*release_template;

} server_configuration;

#endif /* DB2DHCP_TYPES_H_ */

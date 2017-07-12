/*
 * configuration.c
 *
 *  Created at: 27.08.2009
 *      Author: Chebotarev Roman
 */

#include <pwd.h>

#include "config.h"

#include "common_includes.h"
#include "db2dhcp_types.h"
#include "log.h"
#include "dhcp_queue.h"
#include "misc_functions.h"
#include "configuration.h"

#ifdef CONFIG_USE_POSTGRESQL
#include "db_pg_client.h"
#endif

#ifdef CONFIG_USE_MYSQL
#include "db_my_client.h"
#endif

#ifdef CONFIG_USE_FIREBIRD
#include "db_fb_client.h"
#endif


/* TODO need comment */
static int parse_config_file(const char * filename, server_configuration * config);
/* TODO need comment */
static int check_basic_conf(server_configuration * config);
/* TODO need comment */
static int parsing_line(char * line, server_configuration * config);
/* TODO need comment */
static int string_option_handler(const int offset, const char *optval, server_configuration * config);
/* TODO need comment */
static int integer_option_handler(const int offset, const char *optval, server_configuration * config);
/* TODO need comment */
static int dbm_type_option_handler(const int offset, const char *optval, server_configuration * config);
/* TODO need comment */
static char * is_line_hyphen(const char * line);
/* TODO need comment */
int	get_interface_ether_addr(const char *if_name, uint8_t * ether_addr_ptr);
/* TODO need comment */
static int variable_option_handler(const int offset, const char *variable, server_configuration * config);
/* TODO need comment */
static dhcp_query_templ_t * make_query_template(char * original_query_text, const vars_container_t * vars_ctnr);
/* TODO need comment */
static int parse_variable_format(query_var_t * var, char * format, const vars_container_t * vars_ctnr);
/* TODO need comment */
static inline query_var_t * get_var_by_name(const char * var_name, const vars_container_t * vars_ctnr);
/* Creating internal server variables */
static int make_server_vars(server_configuration * config);
/* Creating network devices variables */
static int make_net_devs_vars(server_configuration * config);
/* Add empty variable into variable container and return pointer to new variable */
static query_var_t * add_variable(vars_container_t * ctnr);

const char * default_config_filename =
#ifdef _WIN32
	".\\db2dhcp.conf"
#else
	"/etc/db2dhcp.conf"
#endif
	;

static const char * usage_message =
	"\nUsage:\tdb2dhcp [-L] [-D] [-d] [-q] [-s] [-o] [-c <config-filename>] <interface-name1> [... <interface-nameN>] ";

static const char spaces[] = " \t";

static const option_description_t cfg_options[] =
{
#ifndef _WIN32
	{"User", string_option_handler, CALC_OFFSET(server_configuration, user)},
#endif
	{"LogFile", string_option_handler, CALC_OFFSET(server_configuration, log_file_name)},
	{"DBType", dbm_type_option_handler, CALC_OFFSET(server_configuration, dbm)},
	{"DBServerAddress", string_option_handler, CALC_OFFSET(server_configuration, db_server_address)},
	{"DBServerPort", integer_option_handler, CALC_OFFSET(server_configuration, db_server_port)},
	{"DBUserName", string_option_handler, CALC_OFFSET(server_configuration, db_user_name)},
	{"DBUserPassword", string_option_handler, CALC_OFFSET(server_configuration, db_user_password)},
	{"DBName", string_option_handler, CALC_OFFSET(server_configuration, db_name)},
	{"DBClientsCount", integer_option_handler, CALC_OFFSET(server_configuration, db_clients_count)},
	{"QueryDiscover", string_option_handler, CALC_OFFSET(server_configuration, query_discover)},
	{"QueryHistory", string_option_handler, CALC_OFFSET(server_configuration, query_history)},
	{"IPtoBind", string_option_handler, CALC_OFFSET(server_configuration, ip_bind)},
	{"QueryRequest", string_option_handler, CALC_OFFSET(server_configuration, query_request)},
	/* TODO 40 QueryRequestRej - запрос выполняемый в случае если клиент не выбрал данный сервер */
	/* TODO 40 QueryInform - нужно обрабатывать DHCPINFORM если указан этот запрос */
	{"QueryRelease", string_option_handler, CALC_OFFSET(server_configuration, query_release)},
	{"MaxQpsHost", integer_option_handler, CALC_OFFSET(server_configuration, max_qps_host)},
	{"MaxQpsTotal", integer_option_handler, CALC_OFFSET(server_configuration, max_qps_total)},
	{"DHCPServerPort", integer_option_handler, CALC_OFFSET(server_configuration, dhcp_server_port)},
	{"DHCPClientPort", integer_option_handler, CALC_OFFSET(server_configuration, dhcp_client_port)},
	{"DHCPCacheTTL", integer_option_handler, CALC_OFFSET(server_configuration, cache_ttl)},
	{"Var", variable_option_handler, CALC_OFFSET(server_configuration, vars_container)}

/*	{"", _option_handler, CALC_OFFSET(server_configuration, )},*/
};

static const dbm_description supported_dbm[] =
{
	{NULL, 0, 0, NULL, NULL}
#ifdef CONFIG_USE_POSTGRESQL
	, {"PostgreSQL", db_pgsql, 5432, connect_to_db_pgsql, query_pgsql, disconnect_from_pgsql}
#endif
#ifdef CONFIG_USE_MYSQL
	, {"MySQL", db_mysql, 3306, connect_to_db_mysql, query_mysql, disconnect_from_mysql}
#endif
#ifdef CONFIG_USE_FIREBIRD
	, {"FireBird", db_firebird, 3050, connect_to_db_fbsql, query_fbsql, disconnect_from_fbsql}
#endif
};

static char * remove_excess_spaces(char * string, uint8_t all);

int read_configuration(int argc, char * argv[], server_configuration * config)
{
	/* Available options:
	 * S - discover and print network interfaces on host
	 * D - no daemon mode. Default - false.
	 * d - debug mode
	 * c - configuration file. Default "/etc/db2dhcp.conf" on UNIX or ".\db2dhcp.conf" on Windows
	 * q - quet mode.
	 * s - log to stdout
	 * o - print DHCP header fields offsets.
	 */
	int opt;

	config->daemon = 1;

	while ((opt = getopt(argc, argv, "LDsdqc:o")) != -1)
	{
		switch (opt)
		{
		case 'L':
			config->discover = 1;
			return OK;
		case 'D':
			config->daemon = 0;
			break;
		case 'c':
			config->filename = calloc(strlen(optarg) + 1, sizeof(char));
			CHECK_VALUE_CONF(config->filename,
					"Can't allocate memory for configuration filename. Too long filename?", 0);
			strncpy(config->filename, optarg, strlen(optarg));
		   break;
		case 'q':
			config->quet_mode = 1;
			break;
		case 'd':
			config->debug_mode = 1;
		   break;
		case 's':
			config->log_stdout = 1;
			break;
		case 'o':
			config->print_header_offsets = 1;
			return OK;
		default: /* '?' */
		   fprintf(stderr, "%s\n", usage_message);
		   return FAIL;
		}
	}


	/* Checking interfaces names */
	config->if_count = argc - optind;
	if(config->if_count < 1)
	{
		fprintf(stderr, "Error. Interface name(s) missing.\n");
		return FAIL;
	}

	/* Allocating memory for interfaces names */
	config->interfaces = malloc(sizeof(config->interfaces[0]) * config->if_count);
	CHECK_VALUE_CONF(config->interfaces,  "Can't allocate memory for interfaces list.", FAIL);

	/* Allocating memory for interfaces Ethernet addresses */
	config->ether_addresses = malloc(sizeof(config->ether_addresses[0]) * config->if_count);
	CHECK_VALUE_CONF(config->ether_addresses,
			"Can't allocate memory for ethernet address list.", FAIL);

	int i, j;

	for(i = 0, j = optind; j < argc; ++i, ++j)
	{
		/* Adding interface name to configuration */
		config->interfaces[i] = calloc(strlen(argv[j]) + 1, sizeof(char));
		CHECK_VALUE_CONF(config->interfaces[i], "Can't allocate memory for interface name(s).", 0);
		strncpy(config->interfaces[i], argv[j], strlen(argv[j]));

		/* Get Ethernet address for this interface */
		config->ether_addresses[i] = malloc(ETHER_ALEN * sizeof(uint8_t));
		CHECK_VALUE_CONF(config->ether_addresses[i], "Can't allocate memory for interfase Ethernet address.", 0);

		if(!get_interface_ether_addr((argv[j]), config->ether_addresses[i]))
		{
			fprintf(stderr, "Invalid interface name specified: '%s'\n", argv[j]);
			return FAIL;
		}
	}

	/* Checking configuragion filename */
	if(!config->filename)
		config->filename = (char*) default_config_filename;

	/* Parsing configuration file */
	if(!parse_config_file(config->filename, config))
		return FAIL;

#ifndef _WIN32
	if(config->user)
	{
		struct passwd * pw_user = getpwnam(config->user);
		if(!pw_user)
		{
			fprintf(stderr, "Can't get user ID for username '%s'.\n", config->user);
			return FAIL;
		}
		config->uid = pw_user->pw_uid;
	}
#endif

	/* Check for all data needed to work */
	if(!check_basic_conf(config))
		return FAIL;

	/* Creating internal variables */
	if(!make_server_vars(config))
		return FAIL;

	/* Creating network devices variables */
	if(!make_net_devs_vars(config))
		return FAIL;

	/* Making queries templates */
	if( !(config->discover_template = make_query_template(config->query_discover, &config->vars_container)) )
		return FAIL;

	/* Making queries templates */
	if( !(config->history_template = make_query_template(config->query_history, &config->vars_container)) )
		return FAIL;
	
	/* Making queries templates */
	if( !(config->ip_bind_template = make_query_template(config->ip_bind, &config->vars_container)) )
		return FAIL;
	
	char *query_str = config->query_request ? config->query_request : config->query_discover;
	if( !(config->request_template = make_query_template(query_str, &config->vars_container)) )
		return FAIL;

	if(config->query_release &&
			!(config->release_template = make_query_template(config->query_release, &config->vars_container)))
		return FAIL;

	return OK;
}

/* Creating internal server variables */
int make_server_vars(server_configuration * config)
{
	query_var_t * var;

	/* Get hostname */
	var = add_variable(&config->vars_container);
	CHECK_VALUE_CONF(var, "Can't create internal variable \"SRV-HOSTNAME\"", FAIL);
	CHECK_VALUE_CONF( (var->name = strdup("SRV-HOSTNAME")),
			"Can't allocate memory for \"hostname\" variable name.", FAIL);
	var->type = var_server;
	CHECK_VALUE_CONF(
			(var->string_value = calloc(MAX_HOSTNAME_LEN + 1, sizeof(var->string_value[0]))),
			"Can't allocate memory for hostname.", FAIL);
	if(gethostname(var->string_value, MAX_HOSTNAME_LEN) != 0)
	{
		fprintf(stderr, "Can't get hostname: %s\n", gethostname_error());
		return FAIL;
	}
	var->string_value_size = strlen(var->string_value) + 1;

	return OK;
}

/* Creating network devices variables */
int make_net_devs_vars(server_configuration * config)
{
	static const dev_var_descr_t net_device_vars[] =
	{
			{"DEV-NAME", CALC_OFFSET(dhcp_device_t, str_name)},
			{"DEV-ETHERADDR", CALC_OFFSET(dhcp_device_t, str_ether_addr)},
			{"DEV-IPADDR", CALC_OFFSET(dhcp_device_t, str_ipaddr)},
			{"DEV-NETWORK", CALC_OFFSET(dhcp_device_t, str_network)},
			{"DEV-NETMASK", CALC_OFFSET(dhcp_device_t, str_netmask)},
			{"DEV-NETMASK-CIDR", CALC_OFFSET(dhcp_device_t, str_netmask_cidr)},
			{"DEV-IPADDR-INT", CALC_OFFSET(dhcp_device_t, str_ipaddr_int)},
			{"DEV-NETWORK-INT", CALC_OFFSET(dhcp_device_t, str_network_int)},
			{"DEV-NETMASK-INT", CALC_OFFSET(dhcp_device_t, str_netmask_int)},
			{"DEV-SRVPORT", CALC_OFFSET(dhcp_device_t, str_srv_port)},
			{"DEV-CLIPORT", CALC_OFFSET(dhcp_device_t, str_cli_port)}
	};

	int i;
	query_var_t * var;
	for(i = 0; i < sizeof(net_device_vars) / sizeof(net_device_vars[0]); ++i)
	{
		var = add_variable(&config->vars_container);
		CHECK_VALUE_CONF(var, "Can't create device variable.", FAIL);

		var->type = var_device;
		var->name = net_device_vars[i].name;
		var->offset = net_device_vars[i].offset;
	}
	return OK;
}

int	get_interface_ether_addr(const char *if_name, uint8_t * ether_addr_ptr)
{
#ifdef _WIN32
	/* Start Windows specific code */

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
    /* Declare and initialize variables */

    PIP_ADAPTER_INFO ptr_if_info;
    PIP_ADAPTER_INFO ptr_interface = NULL;
    int ret = 0;

    ULONG out_buf_len = sizeof (IP_ADAPTER_INFO);
    ptr_if_info = (IP_ADAPTER_INFO *) MALLOC(sizeof (IP_ADAPTER_INFO));
    if (ptr_if_info == NULL)
    {
        fprintf(stderr, "Error allocating memory needed to get interfaces info.\n");
        return FAIL;
    }

    if (GetAdaptersInfo(ptr_if_info, &out_buf_len) == ERROR_BUFFER_OVERFLOW)
    {
        FREE(ptr_if_info);
        ptr_if_info = (IP_ADAPTER_INFO *) MALLOC(out_buf_len);
        if (ptr_if_info == NULL)
        {
            fprintf(stderr, "Error allocating memory needed to get interfaces info.\n");
            return FAIL;
        }
    }

    if ( (ret = GetAdaptersInfo(ptr_if_info, &out_buf_len)) != NO_ERROR)
    {
    	fprintf(stderr, "Error! Can't get interfaces info.\n");
    	return FAIL;
    }

    ptr_interface = ptr_if_info;
	while (ptr_interface)
	{
		if(strcmp(if_name + NPF_PREFIX_LEN, ptr_interface->AdapterName))
			ptr_interface = ptr_interface->Next;
		else
		{
			if(ptr_interface->Type != MIB_IF_TYPE_ETHERNET)
			{
				fprintf(stderr, "Interface '%s' not Ethernet device. Can't work on this interface type!\n",
						if_name);
				return FAIL;
			}

			memcpy(ether_addr_ptr, ptr_interface->Address, ETHER_ALEN);
			FREE(ptr_if_info);
			return OK;
		}
	}

	FREE(ptr_if_info);

    return FAIL;
#undef MALLOC
#undef FREE
    /* End Windows-specific code */

#elif __linux__
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd == -1)
	{
		fprintf(stderr, ERROR_PREFIX "Can't create socket for get device %s ethernet address: %s\n",
			if_name, strerror(errno));
		return FAIL;
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

	if(ioctl(fd, SIOCGIFHWADDR, &ifr) != 0)
	{
		fprintf(stderr, ERROR_PREFIX "Can't get device %s ethernet address: %s\n", if_name, strerror(errno));
		return FAIL;
	}

	close(fd);

	/* display result */
	memcpy(ether_addr_ptr, &ifr.ifr_hwaddr.sa_data, ETHER_ALEN);
	int i;
	for (i = 0; i < ETHER_ALEN; ++i)
		ether_addr_ptr[i] = (uint8_t) ifr.ifr_hwaddr.sa_data[i];

	return OK;

#elif __FreeBSD__

	struct ifconf	ifc;
	struct ifreq	ifrs[64], *ifr, *nextifr;
	int				sock;
	int				ifrsize = 0;
	char			dev_name[MAX_NETDEV_NAME_SIZE];

	bzero(&ifc,	sizeof(ifc));
	bzero(ifrs, sizeof(ifrs));

	if ( ( sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
	{
		fprintf(stderr, "Can't create socket for get list of interfaces: '%s'\n", strerror(errno));
		return FAIL;
	}

	ifc.ifc_len = sizeof(ifrs);
	ifc.ifc_buf = (caddr_t)ifrs;

	if (ioctl(sock, SIOCGIFCONF, &ifc) < 0 )
	{
		fprintf(stderr, "Can't get interfaces configuration: '%s'\n", strerror(errno));
		return FAIL;
	}

	for(ifr = ifc.ifc_req; ifc.ifc_len >= sizeof(struct ifreq); ifr = nextifr, ifc.ifc_len -= ifrsize)
	{
		if(ifr->ifr_addr.sa_family == AF_LINK)
		{
			struct sockaddr *sap = &ifr->ifr_addr;
			char    *cptr;
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)sap;
			cptr = sdl->sdl_data;
			if(sdl->sdl_nlen) 
			{
				memcpy(dev_name,cptr,sdl->sdl_nlen);
				dev_name[sdl->sdl_nlen] = '\0';

				if(!strcmp(dev_name, if_name))
				{
					cptr += sdl->sdl_nlen;
					if(sdl->sdl_alen) 
					{
						memcpy(ether_addr_ptr, cptr, ETHER_ALEN);
						goto _found;
					}		
					else
					{
						fprintf(stderr, "Listening device '%s' found but hwaddress for is zero length!\n", if_name);
						return FAIL;
					}
					cptr += sdl->sdl_alen;
				}
			}
		}

		ifrsize =  IFNAMSIZ + ifr->ifr_addr.sa_len;
		nextifr = (struct ifreq *)((caddr_t)ifr + ifrsize);
	}

	fprintf(stderr, "Device '%s' not found.\n", if_name);

	return FAIL;

_found:

	if(close(sock) == -1)
	{
		fprintf(stderr, "Can't close ifconf socket: '%s'\n", strerror(errno));
		return FAIL;
	}

	return OK;

#elif __OpenBSD__

#error OpenBSD is not supported now.

	return FAIL;
#endif
}


int check_basic_conf(server_configuration * config)
{
#define INVALID(msg) \
	{ \
		fprintf(stderr, "%s\n", msg); \
		return FAIL; \
	}

	if(!config->log_file_name)
		INVALID("Log file name missing.");
	if(!config->db_server_address || !strlen(config->db_server_address))
		INVALID("Server address missing.");
	if(!config->db_user_name || !strlen(config->db_user_name))
		INVALID("User name missing.");
	if(!config->query_discover || !strlen(config->query_discover))
		INVALID("SQL DHCPDISCOVER query missing.");
	if(!config->query_history || !strlen(config->query_history))
		INVALID("SQL DHCPHISTORY query missing.");
	
	if(!config->ip_bind || !strlen(config->ip_bind))
		INVALID("SQL ip_bind not set!");

	if((config->db_server_port < MIN_TCP_PORT) || (config->db_server_port > MAX_TCP_PORT) )
		INVALID("Invalid database port value.");

	if(!config->db_clients_count)
		config->db_clients_count = DEFAULT_DBCL_CNT;
	else
		if((config->db_clients_count < MIN_DBCLIENTS) || (config->db_clients_count > MAX_DBCLIENTS))
			INVALID("Invalid database clients count value.");

	if(!config->max_qps_host)
		config->max_qps_host = DEFAULT_MAXQPS_HOST;
	else
		if(config->max_qps_host < 1)
			INVALID("Invalid maximum QPS for host value.");

	if(!config->max_qps_total)
		config->max_qps_total = DEFAULT_MAXQPS_TOTAL;
	else
		if(config->max_qps_total < config->max_qps_host)
			INVALID("Invalid maximum total QPS value.");

	if(!config->dhcp_server_port)
	{
		struct servent * srv = getservbyname("bootps", NULL);
		if(!srv)
			INVALID("Can't get server port value from system DB");
		config->dhcp_server_port = ntohs(srv->s_port);
	}
	else
		if((config->dhcp_server_port < MIN_UDP_PORT) || (config->dhcp_server_port > MAX_UDP_PORT))
			INVALID("Invalid DHCP server port.");

	if(!config->dhcp_client_port)
	{
		struct servent * srv = getservbyname("bootpc", NULL);
		if(!srv)
			INVALID("Can't get client port value from system DB");
		config->dhcp_client_port = ntohs(srv->s_port);
	}
	else
		if((config->dhcp_client_port < MIN_UDP_PORT) || (config->dhcp_client_port > MAX_UDP_PORT))
			INVALID("Invalid DHCP client port.");

	/*if(!config->db_type)
		INVALID("DBType is not set.");*/
	if(!config->db_name)
		INVALID("DBName is not set.");
	if(!config->db_server_address)
		INVALID("DBServerAddress is not set.");
	if(!config->db_user_name)
		INVALID("DBUserName is not set.");

#undef INVALID
	return OK;
}

int parse_config_file(const char * filename, server_configuration * config)
{
	/* Trying to open configuration file */
	FILE *f_cfg = fopen(filename, "r");
	CHECK_VALUE_CONF(f_cfg, "Can't open configuration.", 0);

	/* Start parsing configuratin file */
	char line[MAX_CONFIG_STRLEN + 1];
	bzero(line, sizeof(line));

	int line_num = 0;
	int len;
	char * backsl;
	char * rem_start;	/* Remark start */
	while(fgets(line, MAX_CONFIG_STRLEN, f_cfg))
	{
		++line_num;
		if( (rem_start = strchr(line, '#')) )
			*rem_start = '\0';

		len = strlen(line);
		if(len && (line[len - 1] == '\n') )
			line[len - 1] = '\0';
		/* If the string contain hyphenation */
		while( (backsl = is_line_hyphen(line)) )
		{
			static char next_line[MAX_CONFIG_STRLEN + 1];
			++line_num;
			*backsl = '\0';

			if(!fgets(next_line, MAX_CONFIG_STRLEN, f_cfg))
				break;

			if( (rem_start = strchr(next_line, '#')) )
				*rem_start = '\0';

			len = strlen(next_line);
			if(next_line[len - 1] == '\n')
				next_line [len - 1] = '\0';

			if((strlen(next_line) + strlen(line)) > MAX_CONFIG_STRLEN)
			{
				fprintf(stderr, "Too long string in configuration file. Line #%d:\n", line_num);
				fprintf(stderr, LINE_DIV);
				fprintf(stderr, "%s\n", next_line);
				fprintf(stderr, LINE_DIV);
				return FAIL;
			}
			/* Adding next line to current line */
			strncat(line, next_line, MAX_CONFIG_STRLEN);
		}

		if( !parsing_line(line, config))
		{
			fprintf(stderr, "Problem with parsing line #%d:\n", line_num);
			fprintf(stderr, LINE_DIV);
			fprintf(stderr, "%s\n", line);
			fprintf(stderr, LINE_DIV);
			return FAIL;
		}
	}

	/* Trying to close configuration file */
	if(fclose(f_cfg) == EOF)
	{
		perror("Can't close file");
		return FAIL;
	}

	return OK;
}

/* Checking if the string contains hyphenation */
char * is_line_hyphen(const char * line)
{
	char * backsl = strrchr(line, '\\');

	if(!backsl)
		return FAIL;

	int i;
	int len = strlen(backsl);
	for(i = 1; i < len; ++i)
	{	/* If string after backslash ('\') contain not spase symbols */
		if( (backsl[i] != ' ') && (backsl[i] != '\t') )
			return FAIL;
	}

	return backsl;
}

/* Parsing line from configuration file, character '=' as separator
 * between option name and option value */
int parsing_line(char * ext_line, server_configuration * config)
{

	int len = strlen(ext_line);
	if(!len || ((len == 1) &&(ext_line[0] == '\n')))
		return OK;	/* Empty string */

	if(strspn(ext_line, spaces) == strlen(ext_line))
		return OK;	/* Only spaces in this line */

	static char line[MAX_CONFIG_STRLEN + 1];
	bzero(line, sizeof(line));
	strncpy(line, ext_line, MAX_CONFIG_STRLEN);

	char * opt_name;
	char * opt_val;


	opt_name = line;
	char * ptr = line;
	/* Searching separator */
	ptr = strchr(line, '=');
	CHECK_VALUE_CONF(ptr, "Option/value separator symbol (\"=\") not found.", FAIL)

	*ptr = '\0';	/* Separate option name and option value */

	opt_val = ++ptr;
	CHECK_VALUE_CONF(*opt_val != '\0', "Missing option name.", FAIL);


	/* Searching start option name */
	opt_name += strspn(line, spaces);	/* Skeeping first spaces */
	/* Breaking option name */
	ptr = opt_name + strcspn(opt_name, spaces);
	CHECK_VALUE_CONF(strspn(ptr, spaces) == strlen(ptr), "Unexpected spaces in option name.", FAIL);

	*ptr = '\0';
	CHECK_VALUE_CONF(*opt_name, "Empty option name.", FAIL);

	/* Searching start option value */
	opt_val += strspn(opt_val, spaces);

	CHECK_VALUE_CONF(*opt_val != '\0', "Missing option value.", FAIL);

	/* Searching end of option value */
	ptr = opt_val + strlen(opt_val) - 1;
	while(ptr != opt_val)
	{
		if((*ptr != ' ' ) && (*ptr != '\t'))
		{
			*(ptr + 1) = '\0';
			break;
		}
		--ptr;
	}

	/* Removing symbols ', " from start and end line */
	static const char escapes[] = "\"'`";
	int i;
	len = strlen(opt_val);
	for(i = 0; i < sizeof(escapes); ++i)
	{
		if(opt_val[0] == escapes[i])
		{
			if((opt_val[len - 1] != escapes[i]) || (len < 2))	/* Unterminated string */
				return FAIL;

			opt_val[len - 1] = '\0';
			++opt_val;
			break;
		}
	}

	/* Handling option */
	for(i = 0; i < (sizeof(cfg_options) / sizeof(*cfg_options)); ++i)
	{
		if(!strcmp(opt_name, cfg_options[i].name))
		{
			if(!cfg_options[i].handler(cfg_options[i].offset, opt_val, config))
			{
				fprintf(stderr, ERROR_PREFIX "Can't parse option with name '%s' and value '%s'\n",
						opt_name, opt_val);
				return FAIL;
			}
			return OK;
		}
	}

	/* Option with name 'opt_name' - is unknown */
	CHECK_VALUE_CONF(0, "Unknown option name.", FAIL);
}

int string_option_handler(const int offset, const char *optval, server_configuration * config)
{
	char ** target_pptr = (char**)(((char *) config) + offset);
	int len = strlen(optval);

	if(*target_pptr)
		/* Memory already allocated */
		free(*target_pptr);

	if( ! (*target_pptr = malloc(len + 1)) )
	{
		fprintf(stderr, "Can't allocate memory for saving option value.\n");
		return FAIL;
	}

	strncpy(*target_pptr, optval, len);
	(*target_pptr)[len] = '\0';

	return OK;
}

int integer_option_handler(const int offset, const char *optval, server_configuration * config)
{
	uint32_t * const target_ptr = (uint32_t *) ( ((uint8_t *) config) + offset);
	if(sscanf(optval, "%d", target_ptr) < 1)
		return FAIL;
	return OK;
}

int dbm_type_option_handler(const int offset, const char *optval, server_configuration * config)
{
	int i;
	for(i = 1; i < (sizeof(supported_dbm) / sizeof(dbm_description)); ++i)
	{
		if(!strncmp(optval, supported_dbm[i].name, strlen(optval)))
		{
			if(!supported_dbm[i].connect_to_db || !supported_dbm[i].query)
			{
				fprintf(stderr, "Invalid (or not supported) DBType: '%s'\n", optval);
				return FAIL;
			}
			config->dbm = (dbm_description*)&supported_dbm[i];

			if(!config->db_server_port)
				config->db_server_port = supported_dbm[i].default_port;

			return OK;
		}
	}

	return FAIL;
}

query_var_t * add_variable(vars_container_t * ctnr)
{
	if(!ctnr->size)
	{
		ctnr->variables = malloc(DEFAULT_VAR_CONT_SIZE * sizeof(query_var_t));
		CHECK_VALUE_CONF(ctnr->variables, "Can't allocate memory for parsing variables.", NULL);
		ctnr->size = DEFAULT_VAR_CONT_SIZE;
	}
	if(ctnr->count == ctnr->size)
	{
		ctnr->size *= 2;
		ctnr->variables = realloc(ctnr->variables, sizeof(query_var_t) * ctnr->size);
		CHECK_VALUE_CONF(ctnr->variables, "Can't reallocate memory for parsing variables.", NULL);
	}

	query_var_t * var = &ctnr->variables[ctnr->count++];
	bzero(var, sizeof(query_var_t));

	return var;
}

int variable_option_handler(const int offset, const char *variable, server_configuration * config)
{
	vars_container_t * ctnr = &config->vars_container;

	query_var_t * var = add_variable(ctnr);
	if(!var)
		return FAIL;

	/* Extracting variable name */
	char * pt = strpbrk(variable, spaces);
	if(!pt)
	{
		fprintf(stderr, "Invalid variable format: '%s'\n", variable);
		return FAIL;
	}
	int len = pt - variable;
	var->name = malloc(sizeof(char) * (len + 1));
	CHECK_VALUE_CONF( var->name, "Can't allocate variable for store variable name.", 0);
	memcpy(var->name, variable, len);
	var->name[len] = '\0';
	/* Check for dupes */
	int i;
	for(i = 0; i < ctnr->count - 1; ++i)
		if(!strcmp(ctnr->variables[i].name, var->name))
		{
			fprintf(stderr, "Error: duplicate variable with name '%s'\n", var->name);
			return FAIL;
		}

	/* Skip next spaces */
	char * format = pt + 1 + strspn(pt + 1, spaces);
	CHECK_VALUE_CONF(format && (strlen(format) > 2),
			"Invalid variable - format missing or too short.", FAIL);
	/* Removing all spaces from format */
	remove_excess_spaces(format, 1);

	/* Parsing variable format */

	var->string_value = NULL;

	pt = format;
	format += 2;
	switch(*pt)
	{
	case 'h':
		if( !(pt = strchr(format, ':')))
			return FAIL;

		*pt = '\0';
		if(sscanf(format, "%hu", &var->offset) < 1)
			return FAIL;

		format = pt + 1;
		if(sscanf(format, "%hu", &var->length) < 1)
			return FAIL;

		if(var->offset + var->length > (uint8_t*)(((dhcp_message_t*)NULL)->options) - (uint8_t*)NULL)
		{
			fprintf(stderr, "Too big offset for variable value (\"%s\" - offset: %d, length: %d)\n",
					var->name, var->offset, var->length);
			return FAIL;
		}

		var->code = 0;

		/* Length of header vars always static */
		var->string_value_size = var->length * 2 + 1;
		var->string_value = malloc(var->string_value_size);
		if(!var->string_value)
		{
			fprintf(stderr, "Can't allocate memory for storing value variable \"%s\"\n", var->name);
			return FAIL;
		}
		var->string_value[var->string_value_size - 1] = '\0';

		var->type = var_config_header;

		break;
	case 'o':
		if( !(var->code = atoi(format)) )
			return FAIL;

		var->type = var_config_options;

		if( !(pt = strchr(format, ':')))
		{	/* No offset and length found */
			var->offset = 0;
			var->length = 0;
			break;
		}

		if(!parse_variable_format(var, ++pt, &config->vars_container))
			return FAIL;
		break;
	default:
		return FAIL;
		break;
	}

	return OK;
}

int parse_variable_format(query_var_t * var, char * format, const vars_container_t * vars_ctnr)
{
	char * pt = format;
	if(*pt != '(')	/* Offset + length without conditions */
	{
		if( (pt = strchr(format, ':')) )
			*pt = '\0';

		if(sscanf(format, "%hu", &var->offset) < 1)
			return FAIL;

		if(!pt)
		{	/* Offset only */
			var->length = 0;
			return OK;
		}

		format = pt + 1;
		if(sscanf(format, "%hu", &var->length) < 1)
			return FAIL;
	}
	else
	{	/* Condition found */
		while(format[0] == '(')
		{
			/* Searching last condition for this variable */
			dhcp_var_cond_t * condition;
			dhcp_var_cond_t ** last = &var->condition;
			while(*last)
				last = &(*last)->next_condition;
			condition = calloc(1, sizeof(dhcp_var_cond_t));
			CHECK_VALUE_CONF(condition, "Can't allocate memory for variable condition!", FAIL);
			*last = condition;

			/* Start parsing condition offset */
			++format;
			if(*format == '$')
			{	/* Found offset variable */
				CHECK_VALUE_CONF( (pt = strchr(++format, '$')), "Unterminated variable name.", FAIL);
				*pt = '\0';
				condition->offset_var = get_var_by_name(format, vars_ctnr);
				if(!condition->offset_var)
				{
					fprintf(stderr, "Undefined variable in condition offset: \"%s\"\n", format);
					return FAIL;
				}
				*pt = '$';
			}
			else
			{
				if(sscanf(format, "%hu", &condition->offset) < 1)
				{
					fprintf(stderr, "Invalid condition offset: \"%s\"\n", format);
					return FAIL;
				}
			}

			/* Start parsing condition value */
			CHECK_VALUE_CONF( (pt = strchr(format, '=')), "Can't parse condition value.", FAIL);
			format = pt + 1;
			if(*format == '$')
			{	/* Found value variable */
				CHECK_VALUE_CONF( (pt = strchr(++format, '$')), "Unterminated variable value.", FAIL);
				*pt = '\0';
				condition->value_var = get_var_by_name(format, vars_ctnr);
				if(!condition->value_var)
				{
					fprintf(stderr, "Undefined variable in condition value: \"%s\"\n", format);
					return FAIL;
				}
				*pt = '$';
				CHECK_VALUE_CONF( (pt = strchr(format, ')')) ,
						"Error parsing condition: closed bracket not found.", FAIL);
				format = pt + 1;
			}
			else
			{	/* Check value length and store him if value is not variable */
				if(strncmp(format, "0x", strlen("0x")))
				{
					fprintf(stderr, "Invalid condition value format: \"%s\"\n", format);
					return FAIL;
				}
				format += strlen("0x");

				CHECK_VALUE_CONF( (pt = strchr(format, ')')) ,
						"Error parsing condition: closed bracket not found.", FAIL);

				if((pt - format) % 2)	/* Not even number of bytes format */
				{
					*pt = '\0';
					fprintf(stderr, "Odd number of chars for hex string: 0x%s\n", format);
					return FAIL;
				}
				condition->size = (pt - format) / 2;	/* Size in bytes instead size in chars */

				condition->value = malloc(sizeof(condition->value[0]) * condition->size);
				CHECK_VALUE_CONF(condition->value, "Can't allocate memory for store condition value!", FAIL);

				if(!str_to_hex(condition->size, format, condition->value))
				{
					fprintf(stderr, "Invalid condition value: \"%s\"\n", format);
					return FAIL;
				}

				format = pt + 1;
			}

			/* Get 'if true' values */

			if(strncmp(format, "0x", strlen("0x")))
			{	/* This is not constant value. Get offset and length */
				if(sscanf(format, "%hu", &condition->true_offset) < 1)
				{
					fprintf(stderr, "Invalid condition true offset: \"%s\"\n", format);
					return FAIL;
				}

				if( !(pt = strchr(format, ':')) )
				{
					fprintf(stderr, "Condition true length not found: \"%s\"\n", format);
					return FAIL;
				}

				format = pt + 1;
				if(sscanf(format, "%hu", &condition->true_length) < 1)
				{
					fprintf(stderr, "Invalid condition true length: \"%s\"\n", format);
					return FAIL;
				}

				CHECK_VALUE_CONF( (pt = strchr(format, '|')), "'if false' condition ommited.", FAIL);

				format = pt + 1;
			}
			else
			{	/* Constant value from config */
				format += strlen("0x");
				CHECK_VALUE_CONF( (pt = strchr(format, '|')), "'if false' condition ommited.", FAIL);

				condition->true_length = pt - format;
				if(condition->true_length % 2)
				{
					*pt = '\0';
					fprintf(stderr, "Odd number of chars for hex string: 0x%s in true constant.\n", format);
					return FAIL;
				}
				condition->true_length /= 2;
				condition->true_value = malloc(condition->true_length * sizeof(condition->true_value[0]));
				CHECK_VALUE_CONF(condition->true_value,
						"Can't allocate memory for store condition true value.", FAIL);

				if(!str_to_hex(condition->true_length, format, condition->true_value))
				{
					fprintf(stderr, "Invalid condition true constant value: \"%s\"\n", format);
					return FAIL;
				}
				format = pt + 1;
			}
			/* Get 'if false' values */

			if(format[0] == '(')	/* If false - go to next condition */
				continue;

			if(strlen(format) < 3)	/* 3 minimal length: "digit:digit" = 3 chars */
			{
				fprintf(stderr, "Invalid condition false format length - too short: \"%s\"\n", format);
				return FAIL;
			}

			if(strncmp(format, "0x", strlen("0x")))
			{
				if(sscanf(format, "%hu", &condition->false_offset) < 1)
				{
					fprintf(stderr, "Invalid condition false offset: \"%s\"\n", format);
					return FAIL;
				}

				if( !(pt = strchr(format, ':')) )
				{
					fprintf(stderr, "Condition false length not found: \"%s\"\n", format);
					return FAIL;
				}

				format = pt + 1;
				if(sscanf(format, "%hu", &condition->false_length) < 1)
				{
					fprintf(stderr, "Invalid condition false length: \"%s\"\n", format);
					return FAIL;
				}
			}
			else
			{	/* Constant value from config */
				format += strlen("0x");

				condition->false_length = strlen(format);
				if(condition->false_length % 2)
				{
					fprintf(stderr, "Odd number of chars for hex string: 0x%s in false constant.\n", format);
					return FAIL;
				}
				condition->false_length /= 2;
				condition->false_value = malloc(condition->false_length * sizeof(condition->false_value[0]));
				CHECK_VALUE_CONF(condition->false_value,
						"Can't allocate memory for store condition false value.", FAIL);

				if(!str_to_hex(condition->false_length, format, condition->false_value))
				{
					fprintf(stderr, "Invalid condition false constant value: \"%s\"\n", format);
					return FAIL;
				}
			}

			/* This was last condition */
			break;
		}

	}

	return OK;
}

/* Removed excess spaces and tabulations from strings */
char * remove_excess_spaces(char * string, uint8_t all)
{
	char 	*space_pt = strpbrk(string, spaces);
	size_t	shift;

	while(space_pt)
	{
		shift = strspn(space_pt + 1, spaces);
		if(*(space_pt + 1 + shift) == '\0')	/* Spaces terminated string */
		{
			*space_pt = '\0';
			break;
		}
		memmove(space_pt + (all ? 0 : 1),	/* To next position after space */
				space_pt + 1 + shift, /* From first non space symbol */
				strlen(space_pt + 1 + shift) + 1 /* All string plus zero-terminating sybmol */
				);
		space_pt = strpbrk(space_pt + 1, spaces);
	}

	return string;
}

dhcp_query_templ_t * make_query_template(char * original_query_text, const vars_container_t * vars_container)
{
	char * query_text = strdup(original_query_text);

	CHECK_VALUE_CONF(query_text, "Cant allocate memory for duplicate query text.", NULL);

	remove_excess_spaces(query_text, 0);

	dhcp_query_templ_t * template_q = calloc(1, sizeof(dhcp_query_templ_t));
	CHECK_VALUE_CONF(template_q, "Can't allocate memory for create final query struct.", NULL);

	template_q->slices_size = DEFAULT_SLICES_SIZE;
	template_q->slices = malloc(sizeof(template_q->slices[0]) * template_q->slices_size);
	CHECK_VALUE_CONF(template_q->slices, "Can't allocate memory for query slices.", NULL);

	template_q->vars_size = DEFAULT_SLICES_SIZE - 1;
	template_q->vars = calloc(template_q->vars_size, sizeof(template_q->vars[0]));
	CHECK_VALUE_CONF(template_q->vars, "Can't allocate memory for query variables.", NULL);

	char *var_start, *var_end, *pt;

	template_q->slices_count = 1;
	template_q->slices[0] = query_text;

	var_start = strchr(query_text, '$');

	if(!var_start)
	{
		template_q->total_slices_length = strlen(template_q->slices[0]);
		return template_q;
	}

	if(var_start && (var_start - query_text < 6)) /* 6 - minimal length for suitable SQL (SELECT, UPDATE, INSERT) */
	{
		fprintf(stderr, "Too early variable found. Query: \"%s\"\n", original_query_text);
		return NULL;
	}

	int i;
	do
	{
		/* Check for escaped symbols '\$' */
		if( *(var_start - 1) == '\\')
		{
			pt = var_start;
			while(*pt)
			{
				*(pt - 1) = *pt;
				++pt;
			}
			*(pt - 1) = '\0';
			continue;
		}

		/* Check for end line after symbol '$' */
		if(*(var_start + 1) == '\0')
		{
			fprintf(stderr, "Unterminated variable at end line in query \"%s\".\n", original_query_text);
			return NULL;
		}

		*var_start = '\0';
		++var_start;
		var_end = strchr(var_start, '$');
		while(1)
		{
			if(!var_end)
			{
				fprintf(stderr, "Unterminated variable '%s' in query \"%s\"\n", var_start, original_query_text);
				return NULL;
			}

			if(*(var_end - 1) == '\\')
			{
				pt = var_end;
				while(*pt)
				{
					*(pt - 1) = *pt;
					++pt;
				}
				*(pt - 1) = '\0';
				var_end = strchr(var_end, '$');
			}
			else
				break;
		}
		*var_end = '\0';

		/* Check for empty variable */
		if( var_end - var_start == 0 )
		{
			fprintf(stderr, "Empty variable in query \"%s\".\n", original_query_text);
			return NULL;
		}

		/* Searching variable name in variables container */
		for(i = 0; i < vars_container->count; ++i)
			if(!strcmp(var_start, vars_container->variables[i].name))
			{
				if(template_q->vars_count == template_q->vars_size)
				{
					template_q->vars_size *= 2;
					template_q->vars = realloc(template_q->vars, template_q->vars_size * sizeof(template_q->vars[0]));
					CHECK_VALUE_CONF(template_q->vars, "Can't realloc memory for variables in query.", NULL);
				}
				template_q->vars[template_q->vars_count] = &vars_container->variables[i];
				++template_q->vars_count;
				goto var_found;
			}

		fprintf(stderr, "Undefined variable \"$%s$\" in query:\n\"%s\".\n", var_start, original_query_text);
		return NULL;

var_found:
		/* If not end of line - adding slice to template */
		if(*(var_end + 1))
		{
			if(template_q->slices_count == template_q->slices_size)
			{
				template_q->slices_size *= 2;
				template_q->slices =
					realloc(template_q->slices, template_q->slices_size * sizeof(template_q->slices[0]));
				CHECK_VALUE_CONF(template_q->slices, "Can't realloc memory for query slices.", NULL);
			}
			template_q->slices[template_q->slices_count++] = var_end + 1;

		}

		var_start = var_end + 1;
	}
	while( (var_start = strchr(var_start, '$')) );

	/* Caclculate total slices length */
	for(i = 0; i < template_q->slices_count; ++i)
		template_q->total_slices_length += strlen(template_q->slices[i]);

	return template_q;
}

query_var_t * get_var_by_name(const char * var_name, const vars_container_t * vars_ctnr)
{
	int i;
	for(i = 0; i < vars_ctnr->count; ++i)
	{
		if(!strcmp(var_name, vars_ctnr->variables[i].name))
			return &vars_ctnr->variables[i];
	}
	return NULL;
}

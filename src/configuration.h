/*
 * configuration.h
 *
 *  Created at: 27.08.2009
 *      Author: Chebotarev Roman
 */

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#define LINE_DIV	"-----------------------------\n"

#define	MAX_CONFIG_STRLEN		4095
#define MIN_DBCLIENTS			1
#define MAX_DBCLIENTS			64
#define	DEFAULT_DBCL_CNT		4		/* DB clients count */
#define DEFAULT_MAXQPS_HOST		6
#define	DEFAULT_MAXQPS_TOTAL	(DEFAULT_MAXQPS_HOST * 4)
#define DEFAULT_VAR_CONT_SIZE	5
#define DEFAULT_SLICES_SIZE	3

#define ERROR_PREFIX "CONFIGURATION ERROR: "

#define CHECK_VALUE_CONF(p, msg, ret) \
		if(!(p)) \
		{ \
			if(*msg) \
				fprintf(stderr, ERROR_PREFIX "%s\n", msg); \
			return ret; \
		}

typedef struct config_option
{
	char 	* name;
	int		(*handler)(const int, const char *, server_configuration * );
	int		offset;
} option_description_t;

typedef struct device_variable_description
{
	char	 	*name;
	uint16_t	offset;	/* Offset in dhcp_device_t structure */
} dev_var_descr_t;

/* TODO need comment */
int read_configuration(int argc, char * argv[], server_configuration * config);
void print_dhcp_header_offsets(void);

#endif /* CONFIGURATION_H_ */

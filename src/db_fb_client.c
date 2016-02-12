/*
 * db_fb_client.c
 *
 *  Created at: 19.05.2011
 *      Author: Chebotarev Roman
 */

#include "config.h" 

#include <pthread.h>
#include "common_includes.h"
#include "db2dhcp_types.h"
#include "db_fb_client.h"
#include "log.h"

#include <ibase.h>

/* This macro is used to declare structures representing SQL VARCHAR types */
#define SQL_VARCHAR(len) struct {short vary_length; char vary_string[(len)+1];}

extern inline void free_query_result(query_result_t * result);
extern int server_shutdown_flag;

static char * st_host;
static char * st_user;
static char * st_passwd;
static char * st_db_name;
static char * st_port;

static isc_db_handle * make_fb_connection(const char * host, const char * port, const char * db_name, 
								const char * user, const char * passwd);

void * connect_to_db_fbsql(const char * host, const char * user,
		const char * passwd, const char * db_name, uint16_t port)
{
	static char port_str[6];
	snprintf(port_str, sizeof(port_str), "%u", port);

	st_host = strdup(host);
	st_user = strdup(user);
	st_passwd = strdup(passwd);
	st_db_name = strdup(db_name);
	st_port = port_str;

	if( ! (st_host && st_user && st_passwd && st_db_name) )
	{
		log_wr(CLOG, "Can't allocate memory for save auth data: '%s'", strerror(errno));
		exit(error_memory);
	}

	isc_db_handle ** dbhpp = malloc(sizeof(isc_db_handle*));
	
	if(!dbhpp)
	{
		log_wr(CLOG, "Can't allocate memory for DB handle pointer: '%s'", strerror(errno));
		exit(error_memory);
	}
	*dbhpp = make_fb_connection(host, port_str, db_name, user, passwd);

	return dbhpp;
}

static isc_db_handle * make_fb_connection(const char * host, const char * port, const char * db_name, 
								const char * user, const char * passwd)
{
	char dpb_buffer[256], *dpb;
	short dpb_length; 
    ISC_STATUS_ARRAY        status;                     /* status vector */

	/* Filling buffer of username and password */ 
	dpb = dpb_buffer; 
	*dpb++ = isc_dpb_version1; 
	*dpb++ = isc_dpb_num_buffers; 
	*dpb++ = 1; 
	*dpb++ = 90; 

	*dpb++ = isc_dpb_user_name;
	*dpb++ = strlen(user);
	memcpy(dpb, user, strlen(user));
	dpb += strlen(user);

	*dpb++ = isc_dpb_password;
	*dpb++ = strlen(passwd);
	memcpy(dpb, passwd, strlen(passwd));
	dpb += strlen(passwd);
	
	dpb_length = dpb - dpb_buffer;

	/* Create dbh address string */

	size_t db_addr_size = strlen(host) + strlen(":") + strlen(db_name) + 1;
	char *db_addr = malloc(db_addr_size);
	if(!db_addr)
	{
		log_wr(CLOG, "Can't allocate memory for FireBird database connect string: '%s'", strerror(errno));
		return FB_TYPE_UNCONVERT(NULL);
	}

	*db_addr = '\0';

	snprintf(db_addr, db_addr_size, "%s:%s", host, db_name);

    isc_db_handle *dbhp = malloc(sizeof(isc_db_handle*));
	if(!dbhp)
	{
		log_wr(CLOG, "Can't allocate memory for database handler: '%s'", strerror(errno));
		exit(error_memory);
	}
	*dbhp = FB_TYPE_UNCONVERT(NULL);	/* database handle */

	while(1)
	{
		log_wr(DLOG, "Connecting to FireBird DB '%s' on server '%s:%d' as user '%s'.",
				db_name, host, port, user);

		if (isc_attach_database(status, 0, db_addr, dbhp, dpb_length, dpb_buffer))
		{
			log_wr(ELOG, "Can't connect to FireBird server.");
			isc_print_status(status);

		}
		else
		{
			log_wr(DLOG, "Connected to FireBird DB.");
			return dbhp;
		}

		if(server_shutdown_flag)
		{
			log_wr(NLOG, "Shuting down FireBird thread.");
			return NULL;
		}

		log_wr(ELOG, "Failed connect to FireBird database. Sleeping %d seconds before reconnect.", DB_RECONNECT_TIME);

		sleep(DB_RECONNECT_TIME);
	}

	return NULL;
}

void * query_fbsql(void * _dbh, const char *sql_st, int st_len)
{
	isc_db_handle			**dbhpp = _dbh;
	isc_db_handle			*dbhp = *dbhpp;
	isc_db_handle			dbh = (isc_db_handle) FB_TYPE_UNCONVERT(*dbhp);

    ISC_STATUS_ARRAY        status;								/* status vector */
    isc_tr_handle           trans = FB_TYPE_UNCONVERT(NULL);    /* transaction handle */
    isc_stmt_handle         stmt = FB_TYPE_UNCONVERT(NULL);                /* statement handle */
    XSQLDA  *               sqlda;
	short					flags[4];
    long                    fetch_stat;

	query_result_t * out_result = NULL;

    if (isc_start_transaction(status, &trans, 1, &dbh, 0, NULL))
    {
		log_wr(ELOG, "Can't start FireBird transaction. Trying to reconnect.");
		ISC_STATUS_ARRAY        status;                     /* status vector */
		isc_detach_database(status, &dbh);

		*dbhpp = make_fb_connection(st_host, st_port, st_db_name, st_user, st_passwd);
		
		return NULL;
    }
    
    /* Allocate an output SQLDA. */
    sqlda = (XSQLDA *) malloc(XSQLDA_LENGTH(3));
    sqlda->sqln = 3;
    sqlda->sqld = 3;
    sqlda->version = 1;

    /* Allocate a statement. */
    if (isc_dsql_allocate_statement(status, &dbh, &stmt))
    {
		log_wr(ELOG, "Can't allocate FireBird SQL statement.");
		isc_print_status(status);
		return NULL;
    }

    /* Prepare the statement. */
    if (isc_dsql_prepare(status, &trans, &stmt, 0, sql_st, 3, sqlda))
    {
		log_wr(ELOG, "Can't prepare FireBird SQL statement.");
		isc_print_status(status);
		return NULL;
    }
    
	short					code;
	short					type;
	SQL_VARCHAR(1024)		value;

    sqlda->sqlvar[0].sqldata = (char *)&code;
    sqlda->sqlvar[0].sqltype = SQL_SHORT + 1;
    sqlda->sqlvar[0].sqlind  = &flags[0];

    sqlda->sqlvar[1].sqldata = (char *)&type;
    sqlda->sqlvar[1].sqltype = SQL_SHORT + 1;
    sqlda->sqlvar[1].sqlind  = &flags[1];

    sqlda->sqlvar[2].sqldata = (char *)&value;
    sqlda->sqlvar[2].sqltype = SQL_VARYING + 1;
    sqlda->sqlvar[2].sqlind  = &flags[2];


    /* Execute the statement. */
    if (isc_dsql_execute(status, &trans, &stmt, 3, NULL))
    {
		log_wr(ELOG, "Can't execute SQL statement on FireBird DB.");
		isc_print_status(status);
		return NULL;
    }

	/* Create out result structure */
	out_result = calloc(1, sizeof(query_result_t));
	if(!out_result)
	{
		log_wr(CLOG, "Can't allocate memory for store query result: '%s'", strerror(errno));
		exit(error_memory);
	}
	size_t rows_allocated = 10;
	out_result->items = malloc(sizeof(result_item_t) * rows_allocated);
	if(!out_result->items)
	{
		log_wr(CLOG, "Can't allocate memory for store query result nodes: '%s'", strerror(errno));
		exit(error_memory);
	}


	/* Fetch result */
	int row_num;
    for(row_num = 0; (fetch_stat = isc_dsql_fetch(status, &stmt, 3, sqlda)) == 0; ++row_num)
    {
		if(row_num == rows_allocated)	/* Realloc memory for out data */
		{
			rows_allocated *= 2;
			out_result->items = realloc(out_result->items, sizeof(out_result->items[0]) * rows_allocated);
			if(!out_result->items)
			{
				log_wr(CLOG, "Can't reallocate memory for store result: '%s'", strerror(errno));
				exit(error_memory);
			}
		}
		value.vary_string[value.vary_length] = '\0';

		out_result->items[row_num].code = code;
		out_result->items[row_num].type = type;
		out_result->items[row_num].data = strdup(value.vary_string);
		if(!out_result->items[row_num].data)
		{
			log_wr(CLOG, "Can't allocate memory for store query result data: '%s'", strerror(errno));
			exit(error_memory);
		}
    }

    if (fetch_stat != 100L)
		log_wr(WLOG, "Unsuccefull fetch SQL result.");

	/* Truncate unusable memory */
	if(row_num < rows_allocated)
	{
		out_result->items = realloc(out_result->items, sizeof(out_result->items[0]) * (row_num + 1));
		if(!out_result->items)
		{
			log_wr(CLOG, "Can't realloc memory for truncate result: '%s'", strerror(errno));
			exit(error_memory);
		}
	}

	out_result->count = row_num;

    /* Free statement handle. */
    if (isc_dsql_free_statement(status, &stmt, DSQL_close))
    {
		log_wr(CLOG, "Can't free SQL statement.");
		exit(error_abnormal);
    }

    if (isc_commit_transaction(status, &trans))
    {
		log_wr(CLOG, "Can't commit FireBird transaction.");
		exit(error_abnormal);
    }

    free(sqlda);

	return out_result;
}

void disconnect_from_fbsql(void * _dbh)
{
	isc_db_handle dbh = FB_TYPE_UNCONVERT(_dbh);

	log_wr(NLOG, "Disconnecting from FireBird database.");
	/* TODO */
    ISC_STATUS_ARRAY        status;                     /* status vector */
    isc_detach_database(status, &dbh);
	return; 
}


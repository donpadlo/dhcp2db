/*
 * db_my_client.c
 *
 *  Created at: 27.08.2009
 *      Author: Chebotarev Roman
 */


#include "config.h" 

#include "common_includes.h"
#include "db2dhcp_types.h"
#include "log.h"
#include "dhcp_queue.h"

#ifdef _WIN32
#include <mysql.h>
#else
#include CONFIG_MYSQL_H
#endif

extern inline void free_query_result(query_result_t * result);
extern int server_shutdown_flag;

void * connect_to_db_mysql(const char * host, const char * user,
		const char * passwd,	const char * db_name, uint16_t port)
{
	MYSQL * my = mysql_init(NULL);
	my->reconnect = 1;

	while(1)
	{
		if(!my)
		{
			log_wr(CLOG, "Can't create MySQL struct.", -1);
			return NULL;
		}

		log_wr(DLOG, "Connecting to MySQL DB '%s' on server '%s:%d' as user '%s'.",
				db_name, host, port, user);

		if(mysql_real_connect(my, host, user, passwd, db_name, port, 0, 
			CLIENT_MULTI_STATEMENTS /* Flag which allow multiple statement execution */ ))
		{
			log_wr(NLOG, "Connected to MySQL server.");
			return my;
		}
		log_wr(ELOG, "Failed connect to MySQL database: %s. Sleeping %d seconds before reconnect.",
			mysql_error(my), DB_RECONNECT_TIME);

		if(server_shutdown_flag)
		{
			log_wr(NLOG, "Shuting down MySQL thread.");
			return NULL;
		}

		sleep(DB_RECONNECT_TIME);
	}

	return NULL;
}

void * query_mysql(void * dbh, const char *sql_st, int st_len)
{
	MYSQL * my = dbh;

	int status = mysql_real_query(my, sql_st, st_len);
	if(status)
	{
		log_wr(ELOG, "Error executing SQL statement: \"%s\"", mysql_error(my));
		return NULL;
	}

	MYSQL_RES *result = 0;
	query_result_t * out_result = NULL;
	int i;
	unsigned long *lengths;
	MYSQL_ROW row;

	out_result = calloc(1, sizeof(query_result_t));
	if(!out_result)
	{
		log_wr(CLOG, "Can't allocate memory for store query result!");
		goto _fail;
	}

	do 
	{
		result = mysql_store_result(my);

		if(!result)
		{
			if (mysql_field_count(my) == 0)	/* All right. E.g. - no suitable data or UPDATE was executed.*/
				goto _next_statement_result;
			else  /* Error occurred */
			{
				log_wr(ELOG, "Could not retrieve result set.");
				goto _fail;
			}
		}

		log_wr(DLOG, "Fetched "I64U" rows, %u fields from DB.", result->row_count, result->field_count);
		if(result->field_count < VALUE_INDEX + 1)
		{
			log_wr(ELOG, "Too few fields in fetched result. Check you request!");
			goto _fail;
		}

		if(result->row_count == 0)	/* Empty result. Go to next statement result */
			goto _next_statement_result;

		/* Realloc memory for next statement result */
		out_result->items = realloc(out_result->items, 
				out_result->count * sizeof(result_item_t) +		/* Current size */
				sizeof(result_item_t) * result->row_count);		/* Next statement result size */

		if(!out_result->items)
		{
			log_wr(CLOG, "Can't allocate memory for store query result nodes!");
			goto _fail;
		}

		for(i = out_result->count; (row = mysql_fetch_row(result)); ++i)
		{
			lengths = mysql_fetch_lengths(result);
			/* Fields order: code, value */
			out_result->items[i].len = lengths[VALUE_INDEX];
			out_result->items[i].code = atoi(row[CODE_INDEX]);
			out_result->items[i].type = atoi(row[TYPE_INDEX]);
			out_result->items[i].data = malloc(lengths[VALUE_INDEX] +
											  (out_result->items[i].type == BINARY ? 0 : 1));

			if(!out_result->items[i].data)
			{
				log_wr(CLOG, "Can't allocate memory for store data (code %d, length %d).",
						row[CODE_INDEX], lengths[VALUE_INDEX]);
				goto _fail;
			}
			memcpy(out_result->items[i].data, row[VALUE_INDEX], lengths[VALUE_INDEX]);
			if(out_result->items[i].type != BINARY)	/* Not binary data must be zero-terminated */
				((char*)(out_result->items[i].data))[out_result->items[i].len] = '\0';
		}

		out_result->count = i;

_next_statement_result:
		mysql_free_result(result);

		/* Go to next query result if exist */
		if ((status = mysql_next_result(my)) > 0)
			log_wr(ELOG, "Invalid multiple statement found.");
	}
	while(status == 0);

	return out_result;

_fail:

	if(result)
		mysql_free_result(result);
	if(out_result)
		free(out_result);

	return NULL;
}

void disconnect_from_mysql(void * dbm)
{
	log_wr(NLOG, "Disconnecting from MySQL database.");
	mysql_close((MYSQL*) dbm);

	return; 
}

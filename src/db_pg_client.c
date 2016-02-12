/*
 * db_pg_client.c
 *
 *  Created at: 27.08.2009
 *      Author: Chebotarev Roman
 */

#include "config.h" 

#include <pthread.h>
#include "common_includes.h"
#include "db2dhcp_types.h"
#include "db_pg_client.h"
#include "log.h"

#include CONFIG_LIBPQ_FE_H

/* TODO Нужна cleanup функция */

extern inline void free_query_result(query_result_t * result);
extern int server_shutdown_flag;

static char * st_host;
static char * st_user;
static char * st_passwd;
static char * st_db_name;
static char * st_port;

static PGconn * make_pg_connection(const char * host, const char * port, const char * db_name, 
								const char * user, const char * passwd);

void * connect_to_db_pgsql(const char * host, const char * user,
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
		return NULL;
	}

	PGconn ** pg_pptr = malloc(sizeof(PGconn *));

	if(!pg_pptr)
	{
		log_wr(CLOG, "Can't allocate memory for PG connection pointer: '%s'", strerror(errno));
		return NULL;
	}


	*pg_pptr = make_pg_connection(host, port_str, db_name, user, passwd);

	return pg_pptr;
}

static PGconn * make_pg_connection(const char * host, const char * port, const char * db_name, 
								const char * user, const char * passwd)
{
	PGconn * pg;
	while(1)
	{
		pg = PQsetdbLogin(host, port, NULL, NULL, db_name, user, passwd);

		if (PQstatus(pg) != CONNECTION_OK)
		{
			log_wr(ELOG, "Connection to database failed: '%s'. Trying to reconnect after %d seconds.", 
				PQerrorMessage(pg), DB_RECONNECT_TIME);
			sleep(DB_RECONNECT_TIME);
			if(server_shutdown_flag)
			{
				log_wr(NLOG, "Shuting down PostgreSQL thread.");
				return NULL;
			}
		}
		else
		{
			log_wr(NLOG, "Connected to PostgreSQL server.");
			return pg;
		}
	}

	return NULL;
}

void * query_pgsql(void * dbh, const char *sql_st, int st_len)
{
	PGresult   *res;
	PGconn ** pg_pptr = dbh;
	PGconn * pg = *pg_pptr;

	res = PQexec(pg, sql_st);
	ExecStatusType status = PQresultStatus(res);
	if (status != PGRES_TUPLES_OK)
	{
		PQclear(res);
		log_wr(ELOG, "Error executing SQL statement: '%s'", PQerrorMessage(pg));

		if(status == PGRES_FATAL_ERROR)
		{
			PQfinish(pg);
			log_wr(WLOG, "Trying reconnect to server...");
			*pg_pptr = make_pg_connection(st_host, st_port, st_db_name, st_user, st_passwd);
		}

		return NULL;
	}

	int field_count = PQnfields(res);
	int row_count = PQntuples(res);

	if(field_count < VALUE_INDEX + 1)
	{
		log_wr(ELOG, "Too few fields in fetched result. Check you request!");
		return NULL;
	}
	
	query_result_t *out_result = calloc(1, sizeof(query_result_t));
	if(!out_result)
	{
		log_wr(CLOG, "Can't allocate memory for store query result!");
		PQclear(res);
		return NULL;
	}

	out_result->items = malloc(sizeof(result_item_t) * row_count);
	if(!out_result->items)
	{
		log_wr(CLOG, "Can't allocate memory for store query result nodes!");
		PQclear(res);
		free(out_result);
		return NULL;
	}

	int row_num;
	size_t data_len;
	for(row_num = 0; row_num < row_count; ++row_num)
	{
		/* Fields order: code, value */
		data_len = PQgetlength(res, row_num, VALUE_INDEX);
		out_result->items[row_num].len = data_len;
		out_result->items[row_num].code = atoi(PQgetvalue(res, row_num, CODE_INDEX));
		out_result->items[row_num].type = atoi(PQgetvalue(res, row_num, TYPE_INDEX));
		out_result->items[row_num].data = malloc(data_len +
		                                  (out_result->items[row_num].type == BINARY ? 0 : 1));

		if(!out_result->items[row_num].data)
		{
			log_wr(CLOG, "Can't allocate memory for store data (code %d, length %d).",
					PQgetvalue(res, row_num, CODE_INDEX), data_len);
			out_result->count = row_num;
			free_query_result(out_result);
			PQclear(res);
			return NULL;
		}
		memcpy(out_result->items[row_num].data, PQgetvalue(res, row_num, VALUE_INDEX), data_len);
		if(out_result->items[row_num].type != BINARY)	/* Not binary data must be zero-terminated */
			((char*)(out_result->items[row_num].data))[data_len] = '\0';
	}

	out_result->count = row_num;
	PQclear(res);

	return out_result;
}

void disconnect_from_pgsql(void * dbh)
{
	log_wr(NLOG, "Disconnecting from PostgreSQL database.");
	PQfinish(*(PGconn**) dbh);

	return; 
}


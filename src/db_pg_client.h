/*
 * db_pg_client.h
 *
 *  Created at: 27.08.2009
 *      Author: Chebotarev Roman
 */

#ifndef DB_PG_CLIENT_H_
#define DB_PG_CLIENT_H_

void * connect_to_db_pgsql(const char * host, const char * user,
		const char * passwd,	const char * db_name, uint16_t port);
void * query_pgsql(void * dbh, const char *sql_st, int st_len);
void disconnect_from_pgsql(void * dbh);

#endif /* DB_PG_CLIENT_H_ */

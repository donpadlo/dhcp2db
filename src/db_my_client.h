/*
 * db_my_client.h
 *
 *  Created at: 27.08.2009
 *      Author: Chebotarev Roman
 */

#ifndef DB_MY_CLIENT_H_
#define DB_MY_CLIENT_H_

void * connect_to_db_mysql(const char * host, const char * user,
		const char * passwd,	const char * db_name, uint16_t port);
void * query_mysql(void * dbh, const char *sql_st, int st_len);
void disconnect_from_mysql(void * dbh);

#endif /* DB_MY_CLIENT_H_ */

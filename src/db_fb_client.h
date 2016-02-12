/*
 * db_fb_client.h
 *
 *  Created at: 19.05.2011
 *      Author: Chebotarev Roman
 */

#ifndef DB_FB_CLIENT_H_
#define DB_FB_CLIENT_H_

void * connect_to_db_fbsql(const char * host, const char * user,
		const char * passwd,	const char * db_name, uint16_t port);
void * query_fbsql(void * dbh, const char *sql_st, int st_len);
void disconnect_from_fbsql(void * dbh);

#if defined(_LP64) || defined(__LP64__) || defined(__arch64__) || defined(_WIN64)	/* FireBird - is piece of ... */
		#define FB_TYPE_CONVERT(x) (void*)(unsigned long int)x
		#define FB_TYPE_UNCONVERT(x)	(unsigned int)(long long int)x
#else
		#define FB_TYPE_CONVERT(x)		x
		#define FB_TYPE_UNCONVERT(x)	x
#endif

#endif /* DB_FB_CLIENT_H_ */


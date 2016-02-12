/*
 * log.h
 *
 *  Created at: 21.02.2010
 *      Author: Chebotarev Roman
 */

#ifndef LOG_H_
#define LOG_H_

#define LOG_DEBUG_FLAG	0x01
#define	LOG_STDOUT_FLAG	0x02

#include <stdint.h>
#include <unistd.h>

typedef enum log_levels
{
	CLOG,	/* Critical		*/
	ELOG,	/* Error		*/
	WLOG,	/* Warning		*/
	ILOG,	/* Information	*/
	NLOG,	/* Normal		*/
	DLOG	/* Debug		*/
}LLEVEL;

extern int log_init(const char * file_name, uint32_t flags, pid_t uid);
extern int log_close(void);
int log_wr(LLEVEL level, const char * fmt, ...);
extern int log_fileno(void);
extern void log_reopen(void);

#endif /* LOG_H_ */

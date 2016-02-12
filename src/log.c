/*
 * log.c
 *
 *  Created at: 21.02.2010
 *      Author: Chebotarev Roman
 */

#include <time.h>
#include <syslog.h>

#include "db2dhcp.h"
#include "common_includes.h"
#include "db2dhcp_types.h"
#include "log.h"

static char * log_file_name;
static FILE * logfile;
static int debug_out;
static int log_stdout;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

inline int log_init(const char * file_name, uint32_t flags, pid_t uid)
{
	debug_out = flags & LOG_DEBUG_FLAG;
	log_stdout = flags & LOG_STDOUT_FLAG;

	logfile = fopen(file_name, "a");
	if(logfile)
	{
#ifndef _WIN32
		if(uid)
		{
			if(chown(file_name, uid, getgid()))
			{
				fprintf(stderr, "Can't chown log file '%s' to uid %u: '%s'", 
					file_name, uid, strerror(errno));
				return FAIL;
			}
		}
#endif
		log_file_name = (char*) file_name;
		return OK;
	}

	fprintf(stderr, "Can't open log file: %s\n", strerror(errno));

	return FAIL;
}

inline int log_close(void)
{
	return fclose(logfile);
}

int log_wr(LLEVEL level, const char * fmt, ...)
{
	if(level == DLOG && !debug_out)
		return 0;

	static const char * prefixes[] = 
	{
		"CRITICAL: ",
		"ERROR: ",
		"WARN: ",
		"INFO: ",
		"",	/* Normally - without prefix */
		"DEBUG: "
	};

	char str_timestamp[sizeof("YYYY-MM-DD HH:mm:ss")];
	time_t tp = time(0);
	struct tm * timestamp = localtime(&tp);
	if(!timestamp)
	{
		fprintf(stderr, "Can't get timestamp! Using empty string.\n");
		str_timestamp[0] = '\0';
	}
	else
		snprintf(str_timestamp, sizeof(str_timestamp), "%04d-%02d-%02d %02d:%02d:%02d",
				timestamp->tm_year + 1900, timestamp->tm_mon + 1, timestamp->tm_mday,
				timestamp->tm_hour, timestamp->tm_min, timestamp->tm_sec);

	va_list ap;
	va_start(ap, fmt);


	pthread_mutex_lock(&log_mutex);		/* Lock mutex to avoid overlap output */

	unsigned long int pid = getpid();
	unsigned long int th_id = (unsigned long int)THREAD_ID();
	if(log_stdout)
	{
		va_list ap;
		va_start(ap, fmt);
		fprintf(stderr, "%s [%lu:%lu] %s", str_timestamp, pid, th_id, prefixes[level]);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		va_end(ap);
	}
	fprintf(logfile, "%s [%lu:%lu] %s", str_timestamp, pid, th_id, prefixes[level]);
	int ret = vfprintf(logfile, fmt, ap);
	fprintf(logfile, "\n");
	fflush(logfile);

	pthread_mutex_unlock(&log_mutex);

	va_end(ap);
	return ret;
}

inline void log_reopen(void)
{
	log_wr(ILOG, "Reopening log file '%s'", log_file_name);
	if(fclose(logfile))
	{
		log_wr(CLOG, "Can't close log file: '%s'", log_file_name);
		openlog(PROG_NAME, LOG_PID, LOG_DAEMON);
		syslog(LOG_ERR, "Can't close log file '%s': '%s'", log_file_name, strerror(errno));
		closelog();
		exit(error_abnormal);
	}

	logfile = fopen(log_file_name, "a");
	if(logfile)
	{
		log_wr(ILOG, "Log file '%s' reopened.", log_file_name);
		return;
	}

	fprintf(stderr, "Can't reopen log file '%s': '%s'\n", log_file_name, strerror(errno));

	/* If error open - logging into syslog */
	openlog(PROG_NAME, LOG_PID, LOG_DAEMON);
	syslog(LOG_ERR, "Can't reopen log file '%s': '%s'", log_file_name, strerror(errno));
	closelog();
	abort();
}

inline int log_fileno(void)
{
	return fileno(logfile);
}


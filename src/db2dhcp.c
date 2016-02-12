/*
 ============================================================================
 Name        : db2dhcp.c
 Author      : Chebotarev Roman
 Version     : 0.1
 Copyright   : GPLv2
 Description : DHCP server + SQL database
 ============================================================================
 */

#include "common_includes.h"
#include "db2dhcp_types.h"
#include "log.h"
#include "dhcp_queue.h"
#include "configuration.h"
#include "requests_handling.h"
#include "dhcp_process.h"
#include "misc_functions.h"
#include "net_functions.h"
#include "dhcp_cache.h"
#include "db2dhcp.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


int server_shutdown_flag;

/* TODO Нужно сделать смену uid в *nix системах если таковой задан в конфиге,
	а лучше - обязательную смену пользователя */

/* TODO Поставить sighandler'ы для нормального завершения приложения по INT/TERM */

/* TODO Резервирование БД */

/*

На самом деле память тут ни при чём - просто невозможно добавить ноду из-за переполнения.

2011-03-11 03:27:34 [35049:1096853760] ERROR: Queue 'DHCP requests' is overflow. Max size reached: 100 
2011-03-11 03:27:34 [35049:1096853760] CRITICAL: Can't allocate memory for gracefull shutting down server: 'Unknown error: 0'

*/
/* Going process to daemon mode */
static void daemonize(void);
static void sig_handler(int signal);
/* Server shutdown handler */
inline static void server_shutdown(void);

int main(int argc, char * argv[])
{
	server_configuration config;
	bzero(&config, sizeof(config));

	if(!network_subsystem_init())
	{
		fprintf(stderr, "Network subsystem init failed.\n");
		return error_network_subsystem;
	}

	if(!read_configuration(argc, argv, &config))
	{
		fprintf(stderr, PROG_NAME ": configuration error! Exit.\n");
		return error_config;
	}

	if(config.discover)
		interfaces_discover(0);

	if(config.print_header_offsets)
	{
		print_dhcp_header_offsets();
		return 0;
	}

	if(!log_init(config.log_file_name,
			(config.debug_mode ? LOG_DEBUG_FLAG : 0) |
			(config.log_stdout ? LOG_STDOUT_FLAG : 0),
			config.uid)
		)
	{
		fprintf(stderr, "Can't open log file.\n");
		return error_log;
	}

	log_wr(ILOG, "Program " PROG_NAME " " PROG_VERS " " PROG_DESC " started.");

	struct sigaction sig_handler_s;
	sig_handler_s.sa_handler = sig_handler;
	sigemptyset(&sig_handler_s.sa_mask);
	sig_handler_s.sa_flags = 0;

	if(config.daemon)
		daemonize();

	/* Init DHCP cache */
	if(config.cache_ttl && !dhcp_cache_init(config.cache_ttl))
	{
		log_wr(CLOG, "Can't init DHCP cache. Exit.");
		return error_abnormal;
	}

	/* STARTING DATABASE CLIENTS */

	/* Create array of childen threads */
	request_handler_thread_t **handler_threads =
		(request_handler_thread_t **) malloc(sizeof(request_handler_thread_t *) * config.db_clients_count);

	CHECK_VALUE(handler_threads, "Can't allocate memory for array of children threads for connecting to DB.",
		error_memory);

	/* Create DHCP messages queue */
	config.dhcp_queue = dhcp_queue_create("DHCP requests", YES, DEFAULT_QUEUE_MAX_SIZE);
	CHECK_VALUE(config.dhcp_queue, "Can't create DHCP queue.", error_queue_init);

	/* Running DB clients */
	CHECK_VALUE(run_requests_handlers(handler_threads, &config), "", error_run_db_clients);

	/* STARTING DHCP PROCESSES  */
	dhcp_proc_thread_t **dhcp_threads =
		(dhcp_proc_thread_t**) malloc(sizeof(dhcp_proc_thread_t *) * config.if_count);

	CHECK_VALUE(dhcp_threads, "Can't allocate memory for array of children threads for "
			"processing DHCP clients.", error_run_dhcp_procs);

	CHECK_VALUE(run_dhcp_threads(dhcp_threads, &config, handler_threads), "", error_run_dhcp_procs);

	/* Set signal handlers */
    if( sigaction(SIGINT, &sig_handler_s, NULL) ||
        sigaction(SIGTERM, &sig_handler_s, NULL) ||
        sigaction(SIGUSR1, &sig_handler_s, NULL))
    {
		log_wr(CLOG, "Can't set signal handlers: '%s'", strerror(errno));
        return error_abnormal;
    }

#ifndef _WIN32
	if(config.uid)
	{
		log_wr(DLOG, "Set effective and real user ID to %u.", config.uid);
		if(setreuid(config.uid, config.uid))
		{
			log_wr(CLOG, "Can't execute setreuid(%u): '%s'", config.uid, strerror(errno));
			return 0;
		}
	}
	else
		log_wr(WLOG, "Running with uid 0 - it is not safe!!! Use configuration directive 'User' for set uid.");
#endif

	int i;
	for(i = 0; i < config.if_count; ++i)
		pthread_join(dhcp_threads[i]->thread_id, 0);

	log_wr(ILOG, "All DHCP threads finished");

	for(i = 0; i < config.db_clients_count; ++i)
		pthread_join(handler_threads[i]->thread_id, 0);

	log_wr(ILOG, "All DB threads finished.");

	/* Cleaning up */
	/* TODO 30 Need gracefull cleanup database connections and free all allocated memory */
	log_wr(ILOG, "Program exited.");
	log_close();

	return EXIT_SUCCESS;
}

static void daemonize(void)
{
#ifndef _WIN32
	log_wr(DLOG, "Go to daemon mode...");

	pid_t pid;

	pid = fork();

	if(pid == -1)
	{
		log_wr(CLOG, "Can't fork: '%s'", strerror(errno));
		exit(error_abnormal);
	}

	if(pid) /* I'm a parent */
	{
		log_wr(DLOG, "Fork to child %d, parent exit now.", pid);
		exit(0);
	}

	if(setsid() == (pid_t) -1)
	{
		log_wr(CLOG, "Can't setsid(): '%s'", strerror(errno));
		exit(error_abnormal);
	}

	if(signal(SIGHUP, SIG_IGN) == SIG_ERR)
	{
		log_wr(CLOG, "Can't set SIG_IGN on SIGHUP: '%s'", strerror(errno));
		exit(error_abnormal);
	}

	pid = fork();

	if(pid == -1)
	{
		log_wr(CLOG, "Can't fork(2): '%s'", strerror(errno));
		exit(error_abnormal);
	}

	if(pid) /* I'm a child->parent */
	{
		log_wr(DLOG, "Fork after setsid to child %d, parent exit now.", pid);
		exit(0);
	}

	if(chdir("/") == -1)
	{
		log_wr(CLOG, "Can't chdirectory to '/': '%s'", strerror(errno));
		exit(error_abnormal);
	}

	umask(0);

	int i, maxfd_p1 = getdtablesize(), logfd = log_fileno();

	for(i = 0; i < maxfd_p1; ++i)
		if(i != logfd)
			close(i);

	/* Reopen FD 0,1,2 for std functions */
	if(open("/dev/null", O_RDONLY) == -1)
	{
		log_wr(CLOG, "Can't open /dev/null as stdin for read: '%s'", strerror(errno));
		exit(error_abnormal);
	}

	if(open("/dev/null", O_WRONLY) == -1)
	{
		log_wr(CLOG, "Can't open /dev/null as stdout for write: '%s'", strerror(errno));
		exit(error_abnormal);
	}

	if(open("/dev/null", O_WRONLY) == -1)
	{
		log_wr(CLOG, "Can't open /dev/null as stderr for write: '%s'", strerror(errno));
		exit(error_abnormal);
	}

	log_wr(DLOG, "Program enter into daemon mode succefull.");
#else	/* _WIN32 defined */
	log_wr(CLOG, "Can't work under win32 as daemon. Sorry. :(");
	exit(error_abnormal);
#endif	/* ifndef _WIN32 */

	return;
}

static void sig_handler(int signal)
{
	if(server_shutdown_flag)	/* Already shutting down */
		return;

	switch(signal)
	{
		case SIGINT:
		case SIGTERM:
			log_wr(ILOG, "Terminating by signal %d.", signal);
			server_shutdown();
			break;
		case SIGUSR1:
			log_reopen();
			break;
		default:
			log_wr(ELOG, "Process terminated with unexpected signal %d.", signal);
			server_shutdown();
			break;
	}
}

inline static void server_shutdown(void)
{
	log_wr(ILOG, "Shuting down server - wait for all child threads finished...");

	server_shutdown_flag = 1;
}


/*
 * common_includes.h
 *
 *  Created at: 27.08.2009
 *      Author: Chebotarev Roman
 */

#ifndef COMMON_INCLUDES_H_
#define COMMON_INCLUDES_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>               /* if this gives you an error try pcap/pcap.h */
#include <pthread.h>
#include <stdarg.h>

#ifndef _WIN32

#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#if	__linux__ || __FreeBSD__

#include <sys/ioctl.h>

#define		MAX_NETDEV_NAME_SIZE	IFNAMSIZ
#define		MAX_HOSTNAME_LEN		64

#endif	/* __linux__ */

#define		NPF_PREFIX			""
#define		I64U				"%llu"
#define		THREAD_ID()			pthread_self()

#if __FreeBSD__

#include <net/if_dl.h>

#endif	/* __FreeBSD__ */ 

#else	/* End non WIN32 includes and definitions */

#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>

#define		bzero(x, y)			ZeroMemory(x, y);
#define		sleep(x)			Sleep(1000 * x)
#define		getpid()			((unsigned long int) GetCurrentProcessId())
#define		THREAD_ID()			((unsigned long int) pthread_self().p)
#define		pcap_inject			pcap_sendpacket
#define		NPF_PREFIX			"\\Device\\NPF_"
#define		NPF_PREFIX_LEN		strlen(NPF_PREFIX)
#define		I64U				"%I64u"
#define		MAX_NETDEV_NAME_SIZE	(MAX_ADAPTER_NAME_LENGTH + 4)	/* Why "+ 4"? I'm don't know.
	See: http://msdn.microsoft.com/en-us/library/aa366062(VS.85).aspx , possible field alignment? */

#endif	/* _WIN32 */

#define CHECK_VALUE(p, msg, ret) \
		if(!(p)) \
		{ \
			if(*msg) \
				log_wr(CLOG, "%s", msg); \
			return ret; \
		}

#define OK		1
#define FAIL	0
#define YES		1
#define	NO		0

//#define OLD_CACHE


#endif /* COMMON_INCLUDES_H_ */

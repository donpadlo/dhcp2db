sbin_PROGRAMS = db2dhcp

db2dhcp_SOURCES = \
	dhcp_queue.c \
	requests_handling.c \
	configuration.c \
	log.c \
	misc_functions.c \
	db2dhcp.c \
	net_functions.c \
	dhcp_process.c \
	dhcp_cache.c \
	rbtree.c \
	rbtree_misc.c \
	rbtree_stack.c

noinst_HEADERS = common_includes.h \
	db2dhcp.h \
	dhcp.h \
	dhcp_queue.h \
	misc_functions.h \
	net.h \
	configuration.h \
	db2dhcp_types.h \
	dhcp_process.h \
	log.h \
	net_functions.h \
	requests_handling.h \
	dhcp_cache.h \
	rbtree.h \
	rbtree_misc.h \
	rbtree_stack.h

db2dhcp_LDADD = -lpcap
db2dhcp_CFLAGS = -Wall -Werror -pthread

if POSTGRESQL

db2dhcp_SOURCES += db_pg_client.c
noinst_HEADERS += db_pg_client.h
db2dhcp_LDADD += -lpq

endif

if MYSQL

db2dhcp_SOURCES += db_my_client.c
noinst_HEADERS += db_my_client.h
db2dhcp_LDADD += -lmysqlclient

endif

if FIREBIRD

db2dhcp_SOURCES += db_fb_client.c
noinst_HEADERS += db_fb_client.h
db2dhcp_LDADD += -lfbclient

endif


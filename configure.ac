#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(DB-to-DHCP-server, 0.1.a.10, roma@ultranet.ru)
AC_CANONICAL_TARGET
AC_CONFIG_SRCDIR([src/db2dhcp_types.h])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE(db2dhcp, "0.1.a.10")
# Checks for programs.
AC_LANG_C
AC_PROG_CC
AM_PROG_LIBTOOL
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([pcap], [main])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([stdint.h stdio.h stdlib.h unistd.h errno.h string.h signal.h time.h arpa/inet.h \
					sys/wait.h sys/socket.h netinet/in.h], 
				[], [AC_MSG_ERROR([You need C devel package installed])])
AC_CHECK_HEADERS([pcap.h], [], [AC_MSG_ERROR([You need libpcap devel package installed])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for network library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([bzero inet_ntoa memset pcap_open_live pcap_inject pcap_datalink pcap_setnonblock \
				pcap_close pcap_compile pcap_setfilter pcap_freecode pcap_findalldevs pcap_freealldevs \
				pcap_perror pcap_dispatch ],
	[], [AC_MSG_ERROR([You need libpcap devel package installed])])

AC_CONFIG_FILES([Makefile src/Makefile])

AC_MSG_CHECKING([whether to build Postgresql support])
AC_ARG_ENABLE([postgresql],
		AC_HELP_STRING([--enable-postgresql],
			[enable PostgreSQL support]),
		CONFIG_USE_POSTGRESQL=$enableval,
		CONFIG_USE_POSTGRESQL=no)

if test x$CONFIG_USE_POSTGRESQL = xyes
then
	AC_MSG_RESULT([yes])
	AC_DEFINE_UNQUOTED([CONFIG_USE_POSTGRESQL], [1], [whether need use PostgreSQL])
	AC_CHECK_HEADERS([libpq-fe.h], [pgheader_found=yes; 
		AC_DEFINE_UNQUOTED([CONFIG_LIBPQ_FE_H], [<libpq-fe.h>], [path to PostgreSQL header])])
	AC_CHECK_HEADERS([postgresql/libpq-fe.h], [pgheader_found=yes; 
		AC_DEFINE_UNQUOTED([CONFIG_LIBPQ_FE_H], [<postgresql/libpq-fe.h>], [path to PostgreSQL header])])
	AS_IF([test "x$pgheader_found" != "xyes"], [AC_MSG_ERROR([You need PostgreSQL devel package installed])])
else
	AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([whether to build MySQL support])
AC_ARG_ENABLE([mysql],
		AC_HELP_STRING([--enable-mysql],
			[enable MySQL support]),
		CONFIG_USE_MYSQL=$enableval,
		CONFIG_USE_MYSQL=no)

if test x$CONFIG_USE_MYSQL = xyes
then
	AC_MSG_RESULT([yes])
	AC_DEFINE_UNQUOTED([CONFIG_USE_MYSQL], [1], [whether need use MySQL])
	AC_CHECK_HEADERS([mysql.h], [mysqlheader_found=yes; AC_DEFINE_UNQUOTED([CONFIG_MYSQL_H], [<mysql.h>], [path to MySQL header])])
	AC_CHECK_HEADERS([mysql/mysql.h], [mysqlheader_found=yes; AC_DEFINE_UNQUOTED([CONFIG_MYSQL_H], [<mysql/mysql.h>], [path to MySQL header])])
	AS_IF([test "x$mysqlheader_found" != "xyes"], [AC_MSG_ERROR([You need MySQL devel package installed])])
else
	AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([whether to build FireBird support])
AC_ARG_ENABLE([firebird],
		AC_HELP_STRING([--enable-firebird],
			[enable FireBird support]),
		CONFIG_USE_FIREBIRD=$enableval,
		CONFIG_USE_FIREBIRD=no)

if test x$CONFIG_USE_FIREBIRD = xyes
then
	AC_MSG_RESULT([yes])
	AC_DEFINE_UNQUOTED([CONFIG_USE_FIREBIRD], [1], [whether need use FireBird])
	AC_CHECK_HEADERS([ibase.h], [firebirdheader_found=yes; AC_DEFINE_UNQUOTED([CONFIG_FIREBIRD_H], [<ibase.h>], [path to FireBird header])])
#	AC_CHECK_HEADERS([mysql/mysql.h], [mysqlheader_found=yes; AC_DEFINE_UNQUOTED([CONFIG_MYSQL_H], [<mysql/mysql.h>], [path to MySQL header])])
	AS_IF([test "x$firebirdheader_found" != "xyes"], [AC_MSG_ERROR([You need FireBird/InterBase devel package installed])])
else
	AC_MSG_RESULT([no])
fi

AM_CONDITIONAL(POSTGRESQL, test "$enable_postgresql" = yes)
AM_CONDITIONAL(MYSQL, test "$enable_mysql" = yes)
AM_CONDITIONAL(FIREBIRD, test "$enable_firebird" = yes)

AC_OUTPUT

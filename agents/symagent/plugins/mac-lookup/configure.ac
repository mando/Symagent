
AC_PREREQ(2.53)

AC_INIT()

# RULES FOR CHANGING THE VERSION NUMBER
#	1.	If you have changed any of the sources for this library but the
#		interface is unchanged, the GLOBAL_VERSION_BUGFIX must be incremented.
#		This is a new revision of the current interface.
#
#	2.	If the interface has changed, then GLOBAL_VERSION_MAJOR must be incremented,
#		and GLOBAL_VERSION_BUGFIX reset to `0'. This is the first revision of a
#		new interface.
#
#	3.	If the new interface is a superset of the previous interface
#		(that is, if the previous interface has not been broken by the
#		changes in this new release), then GLOBAL_VERSION_MINOR must be
#		incremented. This release is backwards compatible with the previous release.
#
#	4.	If the new interface has removed elements with respect to the
#		previous interface, then you have broken backward compatibility
#		and GLOBAL_VERSION_MINOR must be reset to `0'. This release has a
#		new, but backwards incompatible interface.
#	5.	Note that, whatever you do, you should update GLOBAL_VERSION_NUMBER
#		as well.

GLOBAL_VERSION_MAJOR=1
GLOBAL_VERSION_MINOR=0
GLOBAL_VERSION_BUGFIX=1
GLOBAL_VERSION_STRING="$GLOBAL_VERSION_MAJOR.$GLOBAL_VERSION_MINOR.$GLOBAL_VERSION_BUGFIX"			dnl	MM.mm.bb
GLOBAL_VERSION_NUMBER='0x010001L'																	dnl MMmmbb
AC_DEFINE_UNQUOTED(PLUGIN_VERSION_NUMBER,[$GLOBAL_VERSION_NUMBER],[Plugin version number])

PROJECT_SHORT_NAME=symplugin-mac-lookup

AC_SUBST(PROJECT_SHORT_NAME)
AC_DEFINE_UNQUOTED(PROJECT_SHORT_NAME,["$PROJECT_SHORT_NAME"],[The name of this agent plugin])

AC_CONFIG_SRCDIR([plugin-main.cc])
AC_CONFIG_AUX_DIR([conftools])
AC_CONFIG_HEADER([plugin-config.h])

sinclude(conftools/ac_c_bigendian_cross.m4)
sinclude(conftools/ac_define_dir.m4)

# Workaround to prevent autoconf from adding its own debugging
# and optimization flags
CXXFLAGS="$CXXFLAGS "

# Set the installation prefix directory
AC_PREFIX_DEFAULT([/usr/local])

AC_CHECK_TOOL_PREFIX

#####################################################################

# Save our configure arguments

PLUGIN_CONFIGURE_COMMAND="$0 $@"
AC_DEFINE_UNQUOTED(PLUGIN_CONFIGURE_COMMAND,["$PLUGIN_CONFIGURE_COMMAND"],[The command used to configure this plugin])

#####################################################################
# Configuration options
#####################################################################

AC_ARG_ENABLE(gdb,
	[AC_HELP_STRING(--enable-gdb,[Add gdb debugging support to all libraries])],
	[ ENABLE_GDB=$enableval],
	[ ENABLE_GDB=no ]
	)

if test "$ENABLE_GDB" = ""; then
	ENABLE_GDB="yes"
fi

#--------------------------------

AC_ARG_WITH(optimize,
	[AC_HELP_STRING(--with-optimize=LEVEL,[Compiler optimization; can be one of 0, 1, 2, or 3 [2]])],
	[ WITH_OPTIMIZE=$withval ],
	[ WITH_OPTIMIZE=2 ]
	)

if test "$WITH_OPTIMIZE" = ""; then
	WITH_OPTIMIZE=2
fi

#--------------------------------

DEFAULT_LIBSYMBIOT_BASE_DIR='/usr/local'
AC_ARG_WITH(libsymbiot-base-dir,
	[AC_HELP_STRING([--with-libsymbiot-base-dir=DIR],[LibSymbiot base directory; headers should be in DIR/include and libraries should be in DIR/lib [/usr/local]])],
	[ WITH_LIBSYMBIOT_BASE_DIR=$withval ],
	[ WITH_LIBSYMBIOT_BASE_DIR=$DEFAULT_LIBSYMBIOT_BASE_DIR ]
	)

if test "$WITH_LIBSYMBIOT_BASE_DIR" = ""; then
	WITH_LIBSYMBIOT_BASE_DIR=$DEFAULT_LIBSYMBIOT_BASE_DIR
fi

#####################################################################

dnl Determine host system OS type
AC_CANONICAL_TARGET

AC_C_BIGENDIAN_CROSS

dnl Platform-specific Makefile setup
case "$target" in
        *-*-solaris*)   		platform=SOLARIS ;;
        *-*-sco*)       		platform=OPENSERVER ;;
        *-*-sysv5*)     		platform=UNIXWARE ;;
        *-*-UnixWare*)  		platform=UNIXWARE ;;
        *-*-unixware*)  		platform=UNIXWARE ;;
        *-*-beos*)      		platform=BEOS ;;
        *-*-linux*)     		platform=LINUX
        						AC_CHECK_PROGS(DPKG,[dpkg-architecture])
        						if test -n "$DPKG"; then
        							osver=DEBIAN
        						fi
        						;;
        *-*-freebsd*)   		platform=FREEBSD ;;
        *-*-irix*)      		platform=IRIX ;;
        *-*-aix*)       		platform=AIX
								case "$target" in
									*-*-aix4.1*)     osver=AIX41 ;;
									*-*-aix4.2*)     osver=AIX42 ;;
									*-*-aix4.3*)     osver=AIX43 ;;
									*-*-aix4.*)      osver=AIX43 ;;
								esac
								;;
        *-sequent-*)    		platform=PTX ;;
        *-*-hp*)        		platform=HPUX
								case "$target" in
									*-*-hpux11*)  osver=HPUX11 ;;
									*-*-hpux10*)  osver=HPUX10 ;;
									*)            osver=HPUX11 ;;
								esac
								;;
        *-*-mvs*)       		platform=OS390 ;;
        *-*-os400*)     		platform=OS400 ;;
        *-*-OS400*)     		platform=OS400 ;;
        *-*-osf*)       		platform=TRU64 ;;
        *-*-darwin*)			platform=MACOSX
								case "$target" in
									*-*-darwin6*)   osver=MACOSX102 ;;
									*-*-darwin7*)   osver=MACOSX103 ;;
									*)	            osver=MACOSX ;;
								esac
								;;
        *-*-cygwin*)			platform=CYGWIN ;;
        *)              		platform=UNKNOWN ;;
esac
AC_SUBST(platform)

if test "$platform" = "LINUX"; then
	AC_MSG_CHECKING(if we are on Gentoo Linux)
	if test -e /etc/make.conf; then
		GENTOO_CFLAGS=`grep -v '^\#' /etc/make.conf | grep CFLAGS\=  | sed -e 's/\"//g' | sed -e 's/CFLAGS\=//' | sed -e 's/\-O[[:digit:]]\?//'`
		ac_cv_cc_linuxgentoo_defined=yes
		AC_MSG_RESULT($ac_cv_cc_linuxgentoo_defined)
		if test "$GENTOO_CFLAGS" != ""; then
			CXXFLAGS="$CXXFLAGS $GENTOO_CFLAGS"
		fi
	fi
fi

#####################################################################

# Locate a program and check that its version is acceptable. This function
# is called later, when trying to determine compiler versions.
#
# AC_PROG_CHECK_VER(var,
#					namelist,
#					version-switch,
#					[version-extract-regexp],
#					version-glob [, do-if-fail])

AC_DEFUN([AC_CHECK_PROG_VER],
[AC_CHECK_PROGS([$1], [$2])
if test -z "[$]$1"; then
  ac_verc_fail=yes
else
  # Found it, now check the version.
  AC_MSG_CHECKING([version of [$]$1])
changequote(<<,>>)dnl
  ac_prog_version=`<<$>>$1 $3 2>&1 ifelse(<<$4>>,,,
                   <<| sed -n 's/^.*patsubst(<<$4>>,/,\/).*$/\1/p'>>)`
  case $ac_prog_version in
    '') ac_prog_version="v. ?.??, bad"; ac_verc_fail=yes;;
    <<$5>>)
changequote([,])dnl
       ac_prog_version="$ac_prog_version, ok"; ac_verc_fail=no;;
    *) ac_prog_version="$ac_prog_version, bad"; ac_verc_fail=yes;;

  esac
  AC_MSG_RESULT([$ac_prog_version])
fi
ifelse([$6],,,
[if test $ac_verc_fail = yes; then
  $6
fi])
])

#####################################################################

dnl Program checks
AC_PROG_CXX

#####################################################################

# Find the compilers and make sure they are the right versions

AC_CHECK_PROG_VER([CC],[gcc cc], [-v],
	[version \([egcygnustpi-]*[0-9.]*\)], [3.[1-9]*] | 4.*,
	[AC_MSG_ERROR([unsupported compiler and/or version; configuration aborting])])

AC_CHECK_PROG_VER(CXX, g++ cxx cc++ c++, -v,
	[version \([egcygnustpi-]*[0-9.]*\)], [3.[1-9]*] | 4.*,
	[AC_MSG_ERROR([unsupported compiler and/or version; configuration aborting])])

AC_LANG(C++)

#####################################################################

# Libtool stuff

sinclude(conftools/libtool.m4)

PLUGINCURRENT=$GLOBAL_VERSION_MAJOR
PLUGINAGE=$GLOBAL_VERSION_MINOR
PLUGINREVISION=$GLOBAL_VERSION_BUGFIX

AC_SUBST(PLUGINCURRENT)
AC_SUBST(PLUGINREVISION)
AC_SUBST(PLUGINAGE)

AM_DISABLE_STATIC

AC_LIBTOOL_DLOPEN
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

AC_PROG_INSTALL

#####################################################################

# OS-specific adjustments

SCAN_LIMIT_190=0

case "$platform" in
	MACOSX)
		ARCHIVE_LIB_SUFFIX='a'
		SHARED_LIB_SUFFIX='dylib'
	;;
	CYGWIN)
		ARCHIVE_LIB_SUFFIX='a'
		SHARED_LIB_SUFFIX='dll.a'
	;;
	LINUX)
		case "$osver" in
			DEBIAN)
				AC_MSG_NOTICE([Debian package architecture detected])
				SCAN_LIMIT_190=1
				ARCHIVE_LIB_SUFFIX='a'
				SHARED_LIB_SUFFIX='so'
			;;
			*)
				AC_MSG_CHECKING([if we are on Red Hat Enterprise Linux])
				if test -e "/etc/issue"; then
					FOO=`grep 'Red Hat Enterprise Linux' /etc/issue`;
					if test -n "$FOO"; then
						SCAN_LIMIT_190=1
						AC_MSG_RESULT([yes])
					else
						AC_MSG_RESULT([no])
					fi
				else
					AC_MSG_RESULT([no])
				fi
				ARCHIVE_LIB_SUFFIX='a'
				SHARED_LIB_SUFFIX='so'
			;;
		esac
	;;
	*)
		ARCHIVE_LIB_SUFFIX='a'
		SHARED_LIB_SUFFIX='so'
	;;
esac

AC_DEFINE_UNQUOTED(SCAN_LIMIT_190,[$SCAN_LIMIT_190],[Set to 1 if we can spawn a maximum of only 190 scan threads, 0 otherwise])

#####################################################################

# Header checks
AC_HEADER_STDC

# Required headers
AC_CHECK_HEADERS([algorithm cctype cerrno climits cmath csignal cstdarg cstddef cstdio cstdlib cstring iostream map memory string vector],
	[],
	[AC_MSG_ERROR([required header files are missing; configuration aborting])])

# Optional headers
AC_CHECK_HEADERS([net/ethernet.h netinet/if_ether.h],
	[],
	[],
	[
		#include <sys/types.h>
		#include <sys/socket.h>
		#ifdef HAVE_NET_ETHERNET_H
			#include <net/ethernet.h>
		#endif
	])

USE_NETPACKET=1
USE_BPF=1

# More header checks

if test $USE_NETPACKET -eq 1; then
	AC_CHECK_HEADERS([net/if.h netinet/in.h netpacket/packet.h netdb.h arpa/inet.h sys/ioctl.h],
		[],
		[USE_NETPACKET=0],
		[
			#include <sys/types.h>
			#include <sys/socket.h>
			#ifdef HAVE_NET_ETHERNET_H
				#include <net/ethernet.h>
			#endif
			#ifdef HAVE_NET_IF_H
				#include <net/if.h>
			#endif
			#ifdef HAVE_NETINET_IN_H
				#include <netinet/in.h>
			#endif
			#ifdef HAVE_NETINET_IF_ETHER_H
				#include <netinet/if_ether.h>
			#endif
			#ifdef HAVE_NETPACKET_PACKET_H
				#include <netpacket/packet.h>
			#endif
			#ifdef HAVE_NETDB_H
				#include <netdb.h>
			#endif
			#ifdef HAVE_ARPA_INET_H
				#include <arpa/inet.h>
			#endif
			#ifdef HAVE_SYS_IOCTL_H
				#include <sys/ioctl.h>
			#endif
		])
fi

if test $USE_NETPACKET -eq 1; then
	USE_BPF=0
fi

if test $USE_BPF -eq 1; then
	AC_CHECK_HEADERS([net/if.h netinet/in.h net/bpf.h netdb.h arpa/inet.h sys/ioctl.h sys/fcntl.h sys/sysctl.h net/route.h net/if_dl.h],
		[],
		[USE_BPF=0],
		[
			#include <sys/types.h>
			#include <sys/socket.h>
			#ifdef HAVE_NET_ETHERNET_H
				#include <net/ethernet.h>
			#endif
			#ifdef HAVE_NET_IF_H
				#include <net/if.h>
			#endif
			#ifdef HAVE_NETINET_IN_H
				#include <netinet/in.h>
			#endif
			#ifdef HAVE_NETINET_IF_ETHER_H
				#include <netinet/if_ether.h>
			#endif
			#ifdef HAVE_NET_BPF_H
				#include <net/bpf.h>
			#endif
			#ifdef HAVE_NETDB_H
				#include <netdb.h>
			#endif
			#ifdef HAVE_ARPA_INET_H
				#include <arpa/inet.h>
			#endif
			#ifdef HAVE_SYS_IOCTL_H
				#include <sys/ioctl.h>
			#endif
			#ifdef HAVE_SYS_FCNTL_H
				#include <sys/fcntl.h>
			#endif
			#ifdef HAVE_SYS_SYSCTL_H
				#include <sys/sysctl.h>
			#endif
			#ifdef HAVE_NET_ROUTE_H
				#include <net/route.h>
			#endif
			#ifdef HAVE_NET_IF_DL_H
				#include <net/if_dl.h>
			#endif
		])
fi

if test $USE_NETPACKET -eq 0 -a $USE_BPF -eq 0; then
	AC_MSG_ERROR([required header files are missing; configuration aborting])
fi

AC_DEFINE_UNQUOTED(USE_NETPACKET,[$USE_NETPACKET],[Set to 1 if this platform uses netpacket interface for raw network bonking, 0 otherwise])
AC_DEFINE_UNQUOTED(USE_BPF,[$USE_BPF],[Set to 1 if this platform uses BPF for raw network bonking, 0 otherwise])

#####################################################################

# Check type of socket length argument

AC_MSG_CHECKING([type of socket length argument])

SAVED_CXXFLAGS=$CXXFLAGS
CXXFLAGS="$CXXFLAGS  -Werror"

SOCKET_SIZE_TYPE=none

# First assume that it's a socklen_t type
AC_COMPILE_IFELSE(AC_LANG_PROGRAM([
									#if defined(inline)
										#undef inline
									#endif
									#include <stdlib.h>
									#include <sys/types.h>
									#include <sys/socket.h>
								  ],
								  [
									int a = accept(1, static_cast<struct sockaddr*>(0), static_cast<socklen_t*>(0));
									return (a != 0);
								  ]),
				  [SOCKET_SIZE_TYPE=socklen_t])

if test "$SOCKET_SIZE_TYPE" = "none"; then
	# Now assume it's a size_t type
	AC_COMPILE_IFELSE(AC_LANG_PROGRAM([
										#if defined(inline)
											#undef inline
										#endif
										#include <stdlib.h>
										#include <sys/types.h>
										#include <sys/socket.h>
									  ],
									  [
										int a = accept(1, static_cast<struct sockaddr*>(0), static_cast<size_t*>(0));
										return (a != 0);
									  ]),
					  [SOCKET_SIZE_TYPE=size_t])
fi

if test "$SOCKET_SIZE_TYPE" = "none"; then
	# We don't know what it is; assume an int
	SOCKET_SIZE_TYPE=int
fi

AC_MSG_RESULT([$SOCKET_SIZE_TYPE])

CXXFLAGS=$SAVED_CXXFLAGS

AC_DEFINE_UNQUOTED(SOCKET_SIZE_TYPE,[$SOCKET_SIZE_TYPE],[The argument type for a socket size])

#####################################################################

# Check for struct sockaddr_ll

if test $USE_NETPACKET -eq 1; then
	AC_MSG_CHECKING([presence of struct sockaddr_ll])
	
	SAVED_CXXFLAGS=$CXXFLAGS
	CXXFLAGS="$CXXFLAGS  -Werror"
	
	AC_COMPILE_IFELSE(AC_LANG_PROGRAM([
										#if defined(inline)
											#undef inline
										#endif
										#include <sys/types.h>
										#include <sys/socket.h>
										#include <net/ethernet.h>
										#include <net/if.h>
										#include <netinet/in.h>
										#include <netinet/if_ether.h>
										#include <netpacket/packet.h>
									  ],
									  [
										struct sockaddr_ll	s;
										int a = s.sll_protocol;
										return (a != 0);
									  ]),
					  [AC_MSG_RESULT([defined])],
					  [AC_MSG_ERROR([required structure is missing; configuration aborting])])
	
	CXXFLAGS=$SAVED_CXXFLAGS
fi

#####################################################################

# Check for PF_PACKET

if test $USE_NETPACKET -eq 1; then
	AC_MSG_CHECKING([presence of PF_PACKET])
	
	SAVED_CXXFLAGS=$CXXFLAGS
	CXXFLAGS="$CXXFLAGS  -Werror"
	
	AC_COMPILE_IFELSE(AC_LANG_PROGRAM([
										#if defined(inline)
											#undef inline
										#endif
										#include <sys/types.h>
										#include <sys/socket.h>
									  ],
									  [
										int a = PF_PACKET;
										return (a != 0);
									  ]),
					  [AC_MSG_RESULT([defined])],
					  [AC_MSG_ERROR([required definition is missing; configuration aborting])])
	
	CXXFLAGS=$SAVED_CXXFLAGS
fi

#####################################################################

AC_MSG_CHECKING([if we should add gdb debugging support])

if test "$ENABLE_GDB" = "yes"; then
	AC_MSG_RESULT([yes])
	CXXFLAGS="$CXXFLAGS -g"
else
	LDFLAGS="$LDFLAGS -s"
	AC_MSG_RESULT([no])
fi

#####################################################################

AC_MSG_CHECKING([optimization level])

AC_MSG_RESULT([$WITH_OPTIMIZE])
CXXFLAGS="$CXXFLAGS -O$WITH_OPTIMIZE"

#####################################################################

# LibSymbiot base directory

AC_CHECK_FILES([$WITH_LIBSYMBIOT_BASE_DIR/include/symlib-api.h $WITH_LIBSYMBIOT_BASE_DIR/include/symlib-defs.h $WITH_LIBSYMBIOT_BASE_DIR/include/symlib-exception.h $WITH_LIBSYMBIOT_BASE_DIR/include/symlib-message.h $WITH_LIBSYMBIOT_BASE_DIR/include/symlib-mutex.h $WITH_LIBSYMBIOT_BASE_DIR/include/symlib-task-queue.h $WITH_LIBSYMBIOT_BASE_DIR/include/symlib-tasks.h],
	[],
	[AC_MSG_ERROR([required LibSymbiot header files are missing; configuration aborting])])

INCLUDES="$INCLUDES -I$WITH_LIBSYMBIOT_BASE_DIR/include"

AC_CHECK_FILES([$WITH_LIBSYMBIOT_BASE_DIR/lib/libsymbiot.$SHARED_LIB_SUFFIX],
	[
		LIBS="$LIBS -L$WITH_LIBSYMBIOT_BASE_DIR/lib -lsymbiot"
		if test "$platform" = "FREEBSD"; then
			LDFLAGS="$LDFLAGS -pthread"
		fi
	],
	[
		AC_CHECK_FILES([$WITH_LIBSYMBIOT_BASE_DIR/lib/libsymbiot.$ARCHIVE_LIB_SUFFIX],
			[
				LIBS="$LIBS -lcrypto -lssl -lcrypto"
				AC_SEARCH_LIBS([dlopen],[dl c])
				AC_SEARCH_LIBS([crypt],[crypt c])
				
				# Required libraries
				AC_CHECK_LIB([z],[gzdopen],
							 [],
							 [AC_MSG_ERROR([required library is missing; configuration aborting])])
				#-------------
				case "$platform" in
					FREEBSD)
						LDFLAGS="$LDFLAGS -pthread"
					;;
					*)
						AC_CHECK_LIB([pthread],[pthread_create],
							[],
							[AC_MSG_ERROR([required library is missing; configuration aborting])],[])
					;;
				esac
				#-------------
				LIBS="$LIBS -L$WITH_LIBSYMBIOT_BASE_DIR/lib -lsymbiot"
			],
			[AC_MSG_ERROR([required LibSymbiot libraries missing; configuration aborting])])
	])

#####################################################################

# Makefile variable substitution

AC_SUBST(INCLUDES)

#####################################################################

AC_CONFIG_FILES([Makefile])
AC_OUTPUT()

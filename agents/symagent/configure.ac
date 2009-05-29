
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
GLOBAL_VERSION_BUGFIX=2
GLOBAL_VERSION_STRING="$GLOBAL_VERSION_MAJOR.$GLOBAL_VERSION_MINOR.$GLOBAL_VERSION_BUGFIX"			dnl	MM.mm.bb
GLOBAL_VERSION_NUMBER='0x010002L'																	dnl MMmmbb
AC_DEFINE_UNQUOTED(AGENT_VERSION_NUMBER,[$GLOBAL_VERSION_NUMBER],[Agent version number])

CREATE_CONFIG_FILE='agent-config.h'			dnl -- Note duplicate in AC_CONFIG_HEADER()

AC_CONFIG_SRCDIR([main.cc])
AC_CONFIG_AUX_DIR([conftools])
AC_CONFIG_HEADER([agent-config.h])

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

AGENT_CONFIGURE_COMMAND="$0 $@"
AC_DEFINE_UNQUOTED(AGENT_CONFIGURE_COMMAND,["$AGENT_CONFIGURE_COMMAND"],[The command used to configure this agent])

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
        *-*-linux*)     		platform=LINUX ;;
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

VERSIONCURRENT=$GLOBAL_VERSION_MAJOR
VERSIONAGE=$GLOBAL_VERSION_MINOR
VERSIONREVISION=$GLOBAL_VERSION_BUGFIX

AC_SUBST(VERSIONCURRENT)
AC_SUBST(VERSIONREVISION)
AC_SUBST(VERSIONAGE)

AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL

AC_PROG_INSTALL

#####################################################################

# OS-specific adjustments

REQUIRE_SUPER_USER="1"

USE_DLOPEN="0"
BUILD_DLCOMPAT=no

case "$platform" in
	MACOSX)
		ARCHIVE_LIB_SUFFIX='a'
		SHARED_LIB_SUFFIX='dylib'
		BUILD_DLCOMPAT=yes
		USE_DLOPEN="1"
	;;
	CYGWIN)
		ARCHIVE_LIB_SUFFIX='a'
		SHARED_LIB_SUFFIX='dll.a'
		USE_DLOPEN="1"
		REQUIRE_SUPER_USER="0"
	;;
	*)
		ARCHIVE_LIB_SUFFIX='a'
		SHARED_LIB_SUFFIX='so'
		USE_DLOPEN="1"
	;;
esac

AC_DEFINE_UNQUOTED(USE_DLOPEN,[$USE_DLOPEN],[Define to 1 if this platform supports the dlopen() call and its friends, and to 0 if it doesn't.])
AC_DEFINE_UNQUOTED(REQUIRE_SUPER_USER,[$REQUIRE_SUPER_USER],[Define to 1 if a super-user is required, 0 otherwise.])

#####################################################################

# Header checks
AC_HEADER_STDC

# Required headers
AC_CHECK_HEADERS([algorithm cctype cerrno climits cmath csignal cstdarg cstddef cstdio cstdlib cstring iostream map memory string vector],
	[],
	[AC_MSG_ERROR([required header files are missing; configuration aborting])])

# Optional headers
AC_CHECK_HEADERS([libgen.h sys/sysinfo.h])

#####################################################################

# System library check

if test "$BUILD_DLCOMPAT" = "no"; then
	AC_CHECK_LIB([dl],[dlopen],
		[USE_DLOPEN="1"],
		[
			AC_CHECK_LIB([c],[dlopen],
				[USE_DLOPEN="1"],
				[AC_MSG_ERROR([required library is missing; configuration aborting])])
		])
fi

#####################################################################

# System header check

AC_HEADER_DIRENT
AC_CHECK_FUNCS([getloadavg readdir_r sysinfo])

#####################################################################

# Check the first argument to getrlimit/setrlimit

AC_MSG_CHECKING([base type of first arg to getrlimit/setrlimit])

SAVED_CXXFLAGS=$CXXFLAGS
CXXFLAGS="$CXXFLAGS  -Werror"

RESOURCE_LIMIT_TYPE=none

# First assume that it's a __rlimit_resource type
AC_COMPILE_IFELSE(AC_LANG_PROGRAM([
									#if defined(inline)
										#undef inline
									#endif
									#include <sys/time.h>
									#include <sys/resource.h>
									#include <unistd.h>
								  ],
								  [
									int a = getrlimit (static_cast<__rlimit_resource>(0),static_cast<struct rlimit*>(NULL));
									return (a != 0);
								  ]),
				  [RESOURCE_LIMIT_TYPE=__rlimit_resource])

if test "$RESOURCE_LIMIT_TYPE" = "none"; then
	# We don't know what it is; assume an int
	RESOURCE_LIMIT_TYPE=int
fi

AC_MSG_RESULT([$RESOURCE_LIMIT_TYPE])

CXXFLAGS=$SAVED_CXXFLAGS

AC_DEFINE_UNQUOTED(RESOURCE_LIMIT_TYPE,[$RESOURCE_LIMIT_TYPE],[The argument type for getrlimit/setrlimit])

#####################################################################

# Check for other definitions

AC_CHECK_DECLS([RLIMIT_CORE,RLIMIT_CPU,RLIMIT_DATA,RLIMIT_FSIZE,RLIMIT_MEMLOCK,RLIMIT_NOFILE,RLIMIT_NPROC,RLIMIT_RSS,RLIMIT_STACK],
			   [],
			   [],
			   [
			   		#include <sys/time.h>
					#include <sys/resource.h>
			   ])

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

AC_MSG_CHECKING([whether to build dlcompat code])
AC_MSG_RESULT($BUILD_DLCOMPAT)

#####################################################################

AC_MSG_CHECKING([should we use dlopen() code for plugins])
if test "$USE_DLOPEN" = "1"; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
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

#-----------------------------

# DLCOMPAT stuff

DLCOMPAT_SUBDIR='dlcompat-20030629'
if test "$BUILD_DLCOMPAT" = "yes"; then
	DLCOMPAT_OBJECTS='$(top_srcdir)/$(DLCOMPAT_SUBDIR)/*.o'
	OPTIONAL_OBJECTS="$OPTIONAL_OBJECTS $DLCOMPAT_OBJECTS"
	DLCOMPAT_INC='-I$(top_srcdir)/$(DLCOMPAT_SUBDIR)'
	INCLUDES="$DLCOMPAT_INC $INCLUDES"		dnl -- Note that we're making that first
	AC_CONFIG_SUBDIRS(dlcompat-20030629)
fi
AC_SUBST(OPTIONAL_OBJECTS)
AC_SUBST(DLCOMPAT_SUBDIR)
AC_SUBST(BUILD_DLCOMPAT)

# Startup script stuff
AC_SUBST(LIBSYMBIOT_DIR,[$WITH_LIBSYMBIOT_BASE_DIR/lib])
AC_SUBST(PID_DIR,/var/run)

#####################################################################

# Configuration file substitution

AC_DEFINE_DIR(ABS_LIBEXECDIR,bindir,[Agent plugin directory prefix])
PLUGIN_PATH=$ABS_LIBEXECDIR/symagent-plugins
AC_DEFINE_UNQUOTED(PLUGIN_PATH,["$PLUGIN_PATH"],[Directory containing agent plugins])
AC_SUBST(PLUGIN_PATH)

#####################################################################

AC_CONFIG_FILES([Makefile startup_script/linux.sh startup_script/gentoo.sh startup_script/mac_os_x/StartupParameters.plist startup_script/mac_os_x/mac_os_x startup_script/freebsd.sh])
AC_OUTPUT()

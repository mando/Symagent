/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Agent to obtain system information from Windows via Cygwin
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					02 Jan 2004
#		Last Modified:				12 Mar 2004
#		
#######################################################################
*/
#if !defined(WIN_PROCESSES)
#define WIN_PROCESSES

#define __USE_W32_SOCKETS		// must be defined before winsock2.h

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <snmp.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/cygwin.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <w32api/iphlpapi.h>

#include "common-info.h"

#include "plugin-utils.h"


//---------------------------------------------------------------------
// Defines
//---------------------------------------------------------------------
#define HOSTNAMELEN 256
#define PORTNAMELEN 256
#define ADDRESSLEN HOSTNAMELEN+PORTNAMELEN

//---------------------------------------------------------------------
// Structures
//---------------------------------------------------------------------
//
// Undocumented extended information structures available 
// only on XP and higher
// 

typedef struct 
{
	DWORD   dwState;        // state of the connection
	DWORD   dwLocalAddr;    // address on local computer
	DWORD   dwLocalPort;    // port number on local computer
	DWORD   dwRemoteAddr;   // address on remote computer
	DWORD   dwRemotePort;   // port number on remote computer
	DWORD	dwProcessId;
}	MIB_TCPEXROW, *PMIB_TCPEXROW;


typedef struct 
{
	DWORD			dwNumEntries;
	MIB_TCPEXROW	table[ANY_SIZE];
} MIB_TCPEXTABLE,	*PMIB_TCPEXTABLE;

typedef struct 
{
	DWORD   dwLocalAddr;    // address on local computer
	DWORD   dwLocalPort;    // port number on local computer
	DWORD	dwProcessId;
}	MIB_UDPEXROW, *PMIB_UDPEXROW;


typedef struct 
{
	DWORD			dwNumEntries;
	MIB_UDPEXROW	table[ANY_SIZE];
}	MIB_UDPEXTABLE, *PMIB_UDPEXTABLE;


//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------
void GetRunningProcessInfo(ProcessInfoMap& procInfoMap, NetworkConnectionMap& netConnMap);
// Entry Point

void GetProcessList( ProcessInfoMap& procInfoMap );
// Collects information about the currently-running processes

void GetNetworkList( ProcessInfoMap& procInfoMap, NetworkConnectionMap& netConnMap );
// Collects information about the open network connections

void GetTCPConnections( ProcessInfoMap& procInfoMap, NetworkConnectionMap& netConnMap, long& connectionKey );
// Get the TCP connections

void GetUDPConnections( ProcessInfoMap& procInfoMap, NetworkConnectionMap& netConnMap, long& connectionKey );
// Get the UDP connections

int InitWindows ();
// Loads the cygwin and windows kernel DLLs and walks the process list

BOOL WINAPI DummyProcessModules (HANDLE hProcess,				// handle to the process
										 HMODULE * lphModule,	// array to receive the module handles
										 DWORD cb,				// size of the array
										 LPDWORD lpcbNeeded		// receives the number of bytes returned 
								);

DWORD WINAPI GetModuleFileNameEx95( HANDLE hProcess, HMODULE hModule, LPTSTR lpstrFileName, DWORD n );

PCHAR ConvertToIp( UINT ipaddr,  PCHAR name ) ;
// Convert DWORD IP address to familar string IP dot notation

//---------------------------------------------------------------------
// typedefs to windows functions in DLLS
//---------------------------------------------------------------------
typedef BOOL	(WINAPI *ENUMPROCESSMODULES)	(	HANDLE hProcess,      // handle to the process
													HMODULE * lphModule,  // array to receive the module handles
													DWORD cb,             // size of the array
													LPDWORD lpcbNeeded    // receives the number of bytes returned
												);

typedef DWORD	(WINAPI *GETMODULEFILENAME)		(	HANDLE hProcess,  
													HMODULE hModule,  
													LPTSTR lpstrFileName, 
													DWORD nSize );

typedef HANDLE	(WINAPI *CREATESNAPSHOT)		(	DWORD dwFlags,	DWORD th32ProcessID	) ;
typedef BOOL	(WINAPI *PROCESSWALK)			(	HANDLE hSnapshot, LPPROCESSENTRY32 lppe );


typedef DWORD ( WINAPI *ALLOCATEANDGETTCPEXTABLEFROMSTACK ) (	PMIB_TCPEXTABLE *pTcpTable,		// buffer for the connection table
																BOOL bOrder,					// sort the table?
																HANDLE heap,
																DWORD zero,
																DWORD flags );

typedef DWORD ( WINAPI *ALLOCATEANDGETUDPEXTABLEFROMSTACK)	(	PMIB_UDPEXTABLE *pUdpTable,		// buffer for the connection table
																BOOL bOrder,					// sort the table?
																HANDLE heap,
																DWORD zero,
																DWORD flags );

//---------------------------------------------------------------------
#endif // WIN_PROCESSES

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
#		Last Modified:				26 Feb 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "win-processes.h"
#include <string.h>

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define FACTOR (0x19db1ded53ea710LL)
#define NSPERSEC 10000000LL
// major and minor versions must be used to distinguish 2000 from XP
// NOTE: VER_PLATFORM_WIN32_NT doesn't distinguish between 2000 and XP
#define OS_RELEASE_4				4			// Windows 95, 95, ME, NT4
#define OS_RELEASE_5				5			// Windows 2000 and XP
#define OS_MINOR_VERSION_2000		0			// 5.0
#define OS_MINOR_VERSION_XP			1			// 5.1
#define OS_MINOR_VERSION_2003		2			// 5.2

//#define printproc						// print processes to stdout
//#define printnet						// print network connections to stdout

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
static ENUMPROCESSMODULES	myEnumProcessModules;
static GETMODULEFILENAME	myGetModuleFileNameEx;
static CREATESNAPSHOT		myCreateToolhelp32Snapshot;
static PROCESSWALK			myProcess32First;
static PROCESSWALK			myProcess32Next;

// undocumented functions in iphlpapi.dll
static ALLOCATEANDGETTCPEXTABLEFROMSTACK	pAllocateAndGetTcpExTableFromStack;
static ALLOCATEANDGETUDPEXTABLEFROMSTACK	pAllocateAndGetUdpExTableFromStack;

static HINSTANCE			hIpHelper;
static bool					bIpHlpApi		= false;	

//---------------------------------------------------------------------
// GetRunningProcessInfo
//---------------------------------------------------------------------
void GetRunningProcessInfo(ProcessInfoMap& procInfoMap, NetworkConnectionMap& netConnMap )
{

	if( ! InitWindows() )	
		return;		// windows failed to init; 

	procInfoMap.clear();								// remove all entries from process map

	GetProcessList( procInfoMap );						// get process list for all supported systems
		
	if( bIpHlpApi )										// OS supports undocumented functions in iphlpapi.dll
	{
		GetNetworkList( procInfoMap, netConnMap );		// map processes to open connections
		FreeLibrary( hIpHelper );
	}
}

//------------------------------------------------------------
void GetProcessList( ProcessInfoMap& procInfoMap )
//------------------------------------------------------------
{
	external_pinfo *p;

	cygwin_getinfo_types query	=	CW_GETPINFO_FULL;
	
	(void) cygwin_internal (CW_LOCK_PINFO, 1000);				// lock internal data strucs 

	// populate the ProcessInfo structure
	for( int pid = 0; (p = (external_pinfo *) cygwin_internal( query, pid | CW_NEXTPID));pid = p->pid )
	{
		ProcessInfo	procInfo;
		pid_t	pID = 0;

		char status = ' ';
		if( p->process_state & PID_STOPPED )
			status = 'S';
		else 
		if( p->process_state & PID_TTYIN )
			status = 'I';
		else 
		if( p->process_state & PID_TTYOU )
			status = 'O';
		char pname[MAX_PATH];
		if( p->process_state & (PID_ZOMBIE | PID_EXITED) )
			strcpy (pname, "<defunct>");
		else 
		if( p->ppid )
			strcpy( pname, p->progname );
		else 
		if( query == CW_GETPINFO_FULL )
		{
			HANDLE h = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p->dwProcessId );
			if( !h )
				continue;
			HMODULE hm[1000];
			DWORD n = p->dwProcessId;
			if( !myEnumProcessModules(h, hm, sizeof (hm), &n) )				// get a list of all the modules in this process
				n = 0;
			if( !n || !myGetModuleFileNameEx(h, hm[0], pname, MAX_PATH) )	// get the full path to the module's file
//				strcpy (pname, "*** unknown ***");
				continue;									// don't include unknown processes
			CloseHandle( h );
		}

		// remove bad cygwin prefix 
		int ret	= strncmp ( pname, "\\??\\", 4 );
		if( ret == 0 )
			strcpy( pname, pname + 4 );

		// convert env variable, if present, to absolute path 
		// ex: \SystemRoot\System32\smss.exe
		// note: drive will be present if not env variable; "c:\"
		if( pname[0] == '\\' )
		{
			char path[MAX_PATH];
			memset( path, 0, MAX_PATH );
			char seps[]   = "\\";
			char* token = strtok( pname, seps );			// extract env variable
			token = strupr( token );						// for some strange reason, Windows wants uppercase
			strcpy( path, getenv( token ) );				// convert it
			strcat( path, "\\" );							// append file separator
			strcat( path, pname + (strlen(token) + 2) );	// append original pname without env variable and 2 slashes
			strcpy( pname, path );							// replace pname with new path						
		}

		pID = p->pid;										// process id is key to map
		procInfo.path		=	pname;

		// Create the signature for that binary
		if (!procInfo.path.empty())
			procInfo.appSig =	GetApplicationSignature(procInfo.path);
		
		procInfo.ownerID	=	p->dwProcessId;
		procInfo.groupID	=	p->pgid;
		procInfoMap[pID]	=	procInfo;

		#ifdef printproc
		printf( "procInfo.path     : %s\n", procInfo.path.c_str() );
		printf( "procInfo.appSig   : %s\n", procInfo.appSig.c_str() );
		printf( "procInfo.ownerID  : %d\n", procInfo.ownerID );
		printf( "procInfo.groupID  : %d\n", procInfo.groupID );
		printf( "--------------------------------------------\n" );
		#endif
		
	}	// end for


//	std::sort(procInfo.inodeList.begin(),procInfo.inodeList.end());


	(void) cygwin_internal (CW_UNLOCK_PINFO);		// unlock internal data strucs
}

//------------------------------------------------------------
void GetNetworkList(	ProcessInfoMap&			procInfoMap, 
						NetworkConnectionMap&	netConnMap )
//------------------------------------------------------------
{
	netConnMap.clear();							// remove all entries from map

	long	connectionKey = 0;

	GetTCPConnections( procInfoMap, netConnMap, connectionKey );
	GetUDPConnections( procInfoMap, netConnMap, connectionKey );
}

//------------------------------------------------------------
void GetTCPConnections( ProcessInfoMap&			procInfoMap, 
						NetworkConnectionMap&	netConnMap, 
						long&					connectionKey )
//------------------------------------------------------------
{

	DWORD					error;
	PMIB_TCPEXTABLE			tcpExTable;
	ProcessInfoMap_iter		processIter;
	ProcessInfo				procInfo;

	CHAR		localname[HOSTNAMELEN], remotename[HOSTNAMELEN];
	CHAR		localaddr[ADDRESSLEN], remoteaddr[ADDRESSLEN];

	// obtain list of TCP connections
	error = pAllocateAndGetTcpExTableFromStack( &tcpExTable, TRUE, GetProcessHeap(), 2, 2 );
	if( error ) 
	{

		printf("Failed to snapshot TCP endpoints.\n");
		return;
	}

	#ifdef printnet
	printf( "**           TCP           **\n" );
	#endif

	// populate the NetworkConnection struct with the TCP entries
	for( DWORD i = 0; i < tcpExTable->dwNumEntries; i++ ) 
	{
		//lookup processId in process map
		processIter = procInfoMap.find( tcpExTable->table[i].dwProcessId );
		if( processIter != procInfoMap.end() )
		{
			procInfo = (*processIter).second; 
			NetworkConnection		connectInfo;

			connectInfo.protoFamily	=	AF_INET;
			connectInfo.protoID		=	IPPROTO_TCP;	

			// local
			sprintf( localaddr, "%s", ConvertToIp(tcpExTable->table[i].dwLocalAddr, localname) );
			connectInfo.sourceAddr	=	localaddr;
			connectInfo.sourcePort	= htons( (WORD) (UINT) tcpExTable->table[i].dwLocalPort );
			// remote
			sprintf( remoteaddr, "%s", ConvertToIp(tcpExTable->table[i].dwRemoteAddr, remotename) );
			connectInfo.destAddr	=	remoteaddr;
			connectInfo.destPort	= 
				tcpExTable->table[i].dwRemoteAddr ? htons((WORD) (UINT) tcpExTable->table[i].dwRemotePort) : 0;
			netConnMap[connectionKey]	=	connectInfo;

			procInfo.inodeList.push_back( connectionKey );		// map connection key to process id
			(*processIter).second	=	procInfo;


			#ifdef printnet
			printf( "connectInfo.protoFamily: %d\n", connectInfo.protoFamily );
			printf( "connectInfo.protoID:     %d\n", connectInfo.protoID );
			printf( "connectInfo.sourceAddr:  %s\n", connectInfo.sourceAddr.c_str() );
			printf( "connectInfo.sourcePort:  %u\n", connectInfo.sourcePort );
			printf( "connectInfo.destAddr:    %s\n", connectInfo.destAddr.c_str() );
			printf( "connectInfo.destPort:    %u\n", connectInfo.destPort );
			printf( "process id:              %d\n", tcpExTable->table[i].dwProcessId );
			printf( "connectionKey:           %d\n", connectionKey );
			printf( "--------------------------------------------\n" );
			#endif
			connectionKey++;
		}
	}
}

//------------------------------------------------------------
void GetUDPConnections(	ProcessInfoMap&			procInfoMap, 
						NetworkConnectionMap&	netConnMap, 
						long&					connectionKey )
//------------------------------------------------------------
{

	DWORD					error;
	PMIB_UDPEXTABLE			udpExTable;
	ProcessInfoMap_iter		processIter;
	ProcessInfo				procInfo;

	CHAR		localname[HOSTNAMELEN];
	CHAR		localaddr[ADDRESSLEN];

	// obtain list of UDP connections
	error = pAllocateAndGetUdpExTableFromStack( &udpExTable, TRUE, GetProcessHeap(), 2, 2 );
	if( error ) 
	{

		printf("Failed to snapshot UDP endpoints.\n");
		return;
	}

	#ifdef printnet
	printf( "**           UDP           **\n" );
	#endif


	// populate the NetworkConnection struct with the UDP entries
	for( DWORD i = 0; i < udpExTable->dwNumEntries; i++ ) 
	{
		//lookup processId in process map
		processIter = procInfoMap.find( udpExTable->table[i].dwProcessId );
		if( processIter != procInfoMap.end() )
		{
			procInfo = (*processIter).second; 
			NetworkConnection		connectInfo;

			connectInfo.protoFamily		=	AF_INET;
			connectInfo.protoID			=	IPPROTO_UDP;	

			// local
			sprintf( localaddr, "%s", ConvertToIp(udpExTable->table[i].dwLocalAddr, localname) );
			connectInfo.sourceAddr		=	localaddr;
			connectInfo.sourcePort		=	htons( (WORD) (UINT) udpExTable->table[i].dwLocalPort );
			connectInfo.destAddr		=   "";
			connectInfo.destPort		=   0;
			netConnMap[connectionKey]	=	connectInfo;
			
			procInfo.inodeList.push_back( connectionKey );		// map connection key to process id
			(*processIter).second		=	procInfo;


			#ifdef printnet
			printf( "connectInfo.protoFamily: %d\n", connectInfo.protoFamily );
			printf( "connectInfo.protoID:     %d\n", connectInfo.protoID );
			printf( "connectInfo.sourceAddr:  %s\n", connectInfo.sourceAddr.c_str() );
			printf( "connectInfo.sourcePort:  %u\n", connectInfo.sourcePort );
			printf( "process id:              %d\n", udpExTable->table[i].dwProcessId );
			printf( "connectionKey:           %d\n", connectionKey );
			printf( "--------------------------------------------\n" );
			#endif
			connectionKey++;
		}

	}
}

//---------------------------------------------------------------------
// InitWindows
//---------------------------------------------------------------------
int InitWindows ()
{

	bIpHlpApi	=	false;

	// obtain OS info

	OSVERSIONINFO os_version_info;

	memset( &os_version_info, 0, sizeof os_version_info );

	os_version_info.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
	GetVersionEx( &os_version_info );

	HMODULE hModule;

	// determine OS

	if( os_version_info.dwMajorVersion == OS_RELEASE_5 )			// windows 2000 and up
	{
		// load the process helper dll
		hModule = LoadLibrary( "psapi.dll" );						// process status helper
		if( !hModule )
		{
			string		errString;
			errString += "psapi.dll failed to load";
			printf( "%s\n", errString.c_str() );
			return 0;
		}
		myEnumProcessModules = (ENUMPROCESSMODULES) GetProcAddress ( hModule, "EnumProcessModules" );
		myGetModuleFileNameEx = (GETMODULEFILENAME) GetProcAddress ( hModule, "GetModuleFileNameExA" );
		if( ! myEnumProcessModules || !myGetModuleFileNameEx )
			return 0;
		
		if( os_version_info.dwMinorVersion > OS_MINOR_VERSION_2000 )
		{
			// load the ip helper dll
			if( (hIpHelper = LoadLibrary("iphlpapi.dll")) == NULL )
			{
				string		errString;
				errString += "Please insure iphlpapi.dll is located in the PATH";
				printf( "%s\n", errString.c_str() );
				return 0;
			}

			// obtain the address of the undocumented helper functions
			pAllocateAndGetTcpExTableFromStack = 
				(ALLOCATEANDGETTCPEXTABLEFROMSTACK) GetProcAddress( hIpHelper, "AllocateAndGetTcpExTableFromStack" ); 

			pAllocateAndGetUdpExTableFromStack = 
				(ALLOCATEANDGETUDPEXTABLEFROMSTACK) GetProcAddress( hIpHelper, "AllocateAndGetUdpExTableFromStack" ); 

			if( pAllocateAndGetTcpExTableFromStack == NULL ) 
			{
				string		errString;
				errString += "iphlpapi.dll version is incorect - need the XP version";
				printf( "%s\n", errString.c_str() );
				return 0;
			}
 
			if( pAllocateAndGetUdpExTableFromStack == NULL ) 
			{
				string		errString;
				errString += "iphlpapi.dll version is incorect - need the XP version";
				printf( "%s\n", errString.c_str() );
				return 0;
			}
			bIpHlpApi	=	true;
			return 1;
		}
    }
	else
	if( os_version_info.dwMajorVersion == OS_RELEASE_4 )				// Windows 95, 98 and ME compatibility
	{	
		hModule = GetModuleHandle("KERNEL32.DLL");

		myCreateToolhelp32Snapshot = (CREATESNAPSHOT)GetProcAddress (hModule, "CreateToolhelp32Snapshot");

		myProcess32First = (PROCESSWALK)GetProcAddress (hModule, "Process32First");
		myProcess32Next  = (PROCESSWALK)GetProcAddress (hModule, "Process32Next");
  
		if( ! myCreateToolhelp32Snapshot || !myProcess32First || !myProcess32Next )
			return 0;

		myEnumProcessModules = DummyProcessModules;
		myGetModuleFileNameEx = GetModuleFileNameEx95;
		return 1;
	}

	return 0;															// unsupported OS
}

//---------------------------------------------------------------------
// DummyProcessModules
//---------------------------------------------------------------------
BOOL WINAPI DummyProcessModules(	HANDLE hProcess,		// handle to the process
									HMODULE * lphModule,	// array to receive the module handles
									DWORD cb,				// size of the array
									LPDWORD lpcbNeeded )	// receives the number of bytes returned 
{
	lphModule[0] = (HMODULE) *lpcbNeeded;
	*lpcbNeeded = 1;
	return 1;
}


//---------------------------------------------------------------------
// GetModuleFilenameEx95
//---------------------------------------------------------------------
DWORD WINAPI GetModuleFileNameEx95( HANDLE hProcess, 
									HMODULE hModule, 
									LPTSTR lpstrFileName, 
									DWORD n )
{
	HANDLE h;
	DWORD pid = (DWORD) hModule;

	h = myCreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
	if(!h)
		return 0;

	PROCESSENTRY32 proc;
	proc.dwSize = sizeof (proc);

	if(myProcess32First(h, &proc))
	do
		if(proc.th32ProcessID == pid)
		{
		  CloseHandle (h);
		  strcpy (lpstrFileName, proc.szExeFile);
		  return 1;
		}
	while (myProcess32Next (h, &proc));

	CloseHandle (h);

	return 0;
}

//------------------------------------------------------------
// ConvertToIp
//------------------------------------------------------------
PCHAR ConvertToIp( UINT ipaddr, PCHAR name ) 
{
	UINT nipaddr;

	nipaddr = htonl( ipaddr );

	sprintf( name, "%d.%d.%d.%d", 
			(nipaddr >> 24) & 0xFF, 
			(nipaddr >> 16) & 0xFF, 
			(nipaddr >> 8) & 0xFF, 
			(nipaddr) & 0xFF );

	return name;
}

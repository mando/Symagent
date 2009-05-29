/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Agent to obtain system information from Linux
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					08 Dec 2003
#		Last Modified:				11 Jan 2004
#		
#######################################################################
*/

#if !defined(LINUX_PROC)
#define LINUX_PROC

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"
#include "common-info.h"

#include <netdb.h>

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TInfoCollector;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Class TInfoCollector
//---------------------------------------------------------------------
class TInfoCollector
{
	public:
		
		TInfoCollector ();
			// Constructor
		
		TInfoCollector (const TInfoCollector& obj);
			// Copy constructor
		
		virtual ~TInfoCollector ();
			// Destructor
			// and stores it internally.
		
		virtual void Collect (ProcessInfoMap& procInfoMap, NetworkConnectionMap& netConnMap);
			// Collects the information and destructively modifies the arguments
			// to contain it.
	
	protected:
		
		static void _GetNetworkConnections (NetworkConnectionMap& netConnMap);
			// Collects information about the currently-open network
			// connections and stores it internally.
		
		static void _GetRunningProcessInfo (ProcessInfoMap& procInfoMap, const NetworkConnectionMap& netConnMap);
			// Collects information about the currently-running processes
		
		static void _GetDirContents (const string& dirPath,
									 StdStringList& filenameList,
									 bool includeInvisibles,
									 bool includeFiles,
									 bool includeDirs,
									 bool symLinksAsFiles,
									 const string& pattern,
									 bool throwOnError);
			// Get the contents of the directory specified by dirPath, which
			// should be a full path with a file system delimiter at the end.
			// Destructively modified the filenameList argument to contain
			// the found files.
		
		static void _ReadWholeFile (const string& filePath,
									string& bufferObj,
									bool followSymLinks = true,
									bool throwOnError = true);
			// Reads the file indicated by filePath, destructively modifying
			// bufferObj to with the file's contents.
		
		static void _ReadSymbolicLink (const string& filePath,
									   string& bufferObj,
									   bool throwOnError = true);
			// Reads the contents of the symbolic link pointed to by filePath,
			// destructively modifying bufferObj with the contents.
		
		static uint16_t _HexEthernetToUInt (const string& addrStr);
			// Given a hexadecimal string up to four characters long, this
			// method converts the string to a number and returns it in network
			// byte order.
		
		
		static unsigned long _HexEthernetToULong (const string& addrStr);
			// Given a hexadecimal string up to eight characters long, this
			// method converts the string to a number and returns it in network
			// byte order.
		
		static string _HexEthernetToIPv4Addr (const string& addrStr);
			// Converts the hexadecimal string representing an IPv4 address
			// to a readable string and returns it.
		
		static string _HexEthernetToIPv6Addr (const string& addrStr);
			// Converts the hexadecimal string representing an IPv6 address
			// to a readable string and returns it.
		
		static string _IPAddressAsString (const struct in_addr& addr);
			// Converts the given IPv4 address structure to a string and returns it.
		
		#if HAVE_DECL_AF_INET6
			static string _IPAddressAsString (const struct in6_addr& addr);
				// Converts the given IPv6 address structure to a string and returns it.
		#endif
};

//---------------------------------------------------------------------
#endif // LINUX_PROC

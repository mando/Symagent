/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Agent to obtain system information
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Last Modified:				04 Jan 2004
#		Last Modified:				04 Jan 2004
#		
#######################################################################
*/

#if !defined(AGENT_COMMON_INFO)
#define AGENT_COMMON_INFO

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include <map>
#include <string>
#include <vector>

//---------------------------------------------------------------------
// Import symbols
//---------------------------------------------------------------------
using std::map;
using std::pair;
using std::string;
using std::vector;

//---------------------------------------------------------------------
// Definitions common to all process acquisition methods
//---------------------------------------------------------------------

// Lookup with protocol ID mapping to its name
typedef	map<int,string>									ProtocolMap;
typedef	ProtocolMap::iterator							ProtocolMap_iter;
typedef	ProtocolMap::const_iterator						ProtocolMap_const_iter;

// Lookup with protocol family ID mapping to its name
typedef	map<int,string>									ProtoFamilyMap;
typedef	ProtoFamilyMap::iterator						ProtoFamilyMap_iter;
typedef	ProtoFamilyMap::const_iterator					ProtoFamilyMap_const_iter;

// Lookup with a service ID mapping to its name
typedef	map<pair<int,string>,string>					ServiceMap;
typedef	ServiceMap::iterator							ServiceMap_iter;
typedef	ServiceMap::const_iterator						ServiceMap_const_iter;

struct	NetworkConnection
	{
		int					protoFamily;	// matches key within ProtoFamilyMap
		int					protoID;		// matches key within ProtocolMap
		string				sourceAddr;
		long				sourcePort;
		string				destAddr;
		long				destPort;
	};

// Lookup between an Inode (next) and a network connection
typedef	map<long,NetworkConnection>						NetworkConnectionMap;
typedef	NetworkConnectionMap::iterator					NetworkConnectionMap_iter;
typedef	NetworkConnectionMap::const_iterator			NetworkConnectionMap_const_iter;

// List of open files/network conneciton IDs.  Can be anything, really.  The numbers
// here are used to lookup information within NetworkConnectionMap.
typedef	vector<long>									InodeList;
typedef	InodeList::iterator								InodeList_iter;
typedef	InodeList::const_iterator						InodeList_const_iter;

struct	ProcessInfo
	{
		string				path;			// Full path to executing application, if possible
		string				appSig;			// SHA-1 signature of application binary
		uid_t				ownerID;		// ID of owner of application
		gid_t				groupID;		// ID of group of application, if possible (zero otherwise)
		InodeList			inodeList;		// List of open files/network connection IDs
	};

// Lookup between a process ID and process information we've collected
typedef	map<pid_t,ProcessInfo>							ProcessInfoMap;
typedef	ProcessInfoMap::iterator						ProcessInfoMap_iter;
typedef	ProcessInfoMap::const_iterator					ProcessInfoMap_const_iter;

//---------------------------------------------------------------------
#endif // AGENT_COMMON_INFO

/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		UberAgent file
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					18 Dec 2003
#		Last Modified:				11 Feb 2004
#		
#######################################################################
*/

#if !defined(UBERAGENT_DEFS)
#define UBERAGENT_DEFS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-api.h"

#include <map>
#include <string>
#include <vector>

//---------------------------------------------------------------------
// Import symbols
//---------------------------------------------------------------------
using namespace symbiot;

using std::map;
using std::pair;
using std::string;
using std::vector;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define	kErrorNoPreferences								-24101
#define	kErrorRequiresSuperUserPerms					-24102
#define	kErrorNoPluginsFound							-24103
#define	kErrorPluginFunctionMissing						-24104
#define	kErrorPluginDirPermissionsBad					-24105
#define	kErrorPluginPermissionsBad						-24106

#define	kUberAgentName									"symagent"

//---------------------------------------------------------------------
#endif // UBERAGENT_DEFS

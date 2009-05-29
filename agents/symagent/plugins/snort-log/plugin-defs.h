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
#		Created:					11 Jan 2004
#		Last Modified:				10 Mar 2004
#		
#######################################################################
*/

#if !defined(PLUGIN_DEFS)
#define PLUGIN_DEFS

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
using std::string;
using std::vector;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

#define	kMessageNodeWatchFile							"WATCH_FILE"
#define	kMessageAttributeFilePath							"path"
#define	kMessageAttributeWatchInterval						"watch_interval"
#define	kMessageAttributeFormat								"format"

#define	kMessageAttributeValueCompact					"compact"

//---------------------------------------------------------------------
#endif // PLUGIN_DEFS

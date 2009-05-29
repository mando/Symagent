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
#		Last Modified:				02 Mar 2004
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
using std::pair;
using std::string;
using std::vector;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

#define	kPluginVersion									"1.0.0"

#define	kDebugWithoutServer								0

#define	kErrorNoPreferences								-24101
#define	kErrorKVMReadFailed								-24102

#define	kMessageTagTransmitInterval						"TRANSMIT_INTERVAL"
#define	kMessageAttributeValue							"value"

//---------------------------------------------------------------------
#endif // PLUGIN_DEFS

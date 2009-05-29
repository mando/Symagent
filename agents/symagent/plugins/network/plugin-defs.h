/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Plugin to report network activity in realtime
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					18 Dec 2003
#		Last Modified:				10 Feb 2004
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

#define	kMessageNodeInterface							"INTERFACE"
#define	kMessageAttributeDevice								"device"
#define	kMessageAttributeValueAnyDevice						"any"
#define	kMessageAttributeValuePrimaryDevice					"primary"
#define kMessageAttributeTransmitInterval				"transmit_interval"
#define kMessageAttributeReportingMode					"report"
#define	kMessageAttributeValueReportingModeNormal			"normal"
#define	kMessageAttributeValueReportingModeSummary			"summary"
#define kMessageAttributeFilter							"filter"

typedef	map<pair<unsigned int,string>,string>			ServiceMap;
typedef	ServiceMap::iterator							ServiceMap_iter;
typedef	ServiceMap::const_iterator						ServiceMap_const_iter;

//---------------------------------------------------------------------
#endif // PLUGIN_DEFS

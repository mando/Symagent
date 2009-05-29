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
#		Last Modified:				22 Mar 2004
#		
#######################################################################
*/

#if !defined(PLUGIN_MAIN)
#define PLUGIN_MAIN

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"
#include "plugin-defs.h"
#include "plugin-utils.h"
#include "sniff-task.h"

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

void ParseConfigAndCreateTask (const string& device, ReportingMode reportingMode, TPreferenceNode& prefNode);
	// Walks through the configuration info cited in 'prefNode' for device
	// 'device' and creates a task object for it.

//---------------------------------------------------------------------
#endif // PLUGIN_MAIN

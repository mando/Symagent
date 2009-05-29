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
#		Created:					28 Jan 2004
#		Last Modified:				28 Jan 2004
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

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------
string LocateNmap ();
	// Searches in likely places on the local computer for the nmap
	// application and, if it is found, returns a full path to it.
	// If not found then an empty string is returned.

bool HandleNmapOutput (const std::string& returnedData,
					   AppExecRef taskRef,
					   void* userData);
	// Callback function that handle's nmap output

//---------------------------------------------------------------------
#endif // PLUGIN_MAIN

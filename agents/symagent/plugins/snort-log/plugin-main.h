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
#		Last Modified:				11 Jan 2004
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

bool SnortLogCallback (const string& filePath,
					   const FileWatchFileInfo& currentInfo,
					   const FileWatchFileInfo& prevInfo,
					   FileWatcherRef taskRef,
					   void* userData);
	// Function is called when the file watcher task in libsymbiot
	// detects a change in Snort's fastlog log file.

//---------------------------------------------------------------------
#endif // PLUGIN_MAIN

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
#		Last Modified:				12 Mar 2004
#		
#######################################################################
*/

#define __USE_W32_SOCKETS		

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "windows-proc.h"

#include "plugin-utils.h"
#include "win-processes.h"

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//*********************************************************************
// Class TInfoCollector
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TInfoCollector::TInfoCollector ()
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TInfoCollector::TInfoCollector (const TInfoCollector& obj)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TInfoCollector::~TInfoCollector ()
{
}

//---------------------------------------------------------------------
// TInfoCollector::Collect
//---------------------------------------------------------------------
void TInfoCollector::Collect (ProcessInfoMap& procInfoMap, NetworkConnectionMap& netConnMap)
{
	procInfoMap.clear();
	netConnMap.clear();
	
	// Calls into win-processes.cc
	GetRunningProcessInfo(procInfoMap,netConnMap);
}

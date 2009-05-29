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
#		Last Modified:				09 Mar 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-main.h"

#include "../../plugin-api.h"

#include "get-processes.h"

#include <iostream>
#include <unistd.h>

//---------------------------------------------------------------------
// Import the std namespace for convenience
//---------------------------------------------------------------------
using namespace std;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
static time_t											gLoopDuration = 0;
static pthread_once_t									gModInitControl = PTHREAD_ONCE_INIT;

//---------------------------------------------------------------------
// AgentName - API function
//---------------------------------------------------------------------
string AgentName ()
{
	return string(PROJECT_SHORT_NAME);
}

//---------------------------------------------------------------------
// AgentVersion - API function
//---------------------------------------------------------------------
string AgentVersion ()
{
	return string(kPluginVersion);
}

//---------------------------------------------------------------------
// AgentDescription - API function
//---------------------------------------------------------------------
string AgentDescription ()
{
	return string();
}

//---------------------------------------------------------------------
// AgentEnvironment - API function
//---------------------------------------------------------------------
void AgentEnvironment (TLoginDataNode& loginEnvNode)
{
	pthread_once(&gModInitControl,InitModEnviron);
	gLoopDuration = 0;
}

//---------------------------------------------------------------------
// AgentInit - API function
//---------------------------------------------------------------------
bool AgentInit (const TPreferenceNode& preferenceNode)
{
	bool				initialized = false;
	TPreferenceNode		transmitNode(preferenceNode.FindNode(kMessageTagTransmitInterval,"",""));
	
	gLoopDuration = 0;
	
	if (transmitNode.IsValid())
	{
		string	loopDurationStr(transmitNode.GetAttributeValue(kMessageAttributeValue));
		
		if (!loopDurationStr.empty())
		{
			gLoopDuration = static_cast<time_t>(StringToNum(loopDurationStr));
			initialized = true;
		}
		else
		{
			throw TSymLibErrorObj(kErrorNoPreferences,"No tasks found in server-based config");
		}
	}
	else
	{
		throw TSymLibErrorObj(kErrorNoPreferences,"No tasks found in server-based config");
	}
	
	return initialized;
}

//---------------------------------------------------------------------
// AgentRun - API function
//---------------------------------------------------------------------
void AgentRun ()
{
	TCollectProcessInfo*	taskObjPtr = NULL;
	
	// Create our thread environment
	CreateModEnviron();
	
	SetRunState(true);
	
	try
	{
		taskObjPtr = new TCollectProcessInfo(gLoopDuration,gLoopDuration > 0);
		
		AddTaskToQueue(taskObjPtr,true);
		
		// Wait for it to kick off
		PauseExecution(1);
		
		while (DoPluginEventLoop() && IsTaskInQueue(taskObjPtr))
			PauseExecution(.5);
		
		if (IsTaskInQueue(taskObjPtr))
			DestroyTask(taskObjPtr);
	}
	catch (...)
	{
		if (IsTaskInQueue(taskObjPtr))
			DestroyTask(taskObjPtr);
		SetRunState(false);
		throw;
	}
	
	SetRunState(false);
}

//---------------------------------------------------------------------
// AgentStop - API function
//---------------------------------------------------------------------
void AgentStop ()
{
	SetRunState(false);
}

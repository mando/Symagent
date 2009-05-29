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
#		Last Modified:				09 Mar 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-main.h"

#include "../../plugin-api.h"

#include <iostream>
#include <unistd.h>

//---------------------------------------------------------------------
// Import the std namespace for convenience
//---------------------------------------------------------------------
using namespace std;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
struct ModGlobals
	{
		SniffTaskPtrList			taskList;
	};

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
static	ModGlobals*										gModGlobalsPtr = NULL;
static	TPthreadMutexObj								gModGlobalsMutex;

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
	StdStringList	interfaceList;
	unsigned long	interfaceCount = TPCAPObj::GetInterfaceList(interfaceList);
	
	if (!gModGlobalsPtr)
	{
		// Initialize the environment
		InitModEnviron();
		
		// Instantiate our global variables
		gModGlobalsPtr = new ModGlobals;
	}
	else
	{
		// Delete our old global variables to clear them out
		delete(gModGlobalsPtr);
		
		// Instantiate new global variables
		gModGlobalsPtr = new ModGlobals;
	}
	
	if (interfaceCount > 0)
	{
		// We do have network interfaces.  How sweet!
		loginEnvNode.SetTag("INTERFACE_LIST");
		
		for (StdStringList_const_iter x = interfaceList.begin(); x != interfaceList.end(); x++)
		{
			if (*x != "any" && *x != "lo")
				loginEnvNode.Append("INTERFACE","device",*x);
		}
	}
}

//---------------------------------------------------------------------
// AgentInit - API function
//---------------------------------------------------------------------
bool AgentInit (const TPreferenceNode& preferenceNode)
{
	bool				initialized = false;
	
	if (gModGlobalsPtr)
	{
		TLockedPthreadMutexObj	lock(gModGlobalsMutex);
		
		if (preferenceNode.IsValid())
		{
			// First check to see if there is an "any" device
			TPreferenceNode		anyDeviceNode(preferenceNode.FindNode(kMessageNodeInterface,kMessageAttributeDevice,kMessageAttributeValueAnyDevice));
			
			if (anyDeviceNode.IsValid())
			{
				StdStringList	interfaceList;
				string			reportingTypeString(anyDeviceNode.GetAttributeValue(kMessageAttributeReportingMode));
				ReportingMode	reportingMode;
				
				// Determining the reporting mode code
				if (reportingTypeString == kMessageAttributeValueReportingModeNormal)
					reportingMode = kReportingModeNormal;
				else if (reportingTypeString == kMessageAttributeValueReportingModeSummary)
					reportingMode = kReportingModeSummary;
				else
					reportingMode = kReportingModeNormal;
				
				// We found an "any" device.  Get a list of network devices and spawn a task for each
				// using the other parameters found in the configuration node
				
				if (TPCAPObj::GetInterfaceList(interfaceList) > 0)
				{
					for (StdStringList_const_iter x = interfaceList.begin(); x != interfaceList.end(); x++)
					{
						if (*x != "any" && *x != "lo")
							ParseConfigAndCreateTask(*x,reportingMode,anyDeviceNode);
					}
				}
			}
			else
			{
				for (unsigned long x = 0; x < preferenceNode.SubnodeCount(); x++)
				{
					TPreferenceNode		prefNode(preferenceNode.GetNthSubnode(x));
					
					if (prefNode.GetTag() == kMessageNodeInterface)
					{
						string			device(prefNode.GetAttributeValue(kMessageAttributeDevice));
						string			reportingTypeString(prefNode.GetAttributeValue(kMessageAttributeReportingMode));
						ReportingMode	reportingMode;
						
						// Determining the reporting mode code
						if (reportingTypeString == kMessageAttributeValueReportingModeNormal)
							reportingMode = kReportingModeNormal;
						else if (reportingTypeString == kMessageAttributeValueReportingModeSummary)
							reportingMode = kReportingModeSummary;
						else
							reportingMode = kReportingModeNormal;
						
						if (device == kMessageAttributeValuePrimaryDevice)
						{
							// Ask pcap to provide an interface name
							device = TPCAPObj::LookupDevice();
						}
						
						ParseConfigAndCreateTask(device,reportingMode,prefNode);
					}
				}
			}
		}
		
		if (!gModGlobalsPtr->taskList.empty())
			initialized = true;
	}
	
	return initialized;
}

//---------------------------------------------------------------------
// AgentRun - API function
//---------------------------------------------------------------------
void AgentRun ()
{
	// Create our thread environment
	CreateModEnviron();
	
	if (gModGlobalsPtr)
	{
		SniffTaskPtrList		taskObjPtrList;
		
		SetRunState(true);
		
		try
		{
			if (!gModGlobalsPtr->taskList.empty())
			{
				{
					TLockedPthreadMutexObj	lock(gModGlobalsMutex);
					
					for (SniffTaskPtrList_iter x = gModGlobalsPtr->taskList.begin(); x != gModGlobalsPtr->taskList.end(); x++)
					{
						(*x)->ResetParentThreadEnviron(GetModEnviron());
						AddTaskToQueue(*x,true);
					}
					
					taskObjPtrList = gModGlobalsPtr->taskList;
					gModGlobalsPtr->taskList.clear();
				}
				
				if (!taskObjPtrList.empty())
				{
					// Give them time to startup
					PauseExecution(1);
					
					while (DoPluginEventLoop())
					{
						SniffTaskPtrList			newTaskObjPtrList;
						
						for (SniffTaskPtrList_const_iter x = taskObjPtrList.begin(); x != taskObjPtrList.end(); x++)
						{
							if (IsTaskInQueue(*x))
								newTaskObjPtrList.push_back(*x);
						}
						
						if (!newTaskObjPtrList.empty())
						{
							taskObjPtrList = newTaskObjPtrList;
							PauseExecution(.5);
						}
						else
						{
							// None of the tasks we spawned are still running
							taskObjPtrList.clear();
							break;
						}
					}
					
					while (!taskObjPtrList.empty())
					{
						if (IsTaskInQueue(taskObjPtrList.back()))
							DestroyTask(taskObjPtrList.back());
						taskObjPtrList.pop_back();
					}
				}
			}
		}
		catch (...)
		{
			while (!taskObjPtrList.empty())
			{
				if (IsTaskInQueue(taskObjPtrList.back()))
					DestroyTask(taskObjPtrList.back());
				taskObjPtrList.pop_back();
			}
			SetRunState(false);
			throw;
		}
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

//---------------------------------------------------------------------
// ParseConfigAndCreateTask
//---------------------------------------------------------------------
void ParseConfigAndCreateTask (const string& device, ReportingMode reportingMode, TPreferenceNode& prefNode)
{
	if (gModGlobalsPtr)
	{
		const time_t			loopDuration(static_cast<time_t>(StringToNum(prefNode.GetAttributeValue(kMessageAttributeTransmitInterval))));
		string					filter(prefNode.GetAttributeValue(kMessageAttributeFilter));
		bool					promiscuous = (getuid() == 0);			// Promiscuous if we're root
		TSniffTask*				sniffTaskPtr = new TSniffTask(0,false);	// It loops forever
		
		// We need to explicitly remove all traffic between this system and the server
		if (!filter.empty())
			filter += " and ";
		filter += "(not (";
		filter += "host " + LocalIPAddressAsString() + " and " + ServerIPAddressAsString();
		filter += " and port " + NumToString(LocalIPPort()) + " and " + NumToString(ServerIPPort());
		filter += "))";
		
		// Spawn the task
		sniffTaskPtr->SetupTask(device,promiscuous,loopDuration,filter);
		sniffTaskPtr->SetReportingMode(reportingMode);
		gModGlobalsPtr->taskList.push_back(sniffTaskPtr);
	}
}

/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Plugin agent to lookup remote machines' MAC addresses
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					03 Feb 2004
#		Last Modified:				09 Mar 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-main.h"

#include "lookup-task.h"

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
#define	kPluginVersion									"1.0.0"
#define	kDebugMode										0

struct	ScanParams
	{
		string				device;
		string				target;
		time_t				scanInterval;
		ScanParams () : scanInterval(0) {}
	};

typedef	vector<ScanParams>								ScanParamsList;
typedef	ScanParamsList::iterator						ScanParamsList_iter;
typedef	ScanParamsList::const_iterator					ScanParamsList_const_iter;

struct	ModGlobals
	{
		StdStringList		interfaceList;
		ScanParamsList		scanParamsList;
	};

typedef	vector<TLookupMACAddrTask*>						LookupTaskObjList;
typedef	LookupTaskObjList::iterator						LookupTaskObjList_iter;
typedef	LookupTaskObjList::const_iterator				LookupTaskObjList_const_iter;

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
static ModGlobals*										gModGlobalsPtr = NULL;
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
	
	if (gModGlobalsPtr->interfaceList.empty())
	{
		StdStringList_iter	foundIter;
		
		// Get the interface list
		NetworkInterfaceList(gModGlobalsPtr->interfaceList);
		
		// Remove some interface names
		while ((foundIter = find(gModGlobalsPtr->interfaceList.begin(),gModGlobalsPtr->interfaceList.end(),"any")) != gModGlobalsPtr->interfaceList.end())
			gModGlobalsPtr->interfaceList.erase(foundIter);
		while ((foundIter = find(gModGlobalsPtr->interfaceList.begin(),gModGlobalsPtr->interfaceList.end(),"lo")) != gModGlobalsPtr->interfaceList.end())
			gModGlobalsPtr->interfaceList.erase(foundIter);
	}
	
	if (!gModGlobalsPtr->interfaceList.empty())
	{
		// We do have network interfaces.  How sweet!
		loginEnvNode.SetTag("INTERFACE_LIST");
		
		for (StdStringList_const_iter x = gModGlobalsPtr->interfaceList.begin(); x != gModGlobalsPtr->interfaceList.end(); x++)
			loginEnvNode.Append("INTERFACE","device",*x);
	}
}

//---------------------------------------------------------------------
// AgentInit - API function
//---------------------------------------------------------------------
bool AgentInit (const TPreferenceNode& preferenceNode)
{
	bool			initialized = false;
	
	if (gModGlobalsPtr)
	{
		TLockedPthreadMutexObj	lock(gModGlobalsMutex);
		
		if (!gModGlobalsPtr->interfaceList.empty())
		{
			#if kDebugMode
				ScanParams		aParam;
				
				aParam.device = "en0";
				aParam.target = "local_net";
				aParam.scanInterval = 30;
				
				gModGlobalsPtr->scanParamsList.push_back(aParam);
				
				initialized = true;
			#else
				if (preferenceNode.IsValid())
				{
					for (unsigned long x = 0; x < preferenceNode.SubnodeCount(); x++)
					{
						const TPreferenceNode		prefNode(preferenceNode.GetNthSubnode(x));
						
						if (prefNode.GetTag() == "SCAN")
						{
							string			device(prefNode.GetAttributeValue("device"));
							string			target(prefNode.GetAttributeValue("target"));
							time_t			scanInterval(static_cast<time_t>(StringToNum(prefNode.GetAttributeValue("interval"))));
							
							// Assign a default watch interval if we weren't given one
							if (scanInterval <= 0)
								scanInterval = 60;
							
							if (!target.empty())
							{
								if (device == "any")
								{
									for (StdStringList_const_iter y = gModGlobalsPtr->interfaceList.begin(); y != gModGlobalsPtr->interfaceList.end(); y++)
									{
										ScanParams		aParam;
										
										aParam.device = *y;
										aParam.target = target;
										aParam.scanInterval = scanInterval;
										
										gModGlobalsPtr->scanParamsList.push_back(aParam);
										
										initialized = true;
									}
								}
								else if (find(gModGlobalsPtr->interfaceList.begin(),gModGlobalsPtr->interfaceList.end(),device) != gModGlobalsPtr->interfaceList.end())
								{
									ScanParams		aParam;
									
									aParam.device = device;
									aParam.target = target;
									aParam.scanInterval = scanInterval;
									
									gModGlobalsPtr->scanParamsList.push_back(aParam);
									
									initialized = true;
								}
							}
						}
					}
				}
			#endif
		}
	}
	
	return initialized;
}

//---------------------------------------------------------------------
// AgentRun - API function
//---------------------------------------------------------------------
void AgentRun ()
{
	LookupTaskObjList		taskObjPtrList;
	
	// Create our thread environment
	CreateModEnviron();
	
	SetRunState(true);
	
	if (gModGlobalsPtr)
	{
		try
		{
			{
				TLockedPthreadMutexObj	lock(gModGlobalsMutex);
				
				for (ScanParamsList_const_iter x = gModGlobalsPtr->scanParamsList.begin(); x != gModGlobalsPtr->scanParamsList.end(); x++)
				{
					TLookupMACAddrTask*		taskObjPtr = new TLookupMACAddrTask;
					
					taskObjPtrList.push_back(taskObjPtr);
					taskObjPtr->SetupTask(x->device,x->target,x->scanInterval);
					AddTaskToQueue(taskObjPtr,true);
				}
				
				gModGlobalsPtr->scanParamsList.clear();
			}
			
			if (!taskObjPtrList.empty())
			{
				// Wait for the tasks to startup
				PauseExecution(1);
				
				while (DoPluginEventLoop())
				{
					LookupTaskObjList			newTaskObjPtrList;
					
					for (LookupTaskObjList_const_iter x = taskObjPtrList.begin(); x != taskObjPtrList.end(); x++)
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
		catch (TSymLibErrorObj& errObj)
		{
			if (!errObj.IsLogged())
			{
				WriteToErrorLog(errObj.GetDescription());
				errObj.MarkAsLogged();
			}
			while (!taskObjPtrList.empty())
			{
				if (IsTaskInQueue(taskObjPtrList.back()))
					DestroyTask(taskObjPtrList.back());
				taskObjPtrList.pop_back();
			}
			SetRunState(false);
			throw;
		}
		catch (...)
		{
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

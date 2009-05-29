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
#		Last Modified:				09 Mar 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-main.h"

#include "plugin-send-info.h"

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

struct	NmapExecInfo
	{
		string						application;
		string						appArgs;
		time_t						scanInterval;
		string						serverRef;
	};

typedef	vector<NmapExecInfo>							NMAPArgsList;
typedef	NMAPArgsList::iterator							NMAPArgsList_iter;
typedef	NMAPArgsList::const_iterator					NMAPArgsList_const_iter;

typedef	map<AppExecRef,string>							ServerRefMap;
typedef	ServerRefMap::const_iterator					ServerRefMap_const_iter;

struct	ModGlobals
	{
		NMAPArgsList				nmapArgsList;
		ServerRefMap				serverRefMap;
	};

typedef	vector<AppExecRef>								AppExecRefList;
typedef	AppExecRefList::iterator						AppExecRefList_iter;
typedef	AppExecRefList::const_iterator					AppExecRefList_const_iter;

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
	string		nmapPath;
	string		nmapVersion;
	string		nmapSig;
	
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
	
	nmapPath = LocateNmap();
	if (!nmapPath.empty())
	{
		string	getVersionCmd;
		
		getVersionCmd = nmapPath + " --version";
		nmapVersion = ExecApplication(getVersionCmd);
		Trim(nmapVersion);
		
		nmapSig = GetFileSignature(nmapPath);
	}
	
	loginEnvNode.SetTag("NMAP_INFO");
	loginEnvNode.AddAttribute("path",nmapPath);
	loginEnvNode.AddAttribute("version",nmapVersion);
	loginEnvNode.AddAttribute("sig",nmapSig);
}

//---------------------------------------------------------------------
// AgentInit - API function
//---------------------------------------------------------------------
bool AgentInit (const TPreferenceNode& preferenceNode)
{
	bool		initialized = false;
	string		nmapPath(LocateNmap());
	
	if (gModGlobalsPtr)
	{
		TLockedPthreadMutexObj	lock(gModGlobalsMutex);
		
		gModGlobalsPtr->nmapArgsList.clear();
		
		if (preferenceNode.IsValid() && !nmapPath.empty())
		{
			for (unsigned long x = 0; x < preferenceNode.SubnodeCount(); x++)
			{
				const TPreferenceNode		prefNode(preferenceNode.GetNthSubnode(x));
				
				if (prefNode.GetTag() == "NMAP_ARGS")
				{
					string			args(prefNode.GetAttributeValue("args"));
					string			serverRef(prefNode.GetAttributeValue("ref"));
					time_t			scanInterval(static_cast<time_t>(StringToNum(prefNode.GetAttributeValue("interval"))));
					StdStringList	argList;
					
					// Split the args into a list
					SplitStdString (' ',args,argList,false);
					
					// Put the arg list back together, skipping -o options
					args = "";
					for (StdStringList_const_iter i = argList.begin(); i != argList.end(); i++)
					{
						if (i->find("-o") != 0 && *i != "-")
						{
							if (!args.empty())
								args += " ";
							args += *i;
						}
					}
					
					if (scanInterval < 0)
						scanInterval = 0;
					
					if (!args.empty())
					{
						NmapExecInfo		info;
						
						// Build the command, including the option that causes nmap
						// to output its findings in XML format to stdout
						info.application = nmapPath;
						info.appArgs = "-oX - " + args;
						info.scanInterval = scanInterval;
						info.serverRef = serverRef;
						
						gModGlobalsPtr->nmapArgsList.push_back(info);
					}
				}
			}
		}
		
		if (!gModGlobalsPtr->nmapArgsList.empty())
			initialized = true;
	}
	
	return initialized;
}

//---------------------------------------------------------------------
// AgentRun - API function
//---------------------------------------------------------------------
void AgentRun ()
{
	AppExecRefList			appExecRefList;
	
	// Create our thread environment
	CreateModEnviron();
	
	if (gModGlobalsPtr)
	{
		SetRunState(true);
		
		try
		{
			if (!gModGlobalsPtr->nmapArgsList.empty())
			{
				{
					TLockedPthreadMutexObj	lock(gModGlobalsMutex);
					
					gModGlobalsPtr->serverRefMap.clear();
					
					for (NMAPArgsList_iter x = gModGlobalsPtr->nmapArgsList.begin(); x != gModGlobalsPtr->nmapArgsList.end(); x++)
					{
						AppExecRef		appExecRef = CreateAppExecTask(x->application,x->appArgs,"",x->scanInterval);
						
						appExecRefList.push_back(appExecRef);
						AddAppExecCallback(appExecRef,HandleNmapOutput);
						QueueAppExecTask(appExecRef,true);
						
						gModGlobalsPtr->serverRefMap[appExecRef] = x->serverRef;
					}
					
					gModGlobalsPtr->nmapArgsList.clear();
				}
				
				if (!appExecRefList.empty())
				{
					// Wait for the tasks to startup
					PauseExecution(1);
					
					while (DoPluginEventLoop())
					{
						AppExecRefList			newAppExecRefList;
						
						for (AppExecRefList_const_iter x = appExecRefList.begin(); x != appExecRefList.end(); x++)
						{
							if (IsAppExecTaskInQueue(*x))
								newAppExecRefList.push_back(*x);
						}
						
						if (!newAppExecRefList.empty())
						{
							appExecRefList = newAppExecRefList;
							PauseExecution(.5);
						}
						else
						{
							// None of the tasks we spawned are still running
							appExecRefList.clear();
							break;
						}
					}
					
					while (!appExecRefList.empty())
					{
						if (IsAppExecTaskInQueue(appExecRefList.back()))
							DestroyAppExecTask(appExecRefList.back());
						appExecRefList.pop_back();
					}
				}
			}
		}
		catch (...)
		{
			while (!appExecRefList.empty())
			{
				if (IsAppExecTaskInQueue(appExecRefList.back()))
					DestroyAppExecTask(appExecRefList.back());
				appExecRefList.pop_back();
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
// LocateNmap
//---------------------------------------------------------------------
string LocateNmap ()
{
	StdStringList	dirList;
	
	// Populate the directory list with directories where nmap can be found
	dirList.push_back("/usr/bin/");
	dirList.push_back("/usr/local/bin/");
	dirList.push_back("/usr/sbin/");
	dirList.push_back("/usr/local/sbin/");
	dirList.push_back("/sbin/");
	
	// Now do the search
	return LocateFile("nmap",dirList);
}

//---------------------------------------------------------------------
// HandleNmapOutput
//---------------------------------------------------------------------
bool HandleNmapOutput (const std::string& returnedData,
					   AppExecRef taskRef,
					   void* /* userData */)
{
	string		serverRef;
	
	if (IsConnectedToServer())
	{
		if (gModGlobalsPtr)
		{
			TLockedPthreadMutexObj		lock(gModGlobalsMutex);
			ServerRefMap_const_iter 	foundIter = gModGlobalsPtr->serverRefMap.find(taskRef);
			
			if (foundIter != gModGlobalsPtr->serverRefMap.end())
				serverRef = foundIter->second;
			
			AddTaskToQueue(new TSendInfoTask(returnedData,serverRef),true);
		}
	}
	
	// This is the only callback for any nmap call, so we
	// will always return true here
	return true;
}

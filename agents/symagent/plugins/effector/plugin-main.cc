/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		symagent effector file
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					27 May 2004
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
#define	kPluginVersion									"1.0.0"

#define	kStateUndefined									0
#define	kStateFindApp									1
#define	kStateRunApp									2

struct	ModGlobals
	{
		unsigned int			state;
		string					application;
		StdStringList			searchPathList;
		string					versionCmd;
		
		ModGlobals () : state(kStateUndefined) {}
	};

#define	kXMLTagFindApp									"FIND_APP"
#define	kXMLTagAppSearch								"APP_SEARCH"
#define	kXMLTagFoundApp									"FOUND_APP"

#define	kXMLTagExecApp									"EXEC_APP"
#define	kXMLTagAppResults								"APP_RESULTS"

#define	kXMLAttributeAppName							"app"
#define	kXMLAttributePaths								"paths"
#define	kXMLAttributeFullPath							"full_path"
#define	kXMLAttributeVersionCommand						"version_cmd"
#define	kXMLAttributeSignature							"sig"
#define	kXMLAttributeVersion							"version"
#define	kXMLAttributeArgString							"arg_string"

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
}

//---------------------------------------------------------------------
// AgentInit - API function
//---------------------------------------------------------------------
bool AgentInit (const TPreferenceNode& preferenceNode)
{
	if (gModGlobalsPtr)
	{
		TLockedPthreadMutexObj	lock(gModGlobalsMutex);
		
		gModGlobalsPtr->state = kStateUndefined;
		
		if (preferenceNode.IsValid())
		{
			for (unsigned long x = 0; x < preferenceNode.SubnodeCount(); x++)
			{
				const TPreferenceNode		prefNode(preferenceNode.GetNthSubnode(x));
				
				if (prefNode.GetTag() == kXMLTagFindApp)
				{
					string			appName(prefNode.GetAttributeValue(kXMLAttributeAppName));
					string			paths(prefNode.GetAttributeValue(kXMLAttributePaths));
					string			versionCommand(prefNode.GetAttributeValue(kXMLAttributeVersionCommand));
					StdStringList	pathList;
					
					if (!appName.empty())
					{
						if (paths.empty())
						{
							// Setup some default paths
							pathList.push_back("/usr/bin/");
							pathList.push_back("/usr/local/bin/");
							pathList.push_back("/usr/sbin/");
							pathList.push_back("/usr/local/sbin/");
							pathList.push_back("/sbin/");
						}
						else
						{
							SplitStdString(':',paths,pathList,false);
						}
						
						if (!pathList.empty())
						{
							gModGlobalsPtr->application = appName;
							gModGlobalsPtr->searchPathList = pathList;
							gModGlobalsPtr->versionCmd = versionCommand;
							
							gModGlobalsPtr->state = kStateFindApp;
						}
					}
				}
				else if (prefNode.GetTag() == kXMLTagExecApp)
				{
					string			appPath(prefNode.GetAttributeValue(kXMLAttributeAppName));
					string			argString(prefNode.GetAttributeValue(kXMLAttributeArgString));
					string			fullCommand;
					
					if (!appPath.empty())
					{
						fullCommand = appPath;
						if (!argString.empty())
							fullCommand += " " + argString;
						
						gModGlobalsPtr->state = kStateRunApp;
						gModGlobalsPtr->application = fullCommand;
						gModGlobalsPtr->searchPathList.clear();
						gModGlobalsPtr->versionCmd = "";
					}
				}
			}
		}
	}
	
	return gModGlobalsPtr->state != kStateUndefined;
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
		TLockedPthreadMutexObj	lock(gModGlobalsMutex);
		
		SetRunState(true);
		
		try
		{
			TServerMessage		messageObj;
			TServerReply		replyObj;
			TMessageNode		topNode;
			bool				messageMade = false;
			
			if (IsConnectedToServer())
			{
				if (gModGlobalsPtr->state == kStateFindApp)
				{
					topNode = messageObj.Append(kXMLTagAppSearch,kXMLAttributeAppName,gModGlobalsPtr->application);
					
					for (StdStringList_const_iter aPath = gModGlobalsPtr->searchPathList.begin(); aPath != gModGlobalsPtr->searchPathList.end(); aPath++)
					{
						StdStringList		searchDirList;
						string				foundPath;
						string				versionInfo;
						string				appSig;
						
						searchDirList.push_back(*aPath);
						foundPath = LocateFile(gModGlobalsPtr->application,searchDirList);
						if (!foundPath.empty())
						{
							TMessageNode		foundNode;
							
							// Found the app here
							if (!gModGlobalsPtr->versionCmd.empty())
							{
								string	getVersionCmd;
								
								getVersionCmd = foundPath + " " + gModGlobalsPtr->versionCmd;
								versionInfo = ExecApplication(getVersionCmd);
								Trim(versionInfo);
							}
							
							// Compute the signature
							appSig = GetFileSignature(foundPath);
							
							foundNode = topNode.Append(kXMLTagFoundApp,kXMLAttributeFullPath,foundPath);
							foundNode.AddAttribute(kXMLAttributeSignature,appSig);
							foundNode.AddAttribute(kXMLAttributeVersion,versionInfo);
							
							messageMade = true;
						}
					}
				}
				else if (gModGlobalsPtr->state == kStateRunApp)
				{
					string	appOutput(ExecApplication(gModGlobalsPtr->application));
					string	dataToSend;
					
					Trim(appOutput);
					dataToSend = "<![CDATA[" + appOutput + "]]>";
					
					topNode = messageObj.Append(kXMLTagAppResults,kXMLAttributeAppName,gModGlobalsPtr->application);
					topNode.SetData(dataToSend);
					messageMade = true;
				}
				
				if (messageMade)
				{
					// Send info to the server
					SendToServer(messageObj,replyObj);
				}
			}
		}
		catch (...)
		{
			SetRunState(false);
			gModGlobalsPtr->state = kStateUndefined;
			throw;
		}
	}
	
	gModGlobalsPtr->state = kStateUndefined;
	SetRunState(false);
}

//---------------------------------------------------------------------
// AgentStop - API function
//---------------------------------------------------------------------
void AgentStop ()
{
	SetRunState(false);
}

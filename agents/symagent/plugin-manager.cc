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
#		Last Modified:				06 Jan 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-manager.h"

#include <sys/types.h>

#if defined(USE_DLOPEN) && USE_DLOPEN && HAVE_DLFCN_H
	#include "dlfcn.h"
#endif

#if HAVE_DIRENT_H
	#include <dirent.h>
	#define NAMLEN(dirent) strlen((dirent)->d_name)
#else
	#define dirent direct
	#define NAMLEN(dirent) (dirent)->d_namlen
	#if HAVE_SYS_NDIR_H
		#include <sys/ndir.h>
	#endif
	#if HAVE_SYS_DIR_H
		#include <sys/dir.h>
	#endif
	#if HAVE_NDIR_H
		#include <ndir.h>
	#endif
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <unistd.h>

#if !defined(RTLD_LOCAL)
	#define RTLD_LOCAL 0
#endif

//---------------------------------------------------------------------
// Import the std namespace for convenience
//---------------------------------------------------------------------
using namespace std;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//*********************************************************************
// Class TPlugin
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPlugin::TPlugin (const string& pluginPath)
	:	fHandle(NULL),
		fPath(pluginPath),
		fAgentNameProcPtr(NULL),
		fAgentVersionProcPtr(NULL),
		fAgentDescriptionProcPtr(NULL),
		fAgentEnvironmentProcPtr(NULL),
		fAgentInitProcPtr(NULL),
		fAgentRunProcPtr(NULL),
		fAgentStopProcPtr(NULL),
		fIsLoaded(false),
		fIsActivated(false)
{
	// Go ahead and try to load the plugin
	Load();
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPlugin::~TPlugin ()
{
	Unload();
}

//---------------------------------------------------------------------
// TPlugin::AgentEnvironment
//---------------------------------------------------------------------
void TPlugin::AgentEnvironment (TLoginDataNode& loginEnvNode)
{
	if (fAgentEnvironmentProcPtr)
		fAgentEnvironmentProcPtr(loginEnvNode);
}

//---------------------------------------------------------------------
// TPlugin::AgentInit
//---------------------------------------------------------------------
bool TPlugin::AgentInit (const TPreferenceNode& preferenceNode)
{
	fIsInited = (fAgentInitProcPtr ? fAgentInitProcPtr(preferenceNode) : false);
	
	return fIsInited;
}

//---------------------------------------------------------------------
// TPlugin::AgentRun
//---------------------------------------------------------------------
void TPlugin::AgentRun ()
{
	if (fAgentRunProcPtr && fIsInited)
	{
		try
		{
			fAgentRunProcPtr();
		}
		catch (...)
		{
			
		}
	}
}

//---------------------------------------------------------------------
// TPlugin::AgentSpawn
//---------------------------------------------------------------------
void TPlugin::AgentSpawn ()
{
	TPluginRunner*		taskObjPtr = new TPluginRunner(this);
	
	if (taskObjPtr)
		AddTaskToQueue(taskObjPtr,true);
}

//---------------------------------------------------------------------
// TPlugin::AgentStop
//---------------------------------------------------------------------
void TPlugin::AgentStop ()
{
	if (IsRunning())
	{
		time_t	expireTime = 0;;
		
		fAgentStopProcPtr();
		
		// Wait for a reasonable time to see if we can stop gracefully
		expireTime = time(NULL) + 5;
		while (IsRunning() && time(NULL) < expireTime)
			PauseExecution(.1);
		
		if (IsRunning())
		{
			// Playing nice didn't work; let's nuke the threads
			while (!fTaskObjPtrList.empty())
			{
				TPluginRunner*			taskObjPtr = NULL;
				
				{
					TLockedPthreadMutexObj	lock(fLock);
					
					if (!fTaskObjPtrList.empty())
						taskObjPtr = fTaskObjPtrList.back();
				}
				
				if (taskObjPtr)
				{
					if (IsTaskInQueue(taskObjPtr))
						DestroyTask(taskObjPtr);
					
					RemoveTaskObjPtr(taskObjPtr);
				}
			}
		}
	}
}

//---------------------------------------------------------------------
// TPlugin::Load
//---------------------------------------------------------------------
bool TPlugin::Load ()
{
	int			loadFlags = RTLD_NOW | RTLD_LOCAL;
	
	if (!fPath.empty())
	{
		try
		{
			fHandle = dlopen(fPath.c_str(),loadFlags);
			if (fHandle)
			{
				// Resolve our symbols
				
				fAgentNameProcPtr = FindSymbol<AgentNameProcPtr>("AgentName");
				if (!fAgentNameProcPtr)
				{
					string	errString;
					
					errString = "AgentName() API function not implemented in plugin at '" + fPath + "'";
					throw TSymLibErrorObj(kErrorPluginFunctionMissing,errString);
				}
				
				fAgentVersionProcPtr = FindSymbol<AgentVersionProcPtr>("AgentVersion");
				if (!fAgentVersionProcPtr)
				{
					string	errString;
					
					errString = "AgentVersion() API function not implemented in plugin at '" + fPath + "'";
					throw TSymLibErrorObj(kErrorPluginFunctionMissing,errString);
				}
				
				fAgentEnvironmentProcPtr = FindSymbol<AgentEnvironmentProcPtr>("AgentEnvironment");
				if (!fAgentEnvironmentProcPtr)
				{
					string	errString;
					
					errString = "AgentEnvironment() API function not implemented in plugin at '" + fPath + "'";
					throw TSymLibErrorObj(kErrorPluginFunctionMissing,errString);
				}
				
				fAgentDescriptionProcPtr = FindSymbol<AgentDescriptionProcPtr>("AgentDescription");
				if (!fAgentDescriptionProcPtr)
				{
					string	errString;
					
					errString = "AgentDescription() API function not implemented in plugin at '" + fPath + "'";
					throw TSymLibErrorObj(kErrorPluginFunctionMissing,errString);
				}
				
				fAgentInitProcPtr = FindSymbol<AgentInitProcPtr>("AgentInit");
				if (!fAgentInitProcPtr)
				{
					string	errString;
					
					errString = "AgentInit() API function not implemented in plugin at '" + fPath + "'";
					throw TSymLibErrorObj(kErrorPluginFunctionMissing,errString);
				}
				
				fAgentRunProcPtr = FindSymbol<AgentRunProcPtr>("AgentRun");
				if (!fAgentRunProcPtr)
				{
					string	errString;
					
					errString = "AgentRun() API function not implemented in plugin at '" + fPath + "'";
					throw TSymLibErrorObj(kErrorPluginFunctionMissing,errString);
				}
				
				fAgentStopProcPtr = FindSymbol<AgentStopProcPtr>("AgentStop");
				if (!fAgentStopProcPtr)
				{
					string	errString;
					
					errString = "AgentStop() API function not implemented in plugin at '" + fPath + "'";
					throw TSymLibErrorObj(kErrorPluginFunctionMissing,errString);
				}
				
				// Compute and save our signature
				fSignature = GetFileSignature(fPath);
				
				// Mark the plugin as fully loaded
				fIsLoaded = true;
			}
		}
		catch (TSymLibErrorObj& errObj)
		{
			if (!errObj.IsLogged())
			{
				string		errString;
				
				errString += "While loading plugin '" + fPath + "': " + errObj.GetDescription();
				WriteToErrorLog(errObj.GetDescription());
				errObj.MarkAsLogged();
			}
		}
		catch (int errNum)
		{
			string		errString;
			
			errString = "While loading plugin '" + fPath + "': Generic Error: ";
			errString += NumberToString(errNum);
			WriteToErrorLog(errString);
		}
		catch (...)
		{
			string		errString;
			
			errString += "While loading plugin '" + fPath + "': Unknown Error";
			WriteToErrorLog(errString);
		}
	}
	
	return fIsLoaded;
}

//---------------------------------------------------------------------
// TPlugin::Unload
//---------------------------------------------------------------------
void TPlugin::Unload ()
{
	if (fHandle)
		dlclose(fHandle);
	
	fHandle = NULL;
	fAgentNameProcPtr = NULL;
	fAgentVersionProcPtr = NULL;
	fAgentDescriptionProcPtr = NULL;
	fIsLoaded = false;
	fIsInited = false;
}

//*********************************************************************
// Class TPluginMgr
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPluginMgr::TPluginMgr ()
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPluginMgr::~TPluginMgr ()
{
	Clear();
}

//---------------------------------------------------------------------
// TPluginMgr::Clear
//---------------------------------------------------------------------
void TPluginMgr::Clear ()
{
	for (PluginMap_iter x = fPluginMap.begin(); x != fPluginMap.end(); x++)
		delete(x->second);
	
	fPluginMap.clear();
}

//---------------------------------------------------------------------
// TPluginMgr::LocatePlugins
//---------------------------------------------------------------------
void TPluginMgr::LocatePlugins (PluginSigMap& pluginSigMap)
{
	TLockedPthreadMutexObj	lock(fLock);
	
	_GetPluginFilenames(pluginSigMap,false);
}

//---------------------------------------------------------------------
// TPluginMgr::LoadPlugins
//---------------------------------------------------------------------
bool TPluginMgr::LoadPlugins (const StdStringList& pluginPathList)
{
	bool					success = false;
	TLockedPthreadMutexObj	lock(fLock);
	
	if (!pluginPathList.empty())
	{
		for (StdStringList_const_iter x = pluginPathList.begin(); x != pluginPathList.end(); x++)
		{
			TPlugin*	pluginObjPtr = NULL;
			string		pluginPath(*x);
			
			try
			{
				pluginObjPtr = new TPlugin(pluginPath);
				if (pluginObjPtr)
				{
					if (pluginObjPtr->IsLoaded())
					{
						// Add the plugin to our internal map if the name doesn't already exist
						if (fPluginMap.find(pluginObjPtr->AgentName()) == fPluginMap.end())
							fPluginMap[pluginObjPtr->AgentName()] = pluginObjPtr;
						else
							delete(pluginObjPtr);
					}
					else
					{
						delete(pluginObjPtr);
					}
				}
			}
			catch (TSymLibErrorObj& errObj)
			{
				string	errString;
				
				errString = "Error while loading plugin '" + pluginPath + "': ";
				errString += errObj.GetDescription();
				WriteToErrorLog(errString);
				
				if (pluginObjPtr)
					delete(pluginObjPtr);
			}
			catch (...)
			{
				string	errString;
				
				errString = "Unknown error while loading plugin '" + pluginPath + "'";
				WriteToErrorLog(errString);
				
				if (pluginObjPtr)
					delete(pluginObjPtr);
			}
		}
		
		if (!fPluginMap.empty())
			success = true;
	}
	
	return success;
}

//---------------------------------------------------------------------
// TPluginMgr::PluginNameList
//---------------------------------------------------------------------
void TPluginMgr::PluginNameList (StdStringList& nameList)
{
	TLockedPthreadMutexObj	lock(fLock);
	
	nameList.clear();
	
	for (PluginMap_const_iter x = fPluginMap.begin(); x != fPluginMap.end(); x++)
		nameList.push_back(x->first);
}

//---------------------------------------------------------------------
// TPluginMgr::GetPluginPtr
//---------------------------------------------------------------------
TPlugin* TPluginMgr::GetPluginPtr (const string& pluginName)
{
	TPlugin*				pluginObjPtr = NULL;
	TLockedPthreadMutexObj	lock(fLock);
	PluginMap_iter			foundIter = fPluginMap.find(pluginName);
	
	if (foundIter != fPluginMap.end())
		pluginObjPtr = foundIter->second;
	
	return pluginObjPtr;
}

//---------------------------------------------------------------------
// TPluginMgr::StopAllPlugins
//---------------------------------------------------------------------
void TPluginMgr::StopAllPlugins ()
{
	for (PluginMap_iter x = fPluginMap.begin(); x != fPluginMap.end(); x++)
		x->second->AgentStop();
}

//---------------------------------------------------------------------
// TPluginMgr::DeactivateAllPlugins
//---------------------------------------------------------------------
void TPluginMgr::DeactivateAllPlugins ()
{
	for (PluginMap_iter x = fPluginMap.begin(); x != fPluginMap.end(); x++)
	{
		if (!x->second->IsRunning() && x->second->IsActivated())
			x->second->MarkAsDeactivated();
	}
}

//---------------------------------------------------------------------
// TPluginMgr::RunningCount
//---------------------------------------------------------------------
unsigned long TPluginMgr::RunningCount ()
{
	unsigned long		runCount = 0;
	
	for (PluginMap_const_iter x = fPluginMap.begin(); x != fPluginMap.end(); x++)
	{
		if (x->second->IsRunning())
			++runCount;
	}
	
	return runCount;
}

//---------------------------------------------------------------------
// TPluginMgr::_GetPluginFilenames (static protected)
//---------------------------------------------------------------------
void TPluginMgr::_GetPluginFilenames (PluginSigMap& pluginSigMap, bool throwOnError)
{
	string				dirPath(PLUGIN_PATH);
	struct dirent*		dirEntryPtr = NULL;
	struct dirent		dirEntry;
	DIR*				dirPtr = NULL;
	struct stat 		statInfo;
	string				fullPath;
	int					statResult;
	string				errString;
	
	pluginSigMap.clear();
	
	dirPtr = opendir(dirPath.c_str());
	
	if (!dirPtr && throwOnError)
	{
		errString = "";
		errString += "While attempting to open directory '" + dirPath + "'";
		throw TSymLibErrorObj(errno,errString);
	}
	
	if (dirPtr)
	{
		try
		{
			do
			{
				#if HAVE_READDIR_R
					// Use the reentrant version
					if (readdir_r(dirPtr,&dirEntry,&dirEntryPtr) != 0)
					{
						if (throwOnError)
						{
							errString = "";
							errString += "While attempting to obtain contents of directory '" + dirPath + "'";
							throw TSymLibErrorObj(errno,errString);
						}
						else
						{
							dirEntryPtr = NULL;
						}
					}
				#else
					dirEntryPtr = readdir(dirPtr);
					// Get a copy so other processes don't trip us up
					if (dirEntryPtr)
						memcpy(&dirEntry,dirEntryPtr,sizeof(dirEntry));
				#endif
				
				if (dirEntryPtr)
				{
					if (strcmp(dirEntry.d_name,".") != 0 & strcmp(dirEntry.d_name,"..") != 0)
					{
						fullPath = dirPath;
						if (fullPath.empty())
							fullPath = "./";
						else if (fullPath[fullPath.length()-1] != '/')
							fullPath += "/";
						fullPath += dirEntry.d_name;
						
						statResult = lstat(fullPath.c_str(),&statInfo);
						
						if (statResult == 0)
						{
							// Don't look at symlinks at all
							if (!S_ISLNK(statInfo.st_mode) && S_ISREG(statInfo.st_mode))
							{
								if (fnmatch("*.so",dirEntry.d_name,FNM_PERIOD) == 0)
								{
									// Verify that the file has the correct permissions
									if (!VerifyExactFilePerms(fullPath,S_IRWXU,getuid()))
									{
										string		errString;
										
										errString = "Plugin '" + fullPath + "' does not have the correct permissions and will not be loaded";
										WriteToErrorLog(errString);
									}
									else
									{
										// Remember the file path and the signature
										pluginSigMap[fullPath] = GetFileSignature(fullPath);
									}
								}
							}
						}
					}
				}
			}
			while (dirEntryPtr);
		}
		catch (...)
		{
			// Make sure the directory pointer is closed
			if (dirPtr)
				closedir(dirPtr);
			dirPtr = NULL;
			throw;
		}
	}
	
	// Make sure the directory pointer is closed
	if (dirPtr)
		closedir(dirPtr);
	dirPtr = NULL;
}

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
#		Last Modified:				09 Mar 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-main.h"

#include "parser-attack-log.h"

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

struct	FileEntry
	{
		string						path;
		string						format;
		time_t						interval;
	};

typedef	vector<FileEntry>								FileEntryList;
typedef	FileEntryList::iterator							FileEntryList_iter;
typedef	FileEntryList::const_iterator					FileEntryList_const_iter;

typedef	map<FileWatcherRef,string>						UnclaimedLogData;

struct	WatcherInfo
	{
		string						outputFormat;
		string						unclaimedData;
	};

typedef	map<FileWatcherRef,WatcherInfo>					FileWatcherInfo;

struct	ModGlobals
	{
		FileEntryList				fileEntryList;
		FileWatcherInfo				info;
	};

typedef	vector<FileWatcherRef>							FileWatcherRefList;
typedef	FileWatcherRefList::iterator					FileWatcherRefList_iter;
typedef	FileWatcherRefList::const_iterator				FileWatcherRefList_const_iter;

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
	bool				initialized = false;
	
	if (gModGlobalsPtr)
	{
		if (preferenceNode.IsValid())
		{
			for (unsigned long x = 0; x < preferenceNode.SubnodeCount(); x++)
			{
				const TPreferenceNode		prefNode(preferenceNode.GetNthSubnode(x));
				
				if (prefNode.GetTag() == kMessageNodeWatchFile)
				{
					string		path(prefNode.GetAttributeValue(kMessageAttributeFilePath));
					string		outFormat(prefNode.GetAttributeValue(kMessageAttributeFormat));
					time_t		watchInterval(static_cast<time_t>(StringToNum(prefNode.GetAttributeValue(kMessageAttributeWatchInterval))));
					
					// Assign a default watch interval if we weren't given one
					if (watchInterval <= 0)
						watchInterval = 5;
					
					if (!path.empty())
					{
						TLockedPthreadMutexObj	lock(gModGlobalsMutex);
						FileEntry				newEntry;
						
						newEntry.path = path;
						newEntry.format = outFormat;
						newEntry.interval = watchInterval;
						
						gModGlobalsPtr->fileEntryList.push_back(newEntry);
					}
				}
			}
		}
		
		if (!gModGlobalsPtr->fileEntryList.empty())
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
		FileWatcherRefList			fileWatcherRefList;
		
		SetRunState(true);
		
		try
		{
			if (!gModGlobalsPtr->fileEntryList.empty())
			{
				{
					TLockedPthreadMutexObj	lock(gModGlobalsMutex);
					
					if (!gModGlobalsPtr->fileEntryList.empty())
					{
						for (FileEntryList_const_iter x = gModGlobalsPtr->fileEntryList.begin(); x != gModGlobalsPtr->fileEntryList.end(); x++)
						{
							FileWatcherRef		watcherRef = CreateFileWatcherTask(x->path,x->interval);
							
							fileWatcherRefList.push_back(watcherRef);
							gModGlobalsPtr->info[watcherRef].outputFormat = x->format;
							AddFileWatcherCallback(watcherRef,kFileWatchChangeFlagDataSize,SnortLogCallback);
							QueueFileWatcherTask(watcherRef,true);
						}
						
						gModGlobalsPtr->fileEntryList.clear();
					}
					else
					{
						SetRunState(false);
					}
				}
				
				if (!fileWatcherRefList.empty())
				{
					// Wait for the tasks to startup
					PauseExecution(1);
					
					while (DoPluginEventLoop())
					{
						FileWatcherRefList			newFileWatcherRefList;
						
						for (FileWatcherRefList_const_iter x = fileWatcherRefList.begin(); x != fileWatcherRefList.end(); x++)
						{
							if (IsFileWatcherTaskInQueue(*x))
								newFileWatcherRefList.push_back(*x);
						}
						
						if (!newFileWatcherRefList.empty())
						{
							fileWatcherRefList = newFileWatcherRefList;
							PauseExecution(.5);
						}
						else
						{
							// None of the tasks we spawned are still running
							fileWatcherRefList.clear();
							break;
						}
					}
					
					while (!fileWatcherRefList.empty())
					{
						if (IsFileWatcherTaskInQueue(fileWatcherRefList.back()))
							DestroyFileWatcherTask(fileWatcherRefList.back());
						fileWatcherRefList.pop_back();
					}
				}
			}
		}
		catch (...)
		{
			while (!fileWatcherRefList.empty())
			{
				if (IsFileWatcherTaskInQueue(fileWatcherRefList.back()))
					DestroyFileWatcherTask(fileWatcherRefList.back());
				fileWatcherRefList.pop_back();
			}
			{
				TLockedPthreadMutexObj	lock(gModGlobalsMutex);
				
				gModGlobalsPtr->fileEntryList.clear();
			}
			SetRunState(false);
			throw;
		}
		
		while (!fileWatcherRefList.empty())
		{
			if (IsFileWatcherTaskInQueue(fileWatcherRefList.back()))
				DestroyFileWatcherTask(fileWatcherRefList.back());
			fileWatcherRefList.pop_back();
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
// SnortLogCallback
//---------------------------------------------------------------------
bool SnortLogCallback (const string& filePath,
					   const FileWatchFileInfo& currentInfo,
					   const FileWatchFileInfo& prevInfo,
					   FileWatcherRef taskRef,
					   void* /* userData */)
{
	std::string	debugString;
	
	// debugString = "DEBUG: Start SnortLogCallback";
	// WriteToMessagesLog(debugString);
	
	if (IsConnectedToServer() && gModGlobalsPtr)
	{
		string		newLogData;
		string		outputFormat;
		
		{
			TLockedPthreadMutexObj	lock(gModGlobalsMutex);
			
			newLogData = gModGlobalsPtr->info[taskRef].unclaimedData;
			gModGlobalsPtr->info[taskRef].unclaimedData = "";
			
			outputFormat = gModGlobalsPtr->info[taskRef].outputFormat;
		
			// debugString = "DEBUG: SnortLogCallback: Found unclaimed data: " + newLogData + " :: " +  outputFormat;
			// WriteToMessagesLog(debugString);
		}
		
		newLogData += GetNewFileWatcherData(taskRef);
		
		if (!newLogData.empty())
		{
			// debugString = "DEBUG: SnortLogCallback: Found new data: " + newLogData;
			// WriteToMessagesLog(debugString);
			
			if (newLogData[newLogData.length()-1] != '\n')
			{
				// The last line of the new data isn't a full line.
				// We need to chop it off and save it for the next time
				TLockedPthreadMutexObj	lock(gModGlobalsMutex);
				StdStringList			lineList;
				
				SplitStdString('\n',newLogData,lineList,false);
				gModGlobalsPtr->info[taskRef].unclaimedData = lineList.back();
				lineList.pop_back();
				newLogData = JoinStdStringList('\n',lineList);
				
				// debugString = "DEBUG: SnortLogCallback: Did some trimming of incomplete last line";
				// WriteToMessagesLog(debugString);
			}
		}
		
		if (!newLogData.empty())
		{
			// debugString = "DEBUG: SnortLogCallback: Pre TParserAttackLog";
			// WriteToMessagesLog(debugString);
				
			TParserAttackLog*	taskObjPtr = new TParserAttackLog(filePath,newLogData,outputFormat);			
			AddTaskToQueue(taskObjPtr,true);
			
			// debugString = "DEBUG: SnortLogCallback: Post TParserAttackLog";
			// WriteToMessagesLog(debugString);
		}
	}
	
	// Always claim to have handled the event
	return true;
}

/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		log-watcher file
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					15 Apr 2004
#		Last Modified:				09 Mar 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-main.h"

#include "send-msg.h"
#include "grep-obj.h"

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
		TGrepSet					grepSet;
		time_t						interval;
		FileWatchStyle				watchStyle;
		string						unclaimedData;
	};

typedef	vector<FileEntry>								FileEntryList;
typedef	FileEntryList::iterator							FileEntryList_iter;
typedef	FileEntryList::const_iterator					FileEntryList_const_iter;

typedef	map<FileWatcherRef,FileEntry>					FileWatcherInfo;

typedef	vector<FileWatcherRef>							FileWatcherRefList;
typedef	FileWatcherRefList::iterator					FileWatcherRefList_iter;
typedef	FileWatcherRefList::const_iterator				FileWatcherRefList_const_iter;

struct	ModGlobals
	{
		FileWatcherInfo				info;
		FileEntryList				fileEntryList;
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
	int	pcreVar = 0;
	
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
	
	// Tell the server about our capabilities
	loginEnvNode.SetTag(kMessageNodePCREInfo);
	#if USE_PCRE
		loginEnvNode.AddAttribute(kMessageAttributePCREEnabled,kMessageAttributeValueTrue);
		loginEnvNode.AddAttribute(kMessageAttributePCREVersion,pcre_version());
		pcre_config(PCRE_CONFIG_UTF8,&pcreVar);
		if (pcreVar == 1)
			loginEnvNode.AddAttribute(kMessageAttributePCREUTF8,kMessageAttributeValueTrue);
		else
			loginEnvNode.AddAttribute(kMessageAttributePCREUTF8,kMessageAttributeValueFalse);
	#else
		loginEnvNode.AddAttribute(kMessageAttributePCREEnabled,kMessageAttributeValueFalse);
	#endif
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
				const TPreferenceNode		watchFileNode(preferenceNode.GetNthSubnode(x));
				FileEntry					aFileEntry;
				
				if (watchFileNode.GetTag() == kMessageNodeWatchFile)
				{
					string		watchStyleStr(watchFileNode.GetAttributeValue(kMessageAttributeWatchStyle));
					
					aFileEntry.path = watchFileNode.GetAttributeValue(kMessageAttributeFilePath);
					aFileEntry.interval = static_cast<time_t>(StringToNum(watchFileNode.GetAttributeValue(kMessageAttributeWatchInterval)));
					
					if (watchStyleStr == kMessageAttributeValueContents)
						aFileEntry.watchStyle = kWatchStyleContents;
					else
						aFileEntry.watchStyle = kWatchStyleTail;
					
					// Assign a default watch interval if we weren't given one
					if (aFileEntry.interval <= 0)
						aFileEntry.interval = 5;
					
					if (!aFileEntry.path.empty())
					{
						const TPreferenceNode		patternListNode(watchFileNode.FindNode(kMessageNodePatternList));
						
						if (patternListNode.IsValid())
						{
							for (unsigned long y = 0; y < patternListNode.SubnodeCount(); y++)
							{
								const TPreferenceNode		patternNode(patternListNode.GetNthSubnode(y));
								
								if (patternNode.GetTag() == kMessageNodePattern)
								{
									string	serverRef(patternNode.GetAttributeValue(kMessageAttributeServerRef));
									string	pattern(patternNode.GetAttributeValue(kMessageAttributePattern));
									string	options(patternNode.GetAttributeValue(kMessageAttributeOptions));
									
									if (!pattern.empty())
									{
										aFileEntry.grepSet.AddSearch(serverRef,pattern,options);
									}
								}
							}
						}
						
						if (!aFileEntry.grepSet.empty())
						{
							TLockedPthreadMutexObj	lock(gModGlobalsMutex);
							
							gModGlobalsPtr->fileEntryList.push_back(aFileEntry);
						}
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
							FileWatcherRef		watcherRef = CreateFileWatcherTask(x->path,x->interval,x->watchStyle);
							
							fileWatcherRefList.push_back(watcherRef);
							gModGlobalsPtr->info[watcherRef] = *x;
							AddFileWatcherCallback(watcherRef,kFileWatchChangeFlagDataSize|kFileWatchChangeFlagContentsModified,LogWatchCallback);
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
// LogWatchCallback
//---------------------------------------------------------------------
bool LogWatchCallback (const string& filePath,
					   const FileWatchFileInfo& /* currentInfo */,
					   const FileWatchFileInfo& /* prevInfo */,
					   FileWatcherRef taskRef,
					   void* /* userData */)
{
	// std::string	debugString;
	
	// debugString = "DEBUG: Start LogWatchCallback";
	// WriteToMessagesLog(debugString);

	if (IsConnectedToServer() && gModGlobalsPtr)
	{
		TLockedPthreadMutexObj	lock(gModGlobalsMutex);
		string					newLogData(gModGlobalsPtr->info[taskRef].unclaimedData);
		
		gModGlobalsPtr->info[taskRef].unclaimedData = "";
		newLogData += GetNewFileWatcherData(taskRef);
		
		// debugString = "DEBUG: LogWatchCallback: Found new data: " + newLogData;
		// WriteToMessagesLog(debugString);
			
		if (!newLogData.empty())
		{
			bool			pushLastLine = (newLogData[newLogData.length()-1] != '\n');
			StdStringList	lineList;
			
			SplitStdString('\n',newLogData,lineList,false);
			
			if (pushLastLine)
			{
				gModGlobalsPtr->info[taskRef].unclaimedData = lineList.back();
				lineList.pop_back();
			}
			
			if (!lineList.empty())
			{
				FoundTextList		foundTextList;
				
				for (StdStringList_const_iter aLine = lineList.begin(); aLine != lineList.end(); aLine++)
				{
					StdStringList	matchingServerRefs;
					
					if (gModGlobalsPtr->info[taskRef].grepSet.AnyMatch(*aLine,matchingServerRefs))
					{
						for (StdStringList_const_iter x = matchingServerRefs.begin(); x != matchingServerRefs.end(); x++)
							foundTextList.push_back(make_pair(*x,*aLine));
					}
				}
				
				if (!foundTextList.empty())
				{
					// debugString = "DEBUG: LogWatchCallback: Pre TSendMsg";
					// WriteToMessagesLog(debugString);
			
					TSendMsg*	taskObjPtr = new TSendMsg(foundTextList);
					
					AddTaskToQueue(taskObjPtr,true);
					
					// debugString = "DEBUG: LogWatchCallback: Post TSendMsg";
					// WriteToMessagesLog(debugString);
				}
			}
		}
	}
	
	return false;
}

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
#		Last Modified:				30 Mar 2004
#		
#######################################################################
*/

#if !defined(PLUGIN_MANAGER)
#define PLUGIN_MANAGER

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "agent-config.h"
#include "agent-defs.h"
#include "agent-utils.h"
#include "plugin-api.h"

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef	map<string,string>					PluginSigMap;
typedef	PluginSigMap::iterator				PluginSigMap_iter;
typedef	PluginSigMap::const_iterator		PluginSigMap_const_iter;

//---------------------------------------------------------------------
// Forward Class Definitions
//---------------------------------------------------------------------
class TPlugin;
class TPluginMgr;

//---------------------------------------------------------------------
// Class TPlugin
//---------------------------------------------------------------------
class TPlugin
{
	protected:
		
		// Function pointers for plugin-api.h functions
		typedef	string (*AgentNameProcPtr)();
		typedef	string (*AgentVersionProcPtr)();
		typedef	string (*AgentDescriptionProcPtr)();
		typedef	void (*AgentEnvironmentProcPtr)(TLoginDataNode&);
		typedef	bool (*AgentInitProcPtr)(const TPreferenceNode&);
		typedef	void (*AgentRunProcPtr)();
		typedef	void (*AgentStopProcPtr)();
		
		//---------------------------------------------------------------------
		// Class TPluginRunner
		//---------------------------------------------------------------------
		class TPluginRunner : public TTaskBase
		{
			private:
				
				typedef	TTaskBase							Inherited;
			
			public:
				
				TPluginRunner (TPlugin* pluginPtr) : Inherited("",0,false),fPluginPtr(pluginPtr)
					{
						if (fPluginPtr)
						{
							string	logString;
							
							fAgentName = fPluginPtr->AgentName();
							
							Inherited::SetTaskName(fAgentName);
							
							logString = "Starting " + fAgentName + " task";
							logString += " (" + NumberToString(reinterpret_cast<unsigned long>(this)) + ")";
							WriteToMessagesLog(logString);
							
							fPluginPtr->InsertTaskObjPtr(this);
						}
					}
				
				virtual ~TPluginRunner ()
					{
						if (fPluginPtr)
						{
							string	logString;
							
							logString = "Stopping " + fAgentName + " task";
							logString += " (" + NumberToString(reinterpret_cast<unsigned long>(this)) + ")";
							WriteToMessagesLog(logString);
							
							fPluginPtr->RemoveTaskObjPtr(this);
						}
					}
				
				virtual void RunTask ()
					{
						if (fPluginPtr)
							fPluginPtr->AgentRun();
					}
			
			protected:
				
				TPlugin*									fPluginPtr;
				string										fAgentName;
		};
		
		typedef	vector<TPluginRunner*>				TaskObjPtrList;
		typedef	TaskObjPtrList::iterator			TaskObjPtrList_iter;
		typedef	TaskObjPtrList::const_iterator		TaskObjPtrList_const_iter;
	
	public:
		
		TPlugin (const string& pluginPath);
			// Constructor
	
	private:
		
		TPlugin (const TPlugin& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TPlugin ();
			// Destructor
		
		virtual void AgentEnvironment (TLoginDataNode& loginEnvNode);
			// Calls the agent's AgentEnvironment() API function.
		
		virtual bool AgentInit (const TPreferenceNode& preferenceNode);
			// Calls the agent's AgentInit() API function.
		
		virtual void AgentRun ();
			// Calls the agent's AgentRun() API function.
		
		virtual void AgentSpawn ();
			// Creates a separate execution thread and calls the agent's
			// AgentRun() API function within it.
		
		virtual void AgentStop ();
			// Calls the agent's AgentStop() API function.
		
		virtual bool Load ();
			// Attempts to load plugin cited by fPath.  Initializes
			// all internal slots, resolve symbols, etc..  Returns
			// true if everything is successful.
		
		virtual void Unload ();
			// Unloads the currently-loaded plugin and reinitializes the
			// internal slots to neutral values.
		
		//-----------------------------
		// Accessors
		//-----------------------------
		
		inline string Path () const
			{ return fPath; }
		
		inline string Signature () const
			{ return fSignature; }
		
		inline void InsertTaskObjPtr (TPluginRunner* taskObjPtr)
			{
				TLockedPthreadMutexObj	lock(fLock);
				
				fTaskObjPtrList.push_back(taskObjPtr);
			}
		
		inline void RemoveTaskObjPtr (TPluginRunner* taskObjPtr)
			{
				TLockedPthreadMutexObj		lock(fLock);
				TaskObjPtrList_iter			foundIter = find(fTaskObjPtrList.begin(),fTaskObjPtrList.end(),taskObjPtr);
				
				if (foundIter != fTaskObjPtrList.end())
					fTaskObjPtrList.erase(foundIter);
			}
		
		inline unsigned long RunningCount ()
			{
				TLockedPthreadMutexObj		lock(fLock);
				
				return fTaskObjPtrList.size();
			}
		
		inline bool IsRunning ()
			{
				TLockedPthreadMutexObj		lock(fLock);
				
				return !fTaskObjPtrList.empty();
			}
		
		inline string AgentName () const
			{ return (fAgentNameProcPtr ? fAgentNameProcPtr() : string()); }
		
		inline string AgentVersion () const
			{ return (fAgentVersionProcPtr ? fAgentVersionProcPtr() : string()); }
		
		inline string AgentDescription () const
			{ return (fAgentDescriptionProcPtr ? fAgentDescriptionProcPtr() : string()); }
		
		inline bool IsLoaded () const
			{ return fIsLoaded; }
		
		inline bool IsInited () const
			{ return fIsInited; }
		
		inline bool IsActivated () const
			{ return fIsActivated; }
		
		inline void MarkAsActivated ()
			{ fIsActivated = true; }
		
		inline void MarkAsDeactivated ()
			{ fIsActivated = false; }
	
	protected:
		
		template <class RETURN_TYPE>
		RETURN_TYPE FindSymbol (const string& symbolName)
			{
				RETURN_TYPE		address = NULL;
				
				if (fHandle)
					address = (RETURN_TYPE)(dlsym(fHandle,symbolName.c_str()));
				
				return address;
			}
			
	
	protected:
		
		void*										fHandle;
		string										fPath;
		string										fSignature;
		TPthreadMutexObj							fLock;
		unsigned long								fRunningCount;
		AgentNameProcPtr							fAgentNameProcPtr;
		AgentVersionProcPtr							fAgentVersionProcPtr;
		AgentDescriptionProcPtr						fAgentDescriptionProcPtr;
		AgentEnvironmentProcPtr						fAgentEnvironmentProcPtr;
		AgentInitProcPtr							fAgentInitProcPtr;
		AgentRunProcPtr								fAgentRunProcPtr;
		AgentStopProcPtr							fAgentStopProcPtr;
		TaskObjPtrList								fTaskObjPtrList;
		bool										fIsLoaded;
		bool										fIsInited;
		bool										fIsActivated;
};

//---------------------------------------------------------------------
// Class TPluginMgr
//---------------------------------------------------------------------
class TPluginMgr
{
	protected:
		
		typedef	map<string,TPlugin*>				PluginMap;
		typedef	PluginMap::iterator					PluginMap_iter;
		typedef	PluginMap::const_iterator			PluginMap_const_iter;
	
	public:
		
		TPluginMgr ();
			// Constructor
	
	private:
		
		TPluginMgr (const TPluginMgr& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TPluginMgr ();
			// Destructor
		
		virtual void Clear ();
			// Resets our internal slots.
		
		virtual void LocatePlugins (PluginSigMap& pluginSigMap);
			// Locates potentially-valid plugins, verifying filename format, ownership,
			// and permissions.  Destructively modifies the argument to contain a
			// map between found and valid plugins and their file signature.
		
		virtual bool LoadPlugins (const StdStringList& pluginPathList);
			// Loads the plugins cited in the argument, which should be a list of
			// full paths.  Returns true if any plugins were loaded.
		
		virtual void PluginNameList (StdStringList& nameList);
			// Destructively modifies the argument to contain a list of the loaded
			// plugins' short agent names.  The list will be sorted alphabetically.
			// Initialize() must be called before this method is called.
		
		virtual TPlugin* GetPluginPtr (const string& pluginName);
			// Method returns a pointer to the plugin object associated with the
			// name cited by the argument or NULL if a matching plugin can't be found.
		
		virtual void StopAllPlugins ();
			// Method finds all running plugins and calls each plugin's AgentStop()
			// API function.
		
		virtual void DeactivateAllPlugins ();
			// Marks all non-running, activated plugins as deactivated.
		
		virtual unsigned long RunningCount ();
			// Returns the number of currently-running plugins.  Note that this number
			// is different than the total number of plugins found and/or loaded.
		
		//-----------------------------
		// Accessors
		//-----------------------------
		
		inline unsigned long PluginCount () const
			{ return fPluginMap.size(); }
	
	protected:
		
		static void _GetPluginFilenames (PluginSigMap& pluginSigMap, bool throwOnError = true);
			// Destructively modifies the pluginSigMap argument to contain a list
			// of full paths to plugins and their corresponding signatures.  If
			// throwOnError is false then exception throwing is disabled.
	
	protected:
		
		PluginMap									fPluginMap;
		TPthreadMutexObj							fLock;
};

//---------------------------------------------------------------------
#endif // PLUGIN_MANAGER

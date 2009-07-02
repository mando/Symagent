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

#include "gather-task.h"
#include "catchup-task.h"
#include "stat-task.h"

#include "../../plugin-api.h"

#include <iostream>
#include <unistd.h>
#include <mysql/mysql.h>

//---------------------------------------------------------------------
// Import the std namespace for convenience
//---------------------------------------------------------------------
using namespace std;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define	kPluginVersion									"0.0.1"

struct MysqlConnectParams
    {
      std::string db;
      std::string server;
      std::string user;
      std::string pass;
    };

struct QueryParams
    {
      std::string max_cid;
      std::string min_cid;

      std::string catchup_max_cid;
      std::string catchup_min_cid;
  
      bool stat;
    };

typedef	vector<TGatherEventsTask*>                GatherTaskObjList;
typedef	GatherTaskObjList::iterator               GatherTaskObjList_iter;
typedef	GatherTaskObjList::const_iterator         GatherTaskObjList_const_iter;

struct ModGlobals
  {
    MysqlConnectParams  connectParams;
    QueryParams         queryParams;
  };

//---------------------------------------------------------------------
// Globals
//---------------------------------------------------------------------
//static pthread_once_t									gModInitControl = PTHREAD_ONCE_INIT;
static ModGlobals*                      gModGlobalsPtr  = NULL;
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
	// If you need to supply environmental information to the server
	// during login, populate the argument with that information.  Note
	// that the server will need to be able to understand it ....
	//
	// NOTE: This aspect needs lots more documentation

  if (!gModGlobalsPtr)
  {
		InitModEnviron();
		gModGlobalsPtr = new ModGlobals;
  }
  else 
  {
    delete(gModGlobalsPtr);
		gModGlobalsPtr = new ModGlobals;
  }
	//pthread_once(&gModInitControl,InitModEnviron);
}

//---------------------------------------------------------------------
// AgentInit - API function
//---------------------------------------------------------------------
bool AgentInit (const TPreferenceNode& preferenceNode)
{
  
  bool initialized = false;

  if (gModGlobalsPtr) {
    TLockedPthreadMutexObj lock(gModGlobalsMutex);

    if (preferenceNode.IsValid()) 
    { 
      for (unsigned long x = 0; x < preferenceNode.SubnodeCount(); x++)
      {
        const TPreferenceNode   prefNode(preferenceNode.GetNthSubnode(x));

        if (prefNode.GetTag() == "DB")
        {
          MysqlConnectParams cParam;

          cParam.server = prefNode.GetAttributeValue("host");
          cParam.db     = prefNode.GetAttributeValue("name");
          cParam.user   = prefNode.GetAttributeValue("user");
          cParam.pass   = prefNode.GetAttributeValue("pass");
          
          gModGlobalsPtr->connectParams = cParam;
        }

        if (prefNode.GetTag() == "PARAMS")
        {
          QueryParams        qParam;
          
          qParam.max_cid = prefNode.GetAttributeValue("max_cid");
          qParam.min_cid = prefNode.GetAttributeValue("min_cid");

          qParam.catchup_max_cid = prefNode.GetAttributeValue("catchup_max_cid");
          qParam.catchup_min_cid = prefNode.GetAttributeValue("catchup_min_cid");

          qParam.stat = false;

          if (!prefNode.GetAttributeValue("stat").empty()) {
            WriteToMessagesLog("stat isn't empty, so it's true!");
            WriteToMessagesLog("val of stat: |" + prefNode.GetAttributeValue("stat") + "|");
            qParam.stat = true;
          }

          gModGlobalsPtr->queryParams = qParam;
        }
      }
      initialized = true;
    }

  }
	return initialized;
}

//---------------------------------------------------------------------
// AgentRun - API function
//---------------------------------------------------------------------
void AgentRun ()
{
    WriteToMessagesLog("in AgentRun");
   
    GatherTaskObjList     taskObjPtrList;
    
    // Create our thread environment
	  CreateModEnviron();
	
	  SetRunState(true);

    if (gModGlobalsPtr) {
      
      try
      {
        TLockedPthreadMutexObj lock(gModGlobalsMutex);

        MysqlConnectParams cParams    = gModGlobalsPtr->connectParams;
        QueryParams qParams           = gModGlobalsPtr->queryParams; 
          
        TGatherEventsTask* gatherObjPtr   = new TGatherEventsTask;
        TStatEventsTask*   statObjPtr     = new TStatEventsTask;
        TCatchUpTask*      catchupObjPtr  = new TCatchUpTask;
       
        if (qParams.stat) 
        {
          WriteToMessagesLog("creating stat task");
          statObjPtr->SetupTask(cParams.db, cParams.server, cParams.user, cParams.pass);
          WriteToMessagesLog("adding stat task to queue");
          AddTaskToQueue(statObjPtr, true);
        } 
        else 
        {
          WriteToMessagesLog("creating first task");
          
          
          //TODO: I don't like sending 0 here for the min
          gatherObjPtr->SetupTask(cParams.db, cParams.server, cParams.user, cParams.pass, qParams.max_cid, "0");
          WriteToMessagesLog("adding first task to queue");
          AddTaskToQueue(gatherObjPtr,true);

          // Catchup task
          if (! qParams.catchup_max_cid.empty()) 
          {
            WriteToMessagesLog("registering catchup task.");
            //
            // TODO:  I'm flipping the min and max values to handle the catchup logic.  Not obvious:  should I make yet another task?
            //
            catchupObjPtr->SetupTask(cParams.db, cParams.server, cParams.user, cParams.pass, qParams.catchup_max_cid, qParams.catchup_min_cid);
            AddTaskToQueue(catchupObjPtr, true);
          }
        } 
          
        PauseExecution(1);
       
        if (!qParams.stat) 
        {
          while (DoPluginEventLoop()) 
          {
            //if (IsTaskInQueue(gatherObjPtr) || IsTaskInQueue(catchupObjPtr))
            //if (IsTaskInQueue(catchupObjPtr))
            if (IsTaskInQueue(gatherObjPtr))
            {
              PauseExecution(.5);
            } else 
            {
              break;
            }
          }
        }
      }
      catch (...)
      {
          WriteToMessagesLog("uhoh:  exception?");
          SetRunState(false);
          throw;
      }
    }

    WriteToMessagesLog("done running ");
    SetRunState(false);
}

//---------------------------------------------------------------------
// AgentStop - API function
//---------------------------------------------------------------------
void AgentStop ()
{
	SetRunState(false);
}


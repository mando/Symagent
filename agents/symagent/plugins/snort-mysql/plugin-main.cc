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
      std::string start_time;
      std::string end_time;
    };

typedef	vector<MysqlConnectParams>                MysqlConnectParamsList;
typedef	MysqlConnectParamsList::iterator          MysqlConnectParamsList_iter;
typedef	MysqlConnectParamsList::const_iterator    MysqlConnectParamsList_const_iter;

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
          QueryParams        qParam;

          cParam.server = prefNode.GetAttributeValue("host");
          cParam.db     = prefNode.GetAttributeValue("name");
          cParam.user   = prefNode.GetAttributeValue("user");
          cParam.pass   = prefNode.GetAttributeValue("pass");
          
          gModGlobalsPtr->connectParams = cParam;

          qParam.start_time = prefNode.GetAttributeValue("start_time");
          qParam.end_time   = prefNode.GetAttributeValue("end_time");

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
    TServerMessage  messageObj;
    TServerReply    replyObj;	
    
    // Create our thread environment
	  CreateModEnviron();
	
	  SetRunState(true);

    if (gModGlobalsPtr) {
      
      try
      {
        TLockedPthreadMutexObj lock(gModGlobalsMutex);

        TGatherEventsTask* taskObjPtr = new TGatherEventsTask;
        
        
        MysqlConnectParams cParams    = gModGlobalsPtr->connectParams;
        QueryParams qParams           = gModGlobalsPtr->queryParams; 
       
        taskObjPtr->SetupTask(cParams.db, cParams.server, cParams.user, cParams.pass, qParams.start_time, qParams.end_time);
        AddTaskToQueue(taskObjPtr,true);
        
        PauseExecution(1);
        
        while (DoPluginEventLoop()) {
          if (IsTaskInQueue(taskObjPtr)) {
            PauseExecution(.5);
          } else {
            break;
          }
        }
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


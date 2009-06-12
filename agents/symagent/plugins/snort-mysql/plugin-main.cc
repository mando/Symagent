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

typedef	vector<MysqlConnectParams>                MysqlConnectParamsList;
typedef	MysqlConnectParamsList::iterator          MysqlConnectParamsList_iter;
typedef	MysqlConnectParamsList::const_iterator    MysqlConnectParamsList_const_iter;

struct ModGlobals
  {
    MysqlConnectParams  connectParams;
  };

//---------------------------------------------------------------------
// Globals
//---------------------------------------------------------------------
static pthread_once_t									gModInitControl = PTHREAD_ONCE_INIT;
static ModGlobals*                    gModGlobalsPtr  = NULL;
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
		gModGlobalsPtr = new ModGlobals;
  }
  else 
  {
    delete(gModGlobalsPtr);
		gModGlobalsPtr = new ModGlobals;
  }
	pthread_once(&gModInitControl,InitModEnviron);
}

//---------------------------------------------------------------------
// AgentInit - API function
//---------------------------------------------------------------------
bool AgentInit (const TPreferenceNode& preferenceNode)
{
  bool initialized = false;

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
    }
    initialized = true;
  }
	return initialized;
}

//---------------------------------------------------------------------
// GatherEvents - Talk to MySQL 
//---------------------------------------------------------------------
void GatherEvents (TServerMessage& messageObj)
{
    TMessageNode  eventListNode(messageObj.Append("EVENTS", "", ""));

    MYSQL       *conn;
    MYSQL_RES   *result;
    MYSQL_ROW   row;

    conn = mysql_init(NULL);

    if (conn == NULL) {
        WriteToErrorLog("MySQL init ERROR");
    }

    if (mysql_real_connect(conn, gModGlobalsPtr->connectParams.server.c_str(), gModGlobalsPtr->connectParams.user.c_str(), gModGlobalsPtr->connectParams.pass.c_str(), gModGlobalsPtr->connectParams.db.c_str(), 0, NULL, 0) == NULL) {
        WriteToErrorLog("MySQL connect ERROR"); 
    }
    

    /* 
     * Make sure this query is good.  segfault otherwise.
     * TODO: Figure out the right way to handle bad queries (try/catch, etc.)
     *
     */
    mysql_query(conn, "select iphdr.ip_src, iphdr.ip_dst, signature.sig_sid, signature.sig_name, count(*) as sum from event, signature, iphdr where event.cid < 1000 and iphdr.cid = event.cid and signature.sig_id = event.signature group by ip_src, ip_dst, sig_name order by count(*) desc");

    result = mysql_store_result(conn);

    while ((row = mysql_fetch_row(result))) {
        string ip_src(row[0]);
        string ip_dst(row[1]);
        string sig_sid(row[2]);
        string sig_name(row[3]);
        string sum(row[4]);
        WriteToMessagesLog("SELECT Results:");
        WriteToMessagesLog("\t IP SRC: " + ip_src);
        WriteToMessagesLog("\t IP DST: " + ip_dst);
        WriteToMessagesLog("\t SIG ID: " + sig_sid);
        WriteToMessagesLog("\t SIG: " + sig_name);
        WriteToMessagesLog("\t SUM: " + sum);
    }

    mysql_free_result(result);
    mysql_close(conn);
    
    /*conn = dbi_conn_new("mysql");
    
    dbi_conn_set_option(conn, "host",     "64.128.30.207");
    dbi_conn_set_option(conn, "dbname",   "snort");
    dbi_conn_set_option(conn, "encoding", "UTF-8");
    dbi_conn_set_option(conn, "username", "snort");
    dbi_conn_set_option(conn, "password", "password");

    if (dbi_conn_connect(conn) < 0) {
        WriteToErrorLog("Could not connect."); 
    } else {
        result = dbi_conn_query(conn, "select count(0) count from events");

        long long count = 0;

        if (result) {
            while (dbi_result_next_row(result)) {
                count = dbi_result_get_longlong(result, "count");
                
                string logMessage;
                logMessage = "NUM OF EVENTS: ";
                std::stringstream appender;
                appender << count;
                logMessage += appender.str();

                WriteToMessagesLog(logMessage);
            }
            dbi_result_free(result);
        } else {
            WriteToErrorLog("No Results :(");
        }
        dbi_conn_close(conn);
    }
    dbi_shutdown();*/
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
	
	  try
	  {
    
        GatherEvents(messageObj);
        // Send it to the server
        SendToServer(messageObj,replyObj);
	  }
    catch (...)
    {
        SetRunState(false);
        throw;
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


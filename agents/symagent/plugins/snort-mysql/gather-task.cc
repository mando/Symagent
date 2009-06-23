/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Plugin agent to gather snort events from MySQL
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Mando Escamilla
#		e-mail: mando@symbiot.com
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "gather-task.h"
#include <mysql/mysql.h>

//*********************************************************************
// Class TGatherEventsTask
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TGatherEventsTask::TGatherEventsTask ()
	:	Inherited(PROJECT_SHORT_NAME,0,false),
		fParentEnvironPtr(GetModEnviron())
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TGatherEventsTask::~TGatherEventsTask ()
{
}

//---------------------------------------------------------------------
// TGatherEventsTask::SetupTask
//---------------------------------------------------------------------
void TGatherEventsTask::SetupTask (const string& db,
									const string& server,
									const string& user,
									const string& pass,
									const string& start_time,
									const string& end_time,
									time_t scanInterval)
{

	if (!db.empty())
		fdbName = db;
	else
		throw TSymLibErrorObj(kErrorDBNameNotSpecified,"Database Name not defined");
	
	if (!server.empty())
		fserverName = server;
	else
		throw TSymLibErrorObj(kErrorDBServerNotSpecified,"Database Server not defined");
	
  if (!user.empty())
		fuserName = user;
	else
		throw TSymLibErrorObj(kErrorUserNameNotSpecified,"User Name not defined");
  
  if (!pass.empty())
		fpassword = pass;
	else
		throw TSymLibErrorObj(kErrorPasswordNotSpecified,"Password not defined");
  
  if (!start_time.empty())
		fstartTime = start_time;
	else
		throw TSymLibErrorObj(kErrorStartTimeNotSpecified,"Start Time not defined");
  
  if (!end_time.empty())
		fendTime = end_time;
	else
		throw TSymLibErrorObj(kErrorEndTimeNotSpecified,"End Time not defined");
	
	if (scanInterval >= 0)
	{
		SetExecutionInterval(scanInterval);
		SetRerun(true);
	}
}

//---------------------------------------------------------------------
// TGatherEventsTask::RunTask
//---------------------------------------------------------------------
void TGatherEventsTask::RunTask ()
{
	TServerMessage		messageObj;
	TServerReply		  replyObj;
	
  // Create our thread environment
	CreateModEnviron(fParentEnvironPtr);

  if (DoPluginEventLoop()) {
		Main(messageObj);
		// Send it to the server
		SendToServer(messageObj,replyObj);
  }
}

//---------------------------------------------------------------------
// TGatherEventsTask::Main
//---------------------------------------------------------------------
void TGatherEventsTask::Main (TServerMessage& messageObj)
{
    TMessageNode  eventListNode(messageObj.Append("EVENT_LIST", "", ""));

    MYSQL       *conn;
    MYSQL_RES   *result;
    MYSQL_ROW   row;

    conn = mysql_init(NULL);

    if (conn == NULL) {
        WriteToErrorLog("MySQL init ERROR");
    }

    if (mysql_real_connect(conn, fserverName.c_str(), fuserName.c_str(), fpassword.c_str(), fdbName.c_str(), 0, NULL, 0) == NULL) {
        WriteToErrorLog("MySQL connect ERROR"); 
    }
    
    /* 
     * Make sure this query is good.  segfault otherwise.
     * TODO: Figure out the right way to handle bad queries (try/catch, etc.)
     *
     */
    std::string query =  "select inet_ntoa(iphdr.ip_src), inet_ntoa(iphdr.ip_dst), signature.sig_sid, signature.sig_name, count(*) "; 
                query += "as sum from event, signature, iphdr where event.timestamp >= \"";
                query += fstartTime.c_str();
                query += "\" and event.timestamp < \"";
                query += fendTime.c_str();
                query += "\" and iphdr.cid = event.cid and signature.sig_id = event.signature group by ip_src, ip_dst, sig_name order by count(*) desc";

    mysql_query(conn, query.c_str());

    result = mysql_store_result(conn);

    while ((row = mysql_fetch_row(result))) {
        string ip_src(row[0]);
        string ip_dst(row[1]);
        string sig_sid(row[2]);
        string sig_name(row[3]);
        string sum(row[4]);
        
        TMessageNode eventNode(eventListNode.Append("EVENT","",""));
        
        eventNode.AddAttribute("src", ip_src);
        eventNode.AddAttribute("dst", ip_dst);
        
        eventNode.AddAttribute("sid", sig_sid);
        eventNode.AddAttribute("sig", sig_name);
        eventNode.AddAttribute("sum", sum);

    }

    mysql_free_result(result);
    mysql_close(conn);
}

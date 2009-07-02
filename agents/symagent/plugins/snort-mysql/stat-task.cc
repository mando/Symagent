/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Plugin agent to stat snort event info from MySQL
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
#include "stat-task.h"
#include <mysql/mysql.h>

//*********************************************************************
// Class TStatEventsTask
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TStatEventsTask::TStatEventsTask ()
	:	Inherited(PROJECT_SHORT_NAME,0,false),
		fParentEnvironPtr(GetModEnviron())
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TStatEventsTask::~TStatEventsTask ()
{
}

//---------------------------------------------------------------------
// TStatEventsTask::SetupTask
//---------------------------------------------------------------------
void TStatEventsTask::SetupTask (const string& db,
									const string& server,
									const string& user,
									const string& pass)
{

  WriteToMessagesLog("in Stat Setuptask");

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

}

//---------------------------------------------------------------------
// TStatEventsTask::RunTask
//---------------------------------------------------------------------
void TStatEventsTask::RunTask ()
{
	TServerMessage		messageObj;
	TServerReply		  replyObj;
	
  // Create our thread environment
	CreateModEnviron(fParentEnvironPtr);

  WriteToMessagesLog("in Stat RunTask");

	Main(messageObj);
	SendToServer(messageObj,replyObj);

  WriteToMessagesLog("done with Stat RunTask?!");
}

//---------------------------------------------------------------------
// TStatEventsTask::Main
//---------------------------------------------------------------------
void TStatEventsTask::Main (TServerMessage& messageObj)
{
    TMessageNode  eventListNode(messageObj.Append("EVENT_LIST", "", ""));

    MYSQL       *conn;
    MYSQL_RES   *result;
    MYSQL_ROW   row;

    // TODO: Maybe we should cache this connection
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
    
    /*std::string query =  "select inet_ntoa(iphdr.ip_src), inet_ntoa(iphdr.ip_dst), signature.sig_sid, signature.sig_name, count(*) "; 
                query += "as sum from event, signature, iphdr where event.timestamp >= \"";
                query += fstartTime.GetFormattedDateTime("%Y-%m-%d %H:%M:%S").c_str();
                query += "\" and event.timestamp < \"";
                query += fendTime.GetFormattedDateTime("%Y-%m-%d %H:%M:%S").c_str();
                query += "\" and iphdr.cid = event.cid and signature.sig_id = event.signature group by ip_src, ip_dst, sig_name order by count(*) desc";
                */

    std::string query = GetQuery();
    
    mysql_query(conn, query.c_str());
    WriteToMessagesLog("query:");
    WriteToMessagesLog(query);
   
    result = mysql_store_result(conn);
   
    //TODO: REALLY need to finish refactoring this
    
    row = mysql_fetch_row(result);

    string min(row[0]);
    string max(row[1]);
        
    TMessageNode eventNode(eventListNode.Append("STAT","",""));
    eventNode.AddAttribute("min", min);
    eventNode.AddAttribute("max", max);

    WriteToMessagesLog("After query: ");
    WriteToMessagesLog("max cid: " + max );
    WriteToMessagesLog("min cid: " + min );

    mysql_free_result(result);
    mysql_close(conn);
}

//---------------------------------------------------------------------
// TStatEventsTask::GetQuery
//---------------------------------------------------------------------
std::string TStatEventsTask::GetQuery ()
{
  std::string query = "select min(cid), max(cid) from event";
  return query;
}

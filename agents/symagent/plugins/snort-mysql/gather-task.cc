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
									const string& max_cid,
									const string& min_cid,
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
  
  if (!max_cid.empty())
    fmaxCid = max_cid;
  else
    throw TSymLibErrorObj(kErrorStartTimeNotSpecified,"Start Time not defined");
  
  if (!min_cid.empty()) 
    fminCid = min_cid;
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

    std::string query = "select event.cid, event.signature, event.timestamp, inet_ntoa(iphdr.ip_src), inet_ntoa(iphdr.ip_dst) from event, iphdr where iphdr.cid = event.cid";
    
    /*if (fmaxCid.compare("0") != 0) {
                query += " and event.cid < ";
                query += fmaxCid.c_str(); 
    }*/
    
    if (fmaxCid.compare("0") != 0) {
                query += " and event.cid > ";
                query += fmaxCid.c_str();
    }
                query += " order by event.cid desc limit 5000";

    mysql_query(conn, query.c_str());
    WriteToMessagesLog("query:");
    WriteToMessagesLog(query);
   
    result = mysql_store_result(conn);
    
    std::string min_cid;
    std::string max_cid;

    int counter = 0;

    while ((row = mysql_fetch_row(result))) {
        string cid(row[0]);
        string sig(row[1]);
        string timestamp(row[2]);
        string ip_src(row[3]);
        string ip_dst(row[4]);
        
        TMessageNode eventNode(eventListNode.Append("EVENT","",""));
        
        eventNode.AddAttribute("cid", cid);
        eventNode.AddAttribute("sig", sig);
        eventNode.AddAttribute("src", ip_src);
        eventNode.AddAttribute("dst", ip_dst);
        eventNode.AddAttribute("timestamp", timestamp);

        // TODO: Fix the handling of min and max cid
        if (counter == 0 ) {
          max_cid.assign(cid);
        }
      
        min_cid.assign(cid);
        counter++;
    }

    WriteToMessagesLog("After query: ");
    WriteToMessagesLog("max cid: " + max_cid );
    WriteToMessagesLog("min cid: " + min_cid );

    // If we got at least one result, let's use the cids as our new max and min.
    if (counter > 0) {
      fmaxCid.assign(max_cid);
      fminCid.assign(min_cid);
    }
    
    mysql_free_result(result);
    mysql_close(conn);
}

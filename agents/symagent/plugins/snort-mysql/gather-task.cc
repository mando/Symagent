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
#include "plugin-utils.h"

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

  WriteToMessagesLog("in Gather Setup Task");
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
 

  if (!max_cid.empty()) {
    fmaxCid = max_cid;
  } else {
    throw TSymLibErrorObj(kErrorStartTimeNotSpecified,"Start Time not defined");
  }

  if (!min_cid.empty()) {
    fminCid = min_cid;
  } else {
    throw TSymLibErrorObj(kErrorEndTimeNotSpecified,"End Time not defined");
  }
 
  if (scanInterval > 0)
	{
    WriteToMessagesLog("setting Gather rerun to true");
		SetExecutionInterval(10);
		SetRerun(true);
	}

  WriteToMessagesLog("leaving SetupTask");
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

  WriteToMessagesLog("in RunTask");
  
  if (DoPluginEventLoop()) {
		Main(messageObj);
		// Send it to the server
		SendToServer(messageObj,replyObj);
  }

  WriteToMessagesLog("done with RunTask");
}

//---------------------------------------------------------------------
// TGatherEventsTask::Main
//---------------------------------------------------------------------
void TGatherEventsTask::Main (TServerMessage& messageObj)
{
    WriteToMessagesLog("In GatherTasks Main");
    WriteToMessagesLog("fmaxCid: " + fmaxCid);
    WriteToMessagesLog("fminCid: " + fminCid);
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
   
    int min_cid = 0;
    int max_cid = 0;

    int counter = 0;

    while ((row = mysql_fetch_row(result))) {
        string cid(row[0]);
        string sig(row[1]);
        string timestamp(row[2]);
        string ip_src(row[3]);
        string ip_dst(row[4]);
        string class_id(row[5]);
        string priority(row[6]);
        
        TMessageNode eventNode(eventListNode.Append("EVENT","",""));
        
        eventNode.AddAttribute("cid", cid);
        eventNode.AddAttribute("sig", sig);
        eventNode.AddAttribute("src", ip_src);
        eventNode.AddAttribute("dst", ip_dst);
        eventNode.AddAttribute("timestamp", timestamp);
        eventNode.AddAttribute("class_id", class_id);
        eventNode.AddAttribute("priority", priority);


        int i_cid = static_cast<int>(StringToNum(cid));

        if (i_cid < min_cid) {
          min_cid = i_cid;
        }
     
        if (i_cid > max_cid) {
          max_cid = i_cid;
        }

        counter++;
    }

    WriteToMessagesLog("After query: ");
    WriteToMessagesLog("max cid: " + IntToString(max_cid));
    WriteToMessagesLog("min cid: " + IntToString(min_cid));

    // If we got at least one result, let's use the cids as our new max and min.
    if (counter > 0) {
      fmaxCid.assign(IntToString(max_cid));
      fminCid.assign(IntToString(min_cid));
    }
   
    WriteToMessagesLog("fmaxCid: " + fmaxCid);
    WriteToMessagesLog("fminCid: " + fminCid);

    mysql_free_result(result);
    mysql_close(conn);
    WriteToMessagesLog("Done with GatherTasks Main");
}

//---------------------------------------------------------------------
// TGatherEventsTask::GetQuery
//---------------------------------------------------------------------
std::string TGatherEventsTask::GetQuery ()
{
    std::string query;
    std::string direction = "asc";

    query = "select event.cid, signature.sig_name, event.timestamp, inet_ntoa(iphdr.ip_src), inet_ntoa(iphdr.ip_dst), signature.sig_class_id, signature.sig_priority from event, signature, iphdr where iphdr.cid = event.cid and event.signature = signature.sig_id";
    
    query += " and event.cid > ";
    query += fmaxCid.c_str();
    
    query += " order by event.cid ";
    query += direction;

    return query;
}

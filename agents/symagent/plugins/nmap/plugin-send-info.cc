/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Plugin to execute nmap and report the results
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					28 Jan 2004
#		Last Modified:				11 Feb 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-send-info.h"

#include "plugin-utils.h"

//---------------------------------------------------------------------
// Namespace stuff
//---------------------------------------------------------------------
using namespace std;

//---------------------------------------------------------------------
// Module Definitions
//---------------------------------------------------------------------

//*********************************************************************
// Class TSendInfoTask
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSendInfoTask::TSendInfoTask (const string& nmapData, const string& serverRef)
	:	Inherited(PROJECT_SHORT_NAME,0,false),
		fData(nmapData),
		fServerRef(serverRef)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSendInfoTask::~TSendInfoTask ()
{
}

//---------------------------------------------------------------------
// TSendInfoTask::RunTask
//---------------------------------------------------------------------
void TSendInfoTask::RunTask ()
{
	if (IsConnectedToServer())
	{
		TServerMessage		messageObj;
		TServerReply		replyObj;
		
		if ((GetDynamicDebuggingFlags() & kDynDebugLogServerCommunication) == kDynDebugLogServerCommunication)
			WriteToMessagesLog("Starting nmap data transmission task");
		
		// Create the outbound message
		_CreateMessage(messageObj);
		
		// Send it to the server
		SendToServer(messageObj,replyObj);
		
		if ((GetDynamicDebuggingFlags() & kDynDebugLogServerCommunication) == kDynDebugLogServerCommunication)
			WriteToMessagesLog("Ending nmap data transmission task");
	}
}

//---------------------------------------------------------------------
// TSendInfoTask::_CreateMessage (protected)
//---------------------------------------------------------------------
void TSendInfoTask::_CreateMessage (TServerMessage& parentMessage)
{
	TMessageNode		nmapNode;
	unsigned long		pos;
	
	// We need to fixup the data just a bit
	Trim(fData);
	
	if (fData.find("<?") == 0)
	{
		// We need to remove the first line of data, as it's the XML header
		pos = fData.find("\n");
		fData.erase(0,pos+1);
	}
	
	// Remove embedded linefeeds
	pos = fData.find('\n');
	while (pos != string::npos)
	{
		fData.erase(pos,1);
		pos = fData.find('\n');
	}
	
	// Now we can create the message
	nmapNode = parentMessage.Append("NMAP_OUTPUT","ref",fServerRef);
	nmapNode.SetData(fData);
}

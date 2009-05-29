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
#		Last Modified:				20 Apr 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "send-msg.h"

#include "plugin-utils.h"

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------

//*********************************************************************
// Class TSendMsg
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSendMsg::TSendMsg (const FoundTextList& foundTextList)
	:	Inherited(PROJECT_SHORT_NAME,0,false),
		fFoundTextList(foundTextList)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSendMsg::~TSendMsg ()
{
}

//---------------------------------------------------------------------
// TSendMsg::RunTask
//---------------------------------------------------------------------
void TSendMsg::RunTask ()
{
	if (IsConnectedToServer() && !fFoundTextList.empty())
	{
		TServerMessage		messageObj;
		TServerReply		replyObj;
		
		Main(messageObj);
		
		// Send it to the server
		SendToServer(messageObj,replyObj);
	}
}

//---------------------------------------------------------------------
// TSendMsg::Main
//---------------------------------------------------------------------
void TSendMsg::Main (TServerMessage& messageObj)
{
	StdStringList	entryList;
	TMessageNode	aNode;
	
	aNode = messageObj.Append(kMessageNodeLogAlert,kMessageAttributeLogEntryCount,NumToString(fFoundTextList.size()));
	
	for (FoundTextList_const_iter x = fFoundTextList.begin(); x != fFoundTextList.end(); x++)
	{
		TMessageNode	entryNode(aNode.Append(kMessageNodeLogEntry,"",""));
		
		entryNode.AddAttribute(kMessageAttributeServerRef,x->first);
		entryNode.AddAttribute(kMessageAttributeLogEntryText,x->second);
	}
}

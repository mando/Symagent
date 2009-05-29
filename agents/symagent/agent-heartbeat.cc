/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Symbiot Master Library
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					29 Dec 2003
#		Last Modified:				18 Mar 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "agent-heartbeat.h"

//---------------------------------------------------------------------
// Module Definitions
//---------------------------------------------------------------------
#define	kDefaultExecutionInterval								10
#define	kMessageTypeValueHeartbeat								"BEAT"

//*********************************************************************
// Class THeartbeat
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
THeartbeat::THeartbeat ()
	:	Inherited(kUberAgentName,kDefaultExecutionInterval,true)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
THeartbeat::THeartbeat (time_t intervalInSeconds)
	:	Inherited(kUberAgentName,intervalInSeconds,true)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
THeartbeat::~THeartbeat ()
{
}

//---------------------------------------------------------------------
// THeartbeat::RunTask
//---------------------------------------------------------------------
void THeartbeat::RunTask ()
{
	// std::string	 debugString;

	if (IsConnectedToServer())
	{
		TServerMessage	heartbeatMessage;
		TServerReply	reply;
		double			oneMin,fiveMin,fifteenMin;
		
		GetLoadInformation(oneMin,fiveMin,fifteenMin);
		
		heartbeatMessage.Append(kMessageTypeValueHeartbeat,kMessageTagLoad,NumberToString(oneMin));
		
		SendToServer(heartbeatMessage,reply,kCompressionModeNone);
		// debugString = "DEBUG: BEAT: true";
	}
	else
	{
		// Cancel our rerun flag
		SetRerun(false);
		// debugString = "DEBUG: BEAT: false";
	}
	// WriteToMessagesLog(debugString);
}

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
#		Created:					29 Dec 2003
#		Last Modified:				18 Mar 2004
#		
#######################################################################
*/

#if !defined(AGENT_HEARTBEAT)
#define AGENT_HEARTBEAT

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "agent-config.h"
#include "agent-defs.h"
#include "agent-utils.h"

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class THeartbeat;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Class THeartbeat
//---------------------------------------------------------------------
class THeartbeat : public TTaskBase
{
	private:
		
		typedef	TTaskBase						Inherited;
	
	public:
		
		THeartbeat ();
			// Constructor
		
		THeartbeat (time_t intervalInSeconds);
			// Constructor
	
	private:
		
		THeartbeat (const THeartbeat& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~THeartbeat ();
			// Destructor
		
		virtual void RunTask ();
			// Entry point for the task.
};

#endif // AGENT_HEARTBEAT

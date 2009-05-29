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
#		Last Modified:				28 Jan 2004
#		
#######################################################################
*/

#if !defined(SNIFF_TASK)
#define SNIFF_TASK

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"

//---------------------------------------------------------------------
// Import namespace symbols
//---------------------------------------------------------------------
using symbiot::TTaskBase;
using symbiot::TServerMessage;
using symbiot::TMessageNode;

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TSendInfoTask;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Class TSendInfoTask
//---------------------------------------------------------------------
class TSendInfoTask : public TTaskBase
{
	private:
		
		typedef	TTaskBase						Inherited;
	
	public:
		
		TSendInfoTask (const string& nmapData, const string& serverRef);
			// Constructor
	
	private:
		
		TSendInfoTask (const TSendInfoTask& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TSendInfoTask ();
			// Destructor
		
		virtual void RunTask ();
			// Thread entry point for the task.
	
	protected:
		
		virtual void _CreateMessage (TServerMessage& parentMessage);
			// Populates the argument with the nmap information.
	
	protected:
		
		string									fData;
		string									fServerRef;
};

#endif // SNIFF_TASK

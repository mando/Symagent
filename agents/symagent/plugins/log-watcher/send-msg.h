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

#if !defined(SEND_MSG)
#define SEND_MSG

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
class TSendMsg;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef	string								ServerRef;
typedef	string								LogText;
		
typedef	pair<ServerRef,LogText>				FoundText;

typedef	vector<FoundText>					FoundTextList;
typedef	FoundTextList::const_iterator		FoundTextList_const_iter;

//---------------------------------------------------------------------
// Class TSendMsg
//---------------------------------------------------------------------
class TSendMsg : public TTaskBase
{
	private:
		
		typedef	TTaskBase						Inherited;
	
	public:
		
		TSendMsg (const FoundTextList& foundTextList);
			// Constructor
	
	private:
		
		TSendMsg (const TSendMsg& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TSendMsg ();
			// Destructor
		
		virtual void RunTask ();
			// Thread entry point for the task.  Really just a wrapper for Main().
		
		virtual void Main (TServerMessage& messageObj);
			// Builds the server-bound message containing the information
			// found in the internal slots.
	
	protected:
		
		FoundTextList							fFoundTextList;
};

//---------------------------------------------------------------------
#endif // SEND_MSG

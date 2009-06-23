/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Plugin agent to lookup remote machines' MAC addresses
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					03 Feb 2004
#		Last Modified:				24 Mar 2004
#		
#######################################################################
*/

#if !defined(GATHER_TASK)
#define GATHER_TASK

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"
#include "plugin-utils.h"

#include <mysql/mysql.h>
//---------------------------------------------------------------------
// Import namespace symbols
//---------------------------------------------------------------------
using symbiot::TTaskBase;
using symbiot::TServerMessage;
using symbiot::TMessageNode;

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TGatherEventsTask;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define	  kDefaultExecutionInterval						60*2	// 5 minutes

#define		kErrorDBNameNotSpecified				    -24301
#define		kErrorDBServerNotSpecified				  -24302
#define		kErrorUserNameNotSpecified          -24303
#define		kErrorPasswordNotSpecified          -24304
#define		kErrorStartTimeNotSpecified         -24305
#define		kErrorEndTimeNotSpecified           -24306

//---------------------------------------------------------------------
// Class TGatherEventsTask
//---------------------------------------------------------------------
class TGatherEventsTask : public TTaskBase
{
	private:
		
		typedef	TTaskBase						Inherited;
	
	public:
		
		TGatherEventsTask ();
			// Constructor
	
	private:
		
		TGatherEventsTask (const TGatherEventsTask& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TGatherEventsTask ();
			// Destructor
		
		virtual void SetupTask (const string& db,
								const string& server,
								const string& user,
								const string& pass,
								const string& start_time,
								const string& end_time,
								time_t scanInterval = 60);
		
		virtual void RunTask ();
			// Thread entry point for the task.  Really just a wrapper for Main().
		
		virtual void Main (TServerMessage& messageObj);
			// ¥¥¥
	
	protected:
		
		string									  fdbName;
		string									  fserverName;
		string									  fuserName;
		string									  fpassword;
		string									  fstartTime;
		string									  fendTime;
	
    MYSQL                     fconn;
		ModEnviron*								fParentEnvironPtr;
			
};

//---------------------------------------------------------------------
#endif // GATHER_TASK

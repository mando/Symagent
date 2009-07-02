/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Plugin agent to catch up missing snort events
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Mando Escamilla
#		e-mail: mando@symbiot.com
#######################################################################
*/

#if !defined(CATCHUP_TASK)
#define CATCHUP_TASK

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
class TCatchUpTask;

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
// Class TCatchUpTask
//---------------------------------------------------------------------
class TCatchUpTask : public TTaskBase
{
	private:
		
		typedef	TTaskBase						Inherited;
	
	public:
		
		TCatchUpTask ();
			// Constructor
	
	private:
		
		TCatchUpTask (const TCatchUpTask& obj) {}
			// Copy constructor is illegal

	public:
		
		virtual ~TCatchUpTask ();
			// Destructor
		
		virtual void SetupTask (const string& db,
								const string& server,
								const string& user,
								const string& pass,
								const string& max_cid,
								const string& min_cid,
								time_t scanInterval = 10);
		
		virtual void RunTask ();
			// Thread entry point for the task.  Really just a wrapper for Main().
		
		virtual void Main (TServerMessage& messageObj);
			// ¥¥¥
		
    virtual std::string GetQuery ();

	protected:
		
		string									  fdbName;
		string									  fserverName;
		string									  fuserName;
		string									  fpassword;
    string                    fmaxCid;
    string                    fminCid;

    MYSQL                     fconn;
		ModEnviron*								fParentEnvironPtr;
			
};

//---------------------------------------------------------------------
#endif // GATHER_TASK

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
#		Created:					01 Nov 2003
#		Last Modified:				18 Feb 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_TASKS)
#define SYMLIB_TASKS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include <ctime>
#include <string>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TTaskBase;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Class TTaskBase
//
// Base class.  Tasks should derive from this class.  The
// entry point of the task is the RunTask() method.
//---------------------------------------------------------------------
class TTaskBase
{
	protected:
		
		TTaskBase ();
			// Constructor
		
		TTaskBase (const std::string& taskName,
				   time_t intervalInSeconds,
				   bool rerun);
			// Constructor
	
	private:
		
		TTaskBase (const TTaskBase& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TTaskBase ();
			// Destructor
		
		virtual void RunTask () = 0;
			// Entry point for the task.
		
		//---------------------------
		// Accessors
		//---------------------------
		
		inline std::string TaskName () const
			{ return fTaskName; }
		
		inline void SetTaskName (const std::string& taskName)
			{ fTaskName = taskName; }
		
		inline time_t ExecutionInterval () const
			{ return fExecInterval; }
		
		inline void SetExecutionInterval (time_t intervalInSeconds)
			{ fExecInterval = intervalInSeconds; }
		
		inline bool Rerun () const
			{ return fRerun; }
		
		inline void SetRerun (bool doRerun)
			{ fRerun = doRerun; }
		
		inline pthread_t ParentThreadID () const
			{ return fParentThread; }
	
	public:
		
		virtual void ThreadMain (void* argPtr = NULL);
			// Original entry point for pthread context classes.
			// Sets up some interesting stuff and then calls RunTask().
			// Subclasses should basically ignore this method.
	
	protected:
		
		std::string								fTaskName;
		time_t									fExecInterval;
		pthread_t								fParentThread;
		bool									fRerun;
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

#endif // SYMLIB_TASKS

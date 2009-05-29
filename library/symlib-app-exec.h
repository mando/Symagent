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
#		Created:					27 Jan 2004
#		Last Modified:				09 Feb 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_APP_EXEC)
#define SYMLIB_APP_EXEC

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-config.h"

#include "symlib-defs.h"
#include "symlib-file.h"
#include "symlib-tasks.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TAppExecTask;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Class TAppExecTask
//---------------------------------------------------------------------
class TAppExecTask : public TTaskBase
{
	private:
		
		typedef		TTaskBase							Inherited;
	
	protected:
		
		typedef	std::pair<AppExecCallback,void*>		CallbackArgs;
		
		typedef	std::vector<CallbackArgs>				CallbackList;
		typedef	CallbackList::iterator					CallbackList_iter;
		typedef	CallbackList::const_iterator			CallbackList_const_iter;
	
	public:
		
		TAppExecTask ();
			// Constructor
		
		TAppExecTask (time_t intervalInSeconds);
			// Constructor
	
	private:
		
		TAppExecTask (const TAppExecTask& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TAppExecTask ();
			// Destructor
		
		virtual void RunTask ();
			// Entry point for the task.
		
		virtual void SetupTask (const TFileObj& appObj,
								const std::string& appArgs = "",
								const std::string& appStdInData = "");
			// Sets up the task so it can execute in the background.
		
		virtual void SetupTask (const std::string& appPath,
								const std::string& appArgs = "",
								const std::string& appStdInData = "");
			// Sets up the task so it can execute in the background.
		
		virtual void AddCallback (AppExecCallback callbackFunction, void* userData = NULL);
	
	protected:
		
		TFileObj										fFileObj;
		std::string										fAppArgs;
		std::string										fAppStdInData;
		CallbackList									fCallbackList;
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

#endif // SYMLIB_APP_EXEC

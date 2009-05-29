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
#		Last Modified:				18 Aug 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-app-exec.h"

#include "symlib-time.h"
#include "symlib-utils.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Module Definitions
//---------------------------------------------------------------------
#define	kDefaultExecutionInterval								0

//*********************************************************************
// Class TAppExecTask
//*********************************************************************

//---------------------------------------------------------------------
// Constructor (protected)
//---------------------------------------------------------------------
TAppExecTask::TAppExecTask ()
	:	Inherited(gEnvironObjPtr->GetTaskName(),kDefaultExecutionInterval,true)
{
	SetRerun(false);
}

//---------------------------------------------------------------------
// Constructor (protected)
//---------------------------------------------------------------------
TAppExecTask::TAppExecTask (time_t intervalInSeconds)
	:	Inherited(gEnvironObjPtr->GetTaskName(),intervalInSeconds,true)
{
	SetRerun(intervalInSeconds > 0);
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TAppExecTask::~TAppExecTask ()
{
}

//---------------------------------------------------------------------
// TAppExecTask::RunTask
//---------------------------------------------------------------------
void TAppExecTask::RunTask ()
{
	if (fFileObj.Exists())
	{
		std::string		appAndArgs;
		std::string		returnedData;
		bool			exceptionThrown = false;
		
		#if HAVE_DECL_PTHREAD_CANCEL_DISABLE && HAVE_DECL_PTHREAD_CANCEL_ENABLE
			int			oldCancelState;
		#endif
		
		appAndArgs = fFileObj.Path();
		if (!fAppArgs.empty())
			appAndArgs += " " + fAppArgs;
		
		#if HAVE_DECL_PTHREAD_CANCEL_DISABLE && HAVE_DECL_PTHREAD_CANCEL_ENABLE
			// Make sure that if we're running in a thread we have the correct cancel states set
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&oldCancelState);
		#endif
		
		try
		{
			if (fAppStdInData.empty())
				returnedData = ExecWithIO(appAndArgs);
			else
				returnedData = ExecWithIO(appAndArgs,reinterpret_cast<const unsigned char*>(fAppStdInData.c_str()),fAppStdInData.length());
		}
		catch (...)
		{
			// Eat all errors
			exceptionThrown = true;
		}
		
		#if HAVE_DECL_PTHREAD_CANCEL_DISABLE && HAVE_DECL_PTHREAD_CANCEL_ENABLE
			// Restore the thread cancel state
			pthread_setcancelstate(oldCancelState,NULL);
		#endif
		
		if (!exceptionThrown)
		{
			// Call the callbacks with the gathered data
			for (CallbackList_const_iter x = fCallbackList.begin(); x != fCallbackList.end(); x++)
			{
				AppExecCallback			functionPtr = x->first;
				void*					userData = x->second;
				
				if ((*functionPtr)(returnedData,this,userData))
				{
					// User function returned true, indicating that processing should stop
					break;
				}
			}
		}
	}
}

//---------------------------------------------------------------------
// TAppExecTask::SetupTask
//---------------------------------------------------------------------
void TAppExecTask::SetupTask (const TFileObj& appObj,
							  const std::string& appArgs,
							  const std::string& appStdInData)
{
	// Initialize our internal slots
	fFileObj = appObj;
	fAppArgs = appArgs;
	fAppStdInData = appStdInData;
}

//---------------------------------------------------------------------
// TAppExecTask::SetupTask
//---------------------------------------------------------------------
void TAppExecTask::SetupTask (const std::string& appPath,
							  const std::string& appArgs,
							  const std::string& appStdInData)
{
	SetupTask(TFileObj(appPath),appArgs,appStdInData);
}

//---------------------------------------------------------------------
// TAppExecTask::AddCallback
//---------------------------------------------------------------------
void TAppExecTask::AddCallback (AppExecCallback callbackFunction, void* userData)
{
	fCallbackList.push_back(make_pair(callbackFunction,userData));
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

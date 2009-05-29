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
#		Last Modified:				15 Oct 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-tasks.h"

#include "symlib-config.h"
#include "symlib-utils.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TTaskBase
//*********************************************************************

//---------------------------------------------------------------------
// Constructor (protected)
//---------------------------------------------------------------------
TTaskBase::TTaskBase ()
	:	fExecInterval(0),
		fRerun(false)
{
}

//---------------------------------------------------------------------
// Constructor (protected)
//---------------------------------------------------------------------
TTaskBase::TTaskBase (const std::string& taskName,
					  time_t intervalInSeconds,
					  bool rerun)
	:	fTaskName(taskName),
		fExecInterval(intervalInSeconds),
		fParentThread(pthread_self()),
		fRerun(rerun)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TTaskBase::~TTaskBase ()
{
}

//---------------------------------------------------------------------
// TTaskBase::ThreadMain
//---------------------------------------------------------------------
void TTaskBase::ThreadMain (void* /* argPtr */)
{
	try
	{
		pthread_testcancel();
		gEnvironObjPtr->SetTaskName(fTaskName);
		RunTask();
		gEnvironObjPtr->RemoveTaskName();
	}
	catch (...)
	{
		gEnvironObjPtr->RemoveTaskName();
		throw;
	}
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

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
#		Adapted from a library authored by BTI and available
#		from http://www.bti.net
#		
#		Created:					20 Nov 2003
#		Last Modified:				03 Feb 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-mutex.h"

#include "symlib-exception.h"

#include <cerrno>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Module Definitions
//---------------------------------------------------------------------

//*********************************************************************
// Class TPthreadMutexObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPthreadMutexObj::TPthreadMutexObj ()
	:	fIsLocked(false)
{
	// Round-about way of initializing the mutex in order to workaround
	// multi-platform oddities
	
	pthread_mutex_t		temp = PTHREAD_MUTEX_INITIALIZER;
	
	fMutex = temp;
	pthread_mutex_init(&fMutex,NULL);
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPthreadMutexObj::TPthreadMutexObj (const pthread_mutexattr_t& attributes)
	:	fIsLocked(false)
{
	// Round-about way of initializing the mutex in order to workaround
	// multi-platform oddities
	
	pthread_mutex_t		temp = PTHREAD_MUTEX_INITIALIZER;
	
	fMutex = temp;
	pthread_mutex_init(&fMutex,&attributes);
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPthreadMutexObj::~TPthreadMutexObj ()
{
	pthread_mutex_unlock(&fMutex);
	fIsLocked = false;
	pthread_mutex_destroy(&fMutex);
}

//---------------------------------------------------------------------
// TPthreadMutexObj::Lock
//---------------------------------------------------------------------
void TPthreadMutexObj::Lock ()
{
	int			result = 0;
	
	result = pthread_mutex_lock(&fMutex);
	if (result != 0)
		throw TSymLibErrorObj(result,"While calling pthread_mutex_lock");
	
	fIsLocked = true;
}

//---------------------------------------------------------------------
// TPthreadMutexObj::TryLock
//---------------------------------------------------------------------
bool TPthreadMutexObj::TryLock ()
{
	bool		wasSeized = false;
	int			result = 0;
	
	result = pthread_mutex_trylock(&fMutex);
	
	if (result == 0)
	{
		wasSeized = true;
		fIsLocked = true;
	}
	else if (result == EBUSY)
		wasSeized = false;
	else
		throw TSymLibErrorObj(result,"While calling pthread_mutex_trylock");
	
	return wasSeized;
}

//---------------------------------------------------------------------
// TPthreadMutexObj::Unlock
//---------------------------------------------------------------------
void TPthreadMutexObj::Unlock ()
{
	int			result = 0;
	
	result = pthread_mutex_unlock(&fMutex);
	if (result != 0)
		throw TSymLibErrorObj(result,"While calling pthread_mutex_unlock");
	
	fIsLocked = false;
}

//*********************************************************************
// Class TLockedPthreadMutexTimeoutObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TLockedPthreadMutexTimeoutObj::TLockedPthreadMutexTimeoutObj (pthread_mutex_t& mutex, time_t seconds)
	:	fMutexPtr(&mutex),
		fIsLocked(false)
{
	time_t	expireTime;
	
	if (seconds < 0)
		seconds = 0;
	
	expireTime = time(NULL) + seconds;
	
	do
	{
		int lockResult = pthread_mutex_trylock(fMutexPtr);
		
		if (lockResult == 0)
			fIsLocked = true;
	} while (!fIsLocked && time(NULL) < expireTime);
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TLockedPthreadMutexTimeoutObj::TLockedPthreadMutexTimeoutObj (TPthreadMutexObj& mutexObj, time_t seconds)
	:	fMutexPtr(mutexObj.MutexPtr()),
		fIsLocked(false)
{
	time_t	expireTime;
	
	if (seconds < 0)
		seconds = 0;
	
	expireTime = time(NULL) + seconds;
	
	do
	{
		int lockResult = pthread_mutex_trylock(fMutexPtr);
		
		if (lockResult == 0)
			fIsLocked = true;
	} while (!fIsLocked && time(NULL) < expireTime);
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TLockedPthreadMutexTimeoutObj::~TLockedPthreadMutexTimeoutObj ()
{
	if (fIsLocked)
		pthread_mutex_unlock(fMutexPtr);
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

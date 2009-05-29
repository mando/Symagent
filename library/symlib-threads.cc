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
#		Created:					28 Oct 2003
#		Last Modified:				Sat Apr  8 15:06:40 CDT 2006
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-threads.h"

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
typedef		void*	(*ThreadEntryPoint)(void*);
typedef		void*	ThreadArgumentPtr;

typedef		std::vector<TPthreadObj*>			PthreadObjPtrList;
typedef		PthreadObjPtrList::iterator			PthreadObjPtrList_iter;
typedef		PthreadObjPtrList::const_iterator	PthreadObjPtrList_const_iter;

// -------------------------------------

class TPthreadTrackerObj
{
	public:
		
		TPthreadTrackerObj () {}
		~TPthreadTrackerObj () {}
		
		PthreadObjPtrList				fTrackedThreads;
};

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
static		TPthreadTrackerObj*					gPthreadTrackObjPtr = NULL;
static		TPthreadMutexObj					gTrackedThreadsMutex;
static		TPthreadMutexObj					gPthreadTrackCreateMutex;

//---------------------------------------------------------------------
// Singleton Accessors
//---------------------------------------------------------------------

TPthreadTrackerObj* PthreadTrackObjPtr ();
TPthreadTrackerObj* PthreadTrackObjPtr ()
{
	if (!gPthreadTrackObjPtr)
	{
		TLockedPthreadMutexObj		lock(gPthreadTrackCreateMutex);
		
		if (!gPthreadTrackObjPtr)
			gPthreadTrackObjPtr = new TPthreadTrackerObj;
	}
	
	return gPthreadTrackObjPtr;
}

//*********************************************************************
// Class TPthreadObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPthreadObj::TPthreadObj (bool makeDetached)
	:	fID(0),
		fCancelState(0),
		fCancelType(0),
		fRunning(kThreadObjStateNotStarted),
		fFunctionPtr(NULL),
		fFunctionArgPtr(NULL),
		fCleanupFunctionPtr(NULL),
		fSignalSetPtr(NULL),
		fDeleteWhenComplete(false),
		fExceptionWasThrown(false)
{
	// Initialize some internal stuff
	Reset();
	memset(&fSignalSet,0,sizeof(fSignalSet));
	pthread_attr_init(&fAttributes);

	// Set stack space to 64k
	pthread_attr_setstacksize(&fAttributes,(8192*8));
	
	#if HAVE_DECL_PTHREAD_CANCEL_DISABLE && HAVE_DECL_PTHREAD_CANCEL_ENABLE
		fCancelState = PTHREAD_CANCEL_ENABLE;
	#endif
	
	#if HAVE_DECL_PTHREAD_CANCEL_DEFERRED && HAVE_DECL_PTHREAD_CANCEL_ASYNCHRONOUS
		fCancelType = PTHREAD_CANCEL_DEFERRED;
	#endif
	
	// Mark our thread as detached if necessary
	if (makeDetached)
		MakeDetached();
	
	// Track ourself
	BeginTracking();
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPthreadObj::TPthreadObj (ThreadEntryPoint functionPtr, bool makeDetached)
	:	fID(0),
		fCancelState(0),
		fCancelType(0),
		fRunning(kThreadObjStateNotStarted),
		fFunctionPtr(functionPtr),
		fFunctionArgPtr(NULL),
		fCleanupFunctionPtr(NULL),
		fSignalSetPtr(NULL),
		fDeleteWhenComplete(false),
		fExceptionWasThrown(false)
{
	// Initialize some internal stuff
	Reset();
	memset(&fSignalSet,0,sizeof(fSignalSet));
	pthread_attr_init(&fAttributes);
	
	// Set stack space to 64k
	pthread_attr_setstacksize(&fAttributes,(8192*8));
	
	#if HAVE_DECL_PTHREAD_CANCEL_DISABLE && HAVE_DECL_PTHREAD_CANCEL_ENABLE
		fCancelState = PTHREAD_CANCEL_ENABLE;
	#endif
	
	#if HAVE_DECL_PTHREAD_CANCEL_DEFERRED && HAVE_DECL_PTHREAD_CANCEL_ASYNCHRONOUS
		fCancelType = PTHREAD_CANCEL_DEFERRED;
	#endif
	
	// Mark our thread as detached if necessary
	if (makeDetached)
		MakeDetached();
	
	// Track ourself
	BeginTracking();
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPthreadObj::~TPthreadObj ()
{
	// Make sure we're joined if necessary
	try
	{
		Join();
	}
	catch (...)
	{
		// Ignore all errors
	}
	
	EndTracking();
	
	// Destroy our attributes
	pthread_attr_destroy(&fAttributes);
	
	// Reset some of our internal slots to NULL to prevent even
	// accidental access, post-delete
	fFunctionPtr = NULL;
	fFunctionArgPtr = NULL;
	fCleanupFunctionPtr = NULL;
	fRunning = kThreadObjStateCompleted;
	fDeleteWhenComplete = false;
}

//---------------------------------------------------------------------
// TPthreadObj::SetThreadFunction
//---------------------------------------------------------------------
void TPthreadObj::SetThreadFunction (ThreadEntryPoint functionPtr)
{
	if (IsRunning())
		throw TSymLibErrorObj(EPERM,"Cannot set a thread function while the thread is running");
	
	fFunctionPtr = functionPtr;
}

//---------------------------------------------------------------------
// TPthreadObj::SetThreadCleanupFunction
//---------------------------------------------------------------------
void TPthreadObj::SetThreadCleanupFunction (ThreadEntryPoint cleanupFunctionPtr)
{
	fCleanupFunctionPtr = cleanupFunctionPtr;
}

//---------------------------------------------------------------------
// TPthreadObj::SetDeleteWhenComplete
//---------------------------------------------------------------------
void TPthreadObj::SetDeleteWhenComplete (bool deleteWhenComplete)
{
	fDeleteWhenComplete = deleteWhenComplete;
}

//---------------------------------------------------------------------
// TPthreadObj::SetCancelState
//---------------------------------------------------------------------
int TPthreadObj::SetCancelState (int newState)
{
	int		oldState = fCancelState;
	
	#if HAVE_DECL_PTHREAD_CANCEL_DISABLE && HAVE_DECL_PTHREAD_CANCEL_ENABLE
		if (newState == PTHREAD_CANCEL_ENABLE || newState == PTHREAD_CANCEL_DISABLE)
			fCancelState = newState;
	#endif
	
	return oldState;
}

//---------------------------------------------------------------------
// TPthreadObj::SetCancelType
//---------------------------------------------------------------------
int TPthreadObj::SetCancelType (int newType)
{
	int		oldType = fCancelType;
	
	#if HAVE_DECL_PTHREAD_CANCEL_DEFERRED && HAVE_DECL_PTHREAD_CANCEL_ASYNCHRONOUS
		if (newType == PTHREAD_CANCEL_ASYNCHRONOUS || newType == PTHREAD_CANCEL_DEFERRED)
			fCancelType = newType;
	#endif
	
	return oldType;
}

//---------------------------------------------------------------------
// TPthreadObj::Run
//---------------------------------------------------------------------
void TPthreadObj::Run (ThreadArgumentPtr argPtr)
{
	TLockedPthreadTrackerObj		trackerLock;
	int								createResult = 0;
	
	if (!fFunctionPtr)
		throw TSymLibErrorObj(ESRCH,"No thread function defined");
	
	fFunctionArgPtr = argPtr;
	MarkAsRunning();

	createResult = pthread_create(&fThread,&fAttributes,_ThreadRunner,this);
	
	if (createResult != 0) {
		throw TSymLibErrorObj(createResult,"While calling pthread_create");
		MarkAsStopped();
	}
}

//---------------------------------------------------------------------
// TPthreadObj::Join
//---------------------------------------------------------------------
void TPthreadObj::Join (void** returnValueHandle)
{
	if (DetachState() != PTHREAD_CREATE_DETACHED)
	{
		if (pthread_join(fThread,returnValueHandle) != 0)
			throw TSymLibErrorObj(errno,"While calling pthread_join");
		
		MarkAsStopped();
	}
}

//---------------------------------------------------------------------
// TPthreadObj::WaitForStop
//---------------------------------------------------------------------
void TPthreadObj::WaitForStop (unsigned int microsecondInterval) const
{
	while (IsRunning())
		usleep(microsecondInterval);
}

//---------------------------------------------------------------------
// TPthreadObj::Cancel
//---------------------------------------------------------------------
void TPthreadObj::Cancel ()
{
	if (IsRunning())
	{
		if (pthread_cancel(fThread) != 0)
			throw TSymLibErrorObj(errno,"While calling pthread_cancel");
	}
}

//---------------------------------------------------------------------
// TPthreadObj::Kill
//---------------------------------------------------------------------
void TPthreadObj::Kill (int signal)
{
	#if !defined(HAVE_PTHREAD_KILL) || !HAVE_PTHREAD_KILL
		Cancel();
	#else
		if (IsRunning())
		{
			if (pthread_kill(fThread,signal) != 0)
				throw TSymLibErrorObj(errno,"While calling pthread_kill");
		}
	#endif
}

//---------------------------------------------------------------------
// TPthreadObj::MarkAsRunning
//---------------------------------------------------------------------
void TPthreadObj::MarkAsRunning ()
{
	fRunning = kThreadObjStateRunning;
}

//---------------------------------------------------------------------
// TPthreadObj::MarkAsStopped
//---------------------------------------------------------------------
void TPthreadObj::MarkAsStopped ()
{
	fRunning = kThreadObjStateCompleted;
}

//---------------------------------------------------------------------
// TPthreadObj::DetachState
//---------------------------------------------------------------------
int TPthreadObj::DetachState () const
{
	int		state;
	
	if (pthread_attr_getdetachstate(&fAttributes,&state) != 0)
		throw TSymLibErrorObj(errno,"While calling pthread_attr_getdetachstate");
	
	return state;
}

//---------------------------------------------------------------------
// TPthreadObj::MakeJoinable
//---------------------------------------------------------------------
void TPthreadObj::MakeJoinable ()
{
	if (pthread_attr_setdetachstate(&fAttributes,PTHREAD_CREATE_JOINABLE) != 0)
		throw TSymLibErrorObj(errno,"While calling pthread_attr_setdetachstate to make thread joinable");
}

//---------------------------------------------------------------------
// TPthreadObj::MakeDetached
//---------------------------------------------------------------------
void TPthreadObj::MakeDetached ()
{
	if (IsRunning())
	{
		int		result = pthread_detach(fThread);
		
		if (result != 0)
			throw TSymLibErrorObj(result,"While calling pthread_detach to make thread detached");
	}
	else
	{
		if (pthread_attr_setdetachstate(&fAttributes,PTHREAD_CREATE_DETACHED) != 0)
			throw TSymLibErrorObj(errno,"While calling pthread_attr_setdetachstate to make thread detached");
	}
}

//---------------------------------------------------------------------
// TPthreadObj::Scheduling
//---------------------------------------------------------------------
int TPthreadObj::Scheduling () const
{
	int		policy;
	
	if (pthread_attr_getschedpolicy(&fAttributes,&policy) != 0)
		throw TSymLibErrorObj(errno,"While calling pthread_attr_getschedpolicy");
	
	return policy;
}

//---------------------------------------------------------------------
// TPthreadObj::SetScheduling
//---------------------------------------------------------------------
void TPthreadObj::SetScheduling (int newPolicy)
{
	if (pthread_attr_setschedpolicy(&fAttributes,newPolicy) != 0)
		throw TSymLibErrorObj(errno,"While calling While calling pthread_attr_setschedpolicy");
}

//---------------------------------------------------------------------
// TPthreadObj::Parameters
//---------------------------------------------------------------------
struct sched_param TPthreadObj::Parameters ()
{
	struct sched_param		parameters;
	
	if (pthread_attr_getschedparam(&fAttributes,&parameters) != 0)
		throw TSymLibErrorObj(errno,"While calling pthread_attr_getschedparam");
	
	return parameters;
}

//---------------------------------------------------------------------
// TPthreadObj::SetParameters
//---------------------------------------------------------------------
void TPthreadObj::SetParameters (const struct sched_param& newParameters)
{
	if (pthread_attr_setschedparam(&fAttributes,&newParameters) != 0)
		throw TSymLibErrorObj(errno,"While calling pthread_attr_setschedparam");
}

//---------------------------------------------------------------------
// TPthreadObj::Scope
//---------------------------------------------------------------------
int TPthreadObj::Scope ()
{
	int		scope;
	
	if (pthread_attr_getscope(&fAttributes,&scope) != 0)
		throw TSymLibErrorObj(errno,"While calling pthread_attr_getscope");
	
	return scope;
}

//---------------------------------------------------------------------
// TPthreadObj::SetScope
//---------------------------------------------------------------------
void TPthreadObj::SetScope (int newScope)
{
	if (pthread_attr_setscope(&fAttributes,newScope) != 0)
		throw TSymLibErrorObj(errno,"While calling pthread_attr_setscope");
}

//---------------------------------------------------------------------
// TPthreadObj::BeginTracking (protected)
//---------------------------------------------------------------------
void TPthreadObj::BeginTracking ()
{
	TLockedPthreadTrackerObj		trackerLock;
	
	fID = 0;
	
	// Determine a unique internal ID to return
	for (PthreadObjPtrList_const_iter x = PthreadTrackObjPtr()->fTrackedThreads.begin(); x != PthreadTrackObjPtr()->fTrackedThreads.end(); x++)
		fID = std::max(fID,(*x)->InternalID());
	++fID;
	
	// Push a pointer to the thread object onto our list
	PthreadTrackObjPtr()->fTrackedThreads.push_back(this);
}

//---------------------------------------------------------------------
// TPthreadObj::EndTracking (protected)
//---------------------------------------------------------------------
void TPthreadObj::EndTracking ()
{
	TLockedPthreadTrackerObj		trackerLock;
	
	// Delete the object based on its address
	for (PthreadObjPtrList_iter x = PthreadTrackObjPtr()->fTrackedThreads.begin(); x != PthreadTrackObjPtr()->fTrackedThreads.end(); x++)
	{
		if ((*x) == this)
		{
			PthreadTrackObjPtr()->fTrackedThreads.erase(x);
			break;
		}
	}
}

//*********************************************************************
// Class TLockedPthreadTrackerObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TLockedPthreadTrackerObj::TLockedPthreadTrackerObj ()
{
	gTrackedThreadsMutex.Lock();
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TLockedPthreadTrackerObj::~TLockedPthreadTrackerObj ()
{
	gTrackedThreadsMutex.Unlock();
}

//*********************************************************************
// Global Functions
//*********************************************************************

//---------------------------------------------------------------------
// PthreadCount
//---------------------------------------------------------------------
unsigned long PthreadCount (bool onlyRunning)
{
	unsigned long		threadCount = 0;
	
	if (!onlyRunning)
		threadCount = PthreadTrackObjPtr()->fTrackedThreads.size();
	else
	{
		TLockedPthreadTrackerObj		trackerLock;
		
		for (PthreadObjPtrList_const_iter x = PthreadTrackObjPtr()->fTrackedThreads.begin(); x != PthreadTrackObjPtr()->fTrackedThreads.end(); x++)
		{
			if ((*x)->IsRunning())
				++threadCount;
		}
	}
	
	return threadCount;
}

//---------------------------------------------------------------------
// MyThreadObjPtr
//---------------------------------------------------------------------
TPthreadObj* MyThreadObjPtr ()
{
	TPthreadObj*		threadObjPtr = NULL;
	
	if (PthreadCount() > 0)
	{
		TLockedPthreadTrackerObj	trackerLock;
		threadObjPtr = FindThreadObjPtrByThreadID(pthread_self());
	}
	
	return threadObjPtr;
}

//---------------------------------------------------------------------
// GetIndexedThreadObjPtr
//---------------------------------------------------------------------
TPthreadObj* GetIndexedThreadObjPtr (unsigned long n)
{
	TPthreadObj*			foundPtr = NULL;
	
	if (n < PthreadTrackObjPtr()->fTrackedThreads.size())
		foundPtr = PthreadTrackObjPtr()->fTrackedThreads[n];
	
	return foundPtr;
}

//---------------------------------------------------------------------
// FindThreadObjPtrByThreadID
//---------------------------------------------------------------------
TPthreadObj* FindThreadObjPtrByThreadID (pthread_t threadID)
{
	TPthreadObj*			foundPtr = NULL;
	
	for (PthreadObjPtrList_iter x = PthreadTrackObjPtr()->fTrackedThreads.begin(); x != PthreadTrackObjPtr()->fTrackedThreads.end(); x++)
	{
		if ((*x)->ThreadID() == threadID)
		{
			foundPtr = (*x);
			break;
		}
	}
	
	return foundPtr;
}

//---------------------------------------------------------------------
// FindThreadObjPtrByInternalID
//---------------------------------------------------------------------
TPthreadObj* FindThreadObjPtrByInternalID (unsigned long internalID)
{
	TPthreadObj*			foundPtr = NULL;
	
	for (PthreadObjPtrList_iter x = PthreadTrackObjPtr()->fTrackedThreads.begin(); x != PthreadTrackObjPtr()->fTrackedThreads.end(); x++)
	{
		if ((*x)->InternalID() == internalID)
		{
			foundPtr = (*x);
			break;
		}
	}
	
	return foundPtr;
}

//---------------------------------------------------------------------
// CancelAllPthreads
//---------------------------------------------------------------------
void CancelAllPthreads ()
{
	TLockedPthreadTrackerObj		trackerLock;
	
	for (PthreadObjPtrList_iter x = PthreadTrackObjPtr()->fTrackedThreads.begin(); x != PthreadTrackObjPtr()->fTrackedThreads.end(); x++)
		(*x)->Cancel();
}

//---------------------------------------------------------------------
// JoinAllPthreads
//---------------------------------------------------------------------
void JoinAllPthreads ()
{
	TLockedPthreadTrackerObj		trackerLock;
	
	for (PthreadObjPtrList_iter x = PthreadTrackObjPtr()->fTrackedThreads.begin(); x != PthreadTrackObjPtr()->fTrackedThreads.end(); x++)
		(*x)->Join();
}

//---------------------------------------------------------------------
// WaitForAllPthreadsToQuit
//---------------------------------------------------------------------
void WaitForAllPthreadsToQuit (unsigned int microsecondInterval)
{
	while (PthreadCount(true) > 0)
		usleep(microsecondInterval);
}

//---------------------------------------------------------------------
// DetachAndCancelPthread
//---------------------------------------------------------------------
void DetachAndCancelPthread (const TPthreadObj& pthreadObj)
{
	pthread_t	threadID = pthreadObj.ThreadID();
	int			result;
	
	result = pthread_detach(threadID);
	
	if (result != 0 && result != ESRCH && result != EINVAL)
		throw TSymLibErrorObj(errno,"While calling pthread_detach during DetachAndCancel");
	
	result = pthread_cancel(threadID);
	
	if (result != 0 && result != ESRCH)
		throw TSymLibErrorObj(errno,"While calling pthread_cancel during DetachAndCancel");
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

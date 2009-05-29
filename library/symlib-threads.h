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

#if !defined(SYMLIB_THREADS)
#define SYMLIB_THREADS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-config.h"

#include "symlib-mutex.h"

#include <pthread.h>
#include <signal.h>

#if HAVE_THREAD_H
	#include <thread.h>
#endif

#include <vector>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {


//---------------------------------------------------
// Thread Object State Values
//---------------------------------------------------
typedef		enum
				{
					kThreadObjStateNotStarted,
					kThreadObjStateRunning,
					kThreadObjStateCompleted,
				}	ThreadObjState;

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TPthreadObj;
class TLockedPthreadTrackerObj;

// Also see:
//		Template Class: TContextPthreadObj
//		Template Functions: Spawn
//		Template Class: TPthreadPool
//		Template Class: TContextPthreadPool

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef		void*	(*ThreadEntryPoint)(void*);
typedef		void*	ThreadArgumentPtr;

//---------------------------------------------------------------------
// Class TPthreadObj
//
// Simple class that exports most of pthread management to object-oriented
// methods.  Meant mainly to retrofit existing pthread code, as the
// management of the thread function is basically passed through to
// pthread_create without alteration.  Note that the TPthreadObj instance
// must remain in scope for the duration of the thread.
//
// By default, a joinable thread is created.
//
// A simple example assuming a thread function name myFunction():
//
//		TPthreadObj			noArgThreadObj(myFunction);
//		TPthreadObj			argThreadObj(myFunction);
//
//		noArgThreadObj.Run();
//		argThreadObj.Run(myDataPtr);
//
// All thread functions are executed within a try...catch block, and all
// thrown exceptions are ignored.
//
// All TPthreadObj objects (and subclasses) are tracked by this module.
// This means that you can easily determine which threads are still
// active (and thereby avoid application crashes resulting from
// terminating while there are active threads) by using the PthreadCount()
// and WaitForAllPthreadsToQuit() global functions.
//
// Also note that this object provides a casting overload to supply
// pthread_t and pthread_t* values, so you can use an instance as a
// direct replacement to function calls requiring pthread_t arguments.
//---------------------------------------------------------------------
class TPthreadObj
{
	private:
		
		static void* _ThreadRunner (void* argPtr)
			{
				TPthreadObj* threadObjPtr = static_cast<TPthreadObj*>(argPtr);
				
				if (threadObjPtr && threadObjPtr->ThreadFunctionPtr())
				{
					// Set the exception variable
					threadObjPtr->ClearException();
					
					// Setup our cancel state if possible
					#if HAVE_DECL_PTHREAD_CANCEL_DISABLE && HAVE_DECL_PTHREAD_CANCEL_ENABLE
						pthread_setcancelstate(threadObjPtr->GetCancelState(),NULL);
					#endif
					
					#if HAVE_DECL_PTHREAD_CANCEL_DEFERRED && HAVE_DECL_PTHREAD_CANCEL_ASYNCHRONOUS
						pthread_setcanceltype(threadObjPtr->GetCancelType(),NULL);
					#endif
					
					// Set our signal mask if provided
					if (threadObjPtr->SignalSetPtr())
						pthread_sigmask(SIG_SETMASK,threadObjPtr->SignalSetPtr(),NULL);
					
					// Setup our cleanup handler
					pthread_cleanup_push(_ThreadRunnerCleanup,threadObjPtr);
					
					try
					{
						//! Handled by the ->Run() method in the TPthreadObj (prior to this)
						// Mark the thread as running
						// threadObjPtr->MarkAsRunning();
						
						// Call the thread's function with the current argument
						(*(threadObjPtr->ThreadFunctionPtr()))(threadObjPtr->ThreadFunctionArg());
					}
					catch (...)
					{
						threadObjPtr->MarkException();
					}
					
					// Execute and clear our cleanup handler
					pthread_cleanup_pop(1);
				}
				
				return NULL;
			}
		
		static void _ThreadRunnerCleanup (void* argPtr)
			{
				TPthreadObj* threadObjPtr = static_cast<TPthreadObj*>(argPtr);
				
				if (threadObjPtr)
				{
					// Mark the thread as stopped
					threadObjPtr->MarkAsStopped();

					// Call the cleanup function if provided
					if (threadObjPtr->ThreadCleanupFunctionPtr())
						(*(threadObjPtr->ThreadCleanupFunctionPtr()))(threadObjPtr);
					
					// Delete the thread if indicated
					if (threadObjPtr->DeleteWhenComplete())
						delete(threadObjPtr);
				}
			}
		
	public:
		
		TPthreadObj (bool makeDetached = false);
			// Constructor
		
		TPthreadObj (ThreadEntryPoint functionPtr, bool makeDetached = false);
			// Constructor
	
	private:
		
		TPthreadObj (const TPthreadObj& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TPthreadObj ();
			// Destructor
		
		virtual void SetThreadFunction (ThreadEntryPoint functionPtr);
			// Sets the function that will be executed in a new thread.

		virtual void SetThreadCleanupFunction (ThreadEntryPoint cleanupFunctionPtr);
			// Sets the cleanup function that will be executed after
			// the thread entry function terminates.  The cleanup function
			// will execute within the pthread!
		
		virtual void SetDeleteWhenComplete (bool deleteWhenComplete);
			// Sets the delete-when-complete flag.  If true, then this pthread
			// object will be deleted (as via a call to delete()) after the
			// thread function terminates.
		
		virtual int SetCancelState (int newState);
			// Sets the cancel state for the thread.  newState must be one of
			// PTHREAD_CANCEL_ENABLE or PTHREAD_CANCEL_DISABLE.  Returns the
			// old state code.  This method must be run before Run() is
			// executed for it to have any effect.
		
		virtual int SetCancelType (int newType);
			// Sets the cancel type for the thread.  newType must be one of
			// PTHREAD_CANCEL_ASYNCHRONOUS or PTHREAD_CANCEL_DEFERRED.  Returns
			// the old type code.  This method must be run before Run() is
			// executed for it to have any effect.
		
		virtual void Run (ThreadArgumentPtr argPtr = NULL);
			// Creates a new thread and executes the current function with
			// the given argument.
		
		virtual void WaitForStop (unsigned int microsecondInterval = 500) const;
			// Method waits for the current thread to terminate.  The argument
			// is used as an argument to usleep(), which is called between checks.
		
		virtual void Join (void** returnValueHandle = NULL);
			// Method waits until the current thread joins before
			// returning.  If returnValueHandle is not NULL then it will
			// contain the thread's result.  Note that this method does
			// nothing for detached threads.
		
		virtual void Cancel ();
			// Cancels the currently-executing thread.
		
		virtual void Kill (int signal);
			// Sends the signal the current thread.  If this library is compiled
			// on Darwin then this method just calls Cancel().
		
		virtual void MarkAsRunning ();
			// This method marks the current thread as running.  Automatically
			// called when the thread function begins.
		
		virtual void MarkAsStopped ();
			// This method marks the current thread as stopped.  Automatically
			// called when the thread function terminates.
		
		virtual int DetachState () const;
			// Returns a value indicating whether the current thread
			// is in detached state or not.  The two values returned
			// are PTHREAD_CREATE_DETACHED and PTHREAD_CREATE_JOINABLE.
		
		virtual void MakeJoinable ();
			// Makes the current thread joinable to the current process.
		
		virtual void MakeDetached ();
			// Makes the current thread detached from the current process.
		
		virtual int Scheduling () const;
			// Returns a value indicating the scheduling policy for
			// the current thread.  Returned values can be one of
			// SCHED_OTHER, SCHED_RR, or SCHED_FIFO.
		
		virtual void SetScheduling (int newPolicy);
			// Sets the scheduling policy for the current thread.
		
		virtual struct sched_param Parameters ();
			// Returns a struct containing the current thread's
			// parameters (essentially, priority info).
		
		virtual void SetParameters (const struct sched_param& newParameters);
			// Sets the scheduling parameters for the current thread.
		
		virtual int Scope ();
			// Returns a value indicating the contention scope for
			// the current thread.  Returned values can be one of
			// PTHREAD_SCOPE_SYSTEM or PTHREAD_SCOPE_PROCESS.
		
		virtual void SetScope (int newScope);
			// Sets the contention scope for the current thread.
	
	// Public accessors
	public:
		
		inline unsigned long InternalID () const
			{ return fID; }
		
		inline pthread_t ThreadID () const
			{ return fThread; }
		
		inline void Reset ()
			{
				memset(&fThread,0,sizeof(fThread));
			}
		
		inline bool IsRunning () const
			{ return (fRunning == kThreadObjStateRunning); }
			
		inline bool HasCompleted () const
			{ return (fRunning > kThreadObjStateRunning); }
		
		inline int GetCancelState () const
			{ return fCancelState; }
		
		inline int GetCancelType () const
			{ return fCancelType; }
		
		inline ThreadEntryPoint ThreadFunctionPtr () const
			{ return fFunctionPtr; }
		
		inline ThreadArgumentPtr ThreadFunctionArg () const
			{ return fFunctionArgPtr; }
		
		inline ThreadEntryPoint ThreadCleanupFunctionPtr () const
			{ return fCleanupFunctionPtr; }
		
		inline sigset_t* SignalSetPtr () const
			{ return fSignalSetPtr; }
		
		inline void SetSignalSetPtr (const sigset_t* signalSetPtr)
			{
				if (signalSetPtr)
				{
					fSignalSet = *signalSetPtr;
					fSignalSetPtr = &fSignalSet;
				}
				else
				{
					fSignalSetPtr = NULL;
				}
			}
		
		inline bool DeleteWhenComplete () const
			{ return fDeleteWhenComplete; }
		
		inline bool WasExceptionThrown () const
			{ return fExceptionWasThrown; }
		
		inline void MarkException ()
			{ fExceptionWasThrown = true; }
		
		inline void ClearException ()
			{ fExceptionWasThrown = false; }
	
	// Public operators
	public:
		
		inline operator pthread_t ()
			{ return fThread; }
		
		inline operator const pthread_t () const
			{ return fThread; }
		
		inline operator pthread_t* ()
			{ return &fThread; }
		
		inline operator const pthread_t* () const
			{ return &fThread; }
		
		inline bool operator== (const TPthreadObj& threadObj) const
			{ return (pthread_equal(fThread,threadObj.ThreadID()) != 0); }
		
		inline bool operator== (const pthread_t thread) const
			{ return (pthread_equal(fThread,thread) != 0); }
	
	protected:
		
		virtual void BeginTracking ();
			// Inserts our pointer into the module global that tracks
			// our objects.  Assigns a unique internal ID at the same time.
		
		virtual void EndTracking ();
			// Removes our pointer from the module global.
	
	protected:
		
		unsigned long								fID;
		pthread_t									fThread;
		pthread_attr_t								fAttributes;
		int											fCancelState;
		int											fCancelType;
		ThreadObjState								fRunning;
		ThreadEntryPoint							fFunctionPtr;
		ThreadArgumentPtr							fFunctionArgPtr;
		ThreadEntryPoint							fCleanupFunctionPtr;
		sigset_t									fSignalSet;
		sigset_t*									fSignalSetPtr;
		bool										fDeleteWhenComplete;
		bool										fExceptionWasThrown;
};

//---------------------------------------------------------------------
// Template Class: TContextPthreadObj
//
// This template class changes the execution of the thread function.
// Rather than running a C function (or a static method) you can
// execute a method named ThreadMain() in an arbitrary object, within a
// new thread.  The definition of Main() is:
//
// 		void MyObject::ThreadMain (void* argPtr = NULL);
//
// The template argument for this class should be the name of the class
// containing the ThreadMain() method -- MyObject in the above example.
// That class is referred to as the context here.
//
// This template class is a subclass of TPthreadObj, and it inherits
// all of the parent's functionality.
//
// The constructors will accept either a pointer or a reference to the
// context object instance.  In addition, two booleans are required:
// deleteThread, if true, indicates that the thread object -- that is,
// the instance of this template class -- should be deleted once the
// thread has completed.  deleteContext, if true, indicates that the
// context object should be deleted after the thread completes.  Both
// are deallocated via calls to delete().
//
// Assuming an appropriate class named MyContext:
//
//		typedef		TContextPthreadObj<MyContext>		ThreadedContext;
//
//		MyContext			contextObj;
//		ThreadedContext		threadObj(contextObj,false,false);
//		threadObj.Run();
//
//	Or, to create a completely self-contained thread:
//
//		MyContext*						contextObjPtr = new MyContext;
//		TContextPthreadObj<MyContext>*	threadObjPtr = new TContextPthreadObj<MyContext>(contextObjPtr,true,true);
//		threadObjPtr->Run();
//---------------------------------------------------------------------
template <class CONTEXT_CLASS>
class TContextPthreadObj : public TPthreadObj
{
	private:
		
		typedef		TPthreadObj			Inherited;
	
		static void* _Cleanup (void* argPtr)
			{
				TContextPthreadObj*		threadObjPtr = static_cast<TContextPthreadObj*>(argPtr);
				
				if (threadObjPtr && threadObjPtr->ContextPtr())
				{
					if (threadObjPtr->DeleteContextWhenFinished())
					{
						delete(threadObjPtr->ContextPtr());
						threadObjPtr->SetContextPtr(NULL);
					}
				}
				
				return NULL;
			}
	
		static void* _Run (void* argPtr)
			{
				TContextPthreadObj*		threadObjPtr = static_cast<TContextPthreadObj*>(argPtr);
				
				if (threadObjPtr && threadObjPtr->ContextPtr())
					threadObjPtr->ContextPtr()->ThreadMain(threadObjPtr->ContextArgPtr());
				
				return NULL;
			}
		
	public:
		
		TContextPthreadObj (CONTEXT_CLASS& contextObj,
							bool deleteThread,
							bool deleteContext,
							bool makeDetached = true)
			:	Inherited(_Run,makeDetached),
				fDeleteContext(deleteContext),
				fContextObjPtr(&contextObj),
				fContextThreadArgPtr(NULL)
			{
				fDeleteWhenComplete = deleteThread;
				fCleanupFunctionPtr = _Cleanup;
			}
		
		TContextPthreadObj (CONTEXT_CLASS* contextObjPtr,
							bool deleteThread,
							bool deleteContext,
							bool makeDetached = true)
			:	Inherited(_Run,makeDetached),
				fDeleteContext(deleteContext),
				fContextObjPtr(contextObjPtr),
				fContextThreadArgPtr(NULL)
			{
				fDeleteWhenComplete = deleteThread;
				fCleanupFunctionPtr = _Cleanup;
			}
		
		virtual ~TContextPthreadObj ()
			{
				fDeleteContext = false;
				fContextObjPtr = NULL;
				fContextThreadArgPtr = NULL;
			}
		
		virtual void Run (ThreadArgumentPtr argPtr = NULL)
			{
				fContextThreadArgPtr = argPtr;
				Inherited::Run(this);
			}
		
		inline bool DeleteContextWhenFinished () const
			{ return fDeleteContext; }
		
		inline void SetDeleteContextWhenFinished (bool deleteWhenFinished)
			{ fDeleteContext = deleteWhenFinished; }
		
		inline CONTEXT_CLASS* ContextPtr ()
			{ return fContextObjPtr; }
		
		inline void SetContextPtr (CONTEXT_CLASS* contextObjPtr)
			{ fContextObjPtr = contextObjPtr; }
		
		inline void SetContextPtr (CONTEXT_CLASS& contextObj)
			{ fContextObjPtr = &contextObj; }
		
		inline ThreadArgumentPtr ContextArgPtr ()
			{ return fContextThreadArgPtr; }
		
		inline void SetContextArgPtr (ThreadArgumentPtr argPtr)
			{ fContextThreadArgPtr = argPtr; }
	
	protected:
		
		bool										fDeleteContext;
		CONTEXT_CLASS*								fContextObjPtr;
		ThreadArgumentPtr							fContextThreadArgPtr;
};

//---------------------------------------------------------------------
// Template Functions: Spawn
//
// The following template functions are easy ways to create self-running
// and self-cleaning independent threads.  They always create and destroy
// a new thread object for the duration.  If a pointer to a context
// object is passed in then it will be assumed that the context object
// must be destroyed (via delete()) when the thread terminates.  If
// the context object is passed in by reference then it will not be
// destroyed.
//
// The examples from the TContextPthreadObj<> example could be rewritten as:
//
//		MyContext		contextObj;
//		Spawn<MyContext>(contextObj);
//
//		MyContext		contextObjPtr = new MyContext;
//		Spawn<MyContext>(contextObjPtr);
//---------------------------------------------------------------------
template <class CONTEXT_CLASS>
void Spawn (CONTEXT_CLASS& contextObj)
{
	TContextPthreadObj<CONTEXT_CLASS>*	threadObjPtr = new TContextPthreadObj<CONTEXT_CLASS>(contextObj,true,false,true);
	
	if (threadObjPtr)
		threadObjPtr->Run();
}

template <class CONTEXT_CLASS>
void Spawn (CONTEXT_CLASS* contextObjPtr)
{
	TContextPthreadObj<CONTEXT_CLASS>*	threadObjPtr = new TContextPthreadObj<CONTEXT_CLASS>(contextObjPtr,true,true,true);
	
	if (threadObjPtr)
		threadObjPtr->Run();
}

//---------------------------------------------------------------------
// Template Class: TPthreadPoolBase
//
// This class should not be directly instantiated; use a subclass instead.
// However, the public methods here will propogate downward and used by
// those subclasses.
//---------------------------------------------------------------------
template <class THREAD_CLASS>
class TPthreadPoolBase
{
	protected:
		
		typedef		std::vector<THREAD_CLASS*>					ThreadObjPtrList;
		typedef		typename ThreadObjPtrList::iterator			ThreadObjPtrList_iter;
		typedef		typename ThreadObjPtrList::const_iterator	ThreadObjPtrList_const_iter;
		
	protected:
		
		TPthreadPoolBase ()
			{
			}
		
		virtual ~TPthreadPoolBase ()
			{
				TLockedPthreadMutexObj		lock(fMutex);
				
				// Delete our thread object list
				while (!fThreadList.empty())
				{
					delete(fThreadList.back());
					fThreadList.pop_back();
				}
			}
		
		unsigned long ThreadCount (bool runState)
			{
				unsigned long				count = 0;
				TLockedPthreadMutexObj		lock(fMutex);
				
				// Count the number of thread objects whose state
				// matches the given boolean.  Return the number.
				for (ThreadObjPtrList_const_iter x = fThreadList.begin(); x != fThreadList.end(); x++)
				{
					if ((*x)->IsRunning() == runState)
						++count;
				}
				
				return count;
			}
	
	public:
		
		virtual void Lock ()
			{
				// Public access to the mutex surrounding our thread object list.
				// Useful for calling functions that require direct manipulation
				// of a thread object and need to stabilize the list.
				fMutex.Lock();
			}
		
		virtual void Unlock ()
			{
				// The complement of Lock(), of course.
				fMutex.Unlock();
			}
		
		virtual void AddThreads (unsigned long count) = 0;
			// Must be defined in subclasses.  This method will be called whenever
			// new thread objects must be added to the internal list.  Subclassed
			// because different thread objects may have different initialization
			// parameters.
		
		virtual THREAD_CLASS* AddOneThread () = 0;
			// Must be defined in subclasses.  This method will be called whenever
			// one new thread object must be added to the internal list.  Subclassed
			// because different thread objects may have different initialization
			// parameters.
		
		virtual THREAD_CLASS* GetFreeThread ()
			{
				THREAD_CLASS*	freeThreadPtr = NULL;
				
				// Find the first non-running thread object and return a pointer to it.
				for (ThreadObjPtrList_iter x = fThreadList.begin(); x != fThreadList.end(); x++)
				{
					if (!(*x)->IsRunning())
					{
						freeThreadPtr = *x;
						break;
					}
				}
				
				return freeThreadPtr;
			}
		
		virtual bool RunFreeThread (ThreadArgumentPtr argPtr = NULL)
			{
				bool						wasRun = false;
				THREAD_CLASS*				freeThread = NULL;
				TLockedPthreadMutexObj		lock(fMutex);
				
				// Find the first non-running thread in the list and execute it
				// with the given argument.
				freeThread = GetFreeThread();
				if (freeThread)
				{
					freeThread->Run(argPtr);
					wasRun = true;
				}
				
				return wasRun;
			}
		
		virtual bool RunNewThread (ThreadArgumentPtr argPtr = NULL)
			{
				bool						wasRun = false;
				THREAD_CLASS*				threadPtr = AddOneThread();
				
				// Create a new thread, add it to the list, then execute it
				// with the given argument.
				if (threadPtr)
				{
					threadPtr->Run(argPtr);
					wasRun = true;
				}
				
				return wasRun;
			}
		
		virtual void WaitForAllThreadsToQuit (unsigned int microsecondInterval = 500)
			{
				// Function returns only when all threads in the list are non-running.
				// The argument specifies the number of microseconds to sleep
				// between checks.
				while (RunningThreadCount() > 0)
					usleep(microsecondInterval);
			}
		
		virtual void KillAllThreads (int signal)
			{
				TLockedPthreadMutexObj		lock(fMutex);
				
				// Sends all running threads the given signal.
				for (ThreadObjPtrList_const_iter x = fThreadList.begin(); x != fThreadList.end(); x++)
					(*x)->Kill(signal);
			}
		
		virtual unsigned long ThreadCount ()
			{
				// Returns the total number of threads in the list, regardless of
				// their status.
				return fThreadList.size();
			}
		
		virtual unsigned long FreeThreadCount ()
			{
				// Returns the number of non-running threads in the list.
				return ThreadCount(false);
			}
		
		virtual unsigned long RunningThreadCount ()
			{
				// Returns the number of running threads in the list.
				return ThreadCount(true);
			}
	
	protected:
		
		ThreadObjPtrList								fThreadList;
		TPthreadMutexObj								fMutex;
};

//---------------------------------------------------------------------
// Template Class: TPthreadPool
//
// This class manages homogenous thread objects in a very simple manner.
// Basically, it's just a way of grouping thread objects, rather than
// a manager of a traditional thread pool (to whit, the class does not
// spawn and block actual threads, it just creates the thread objects
// that will manage the threads that will eventually be created).
//---------------------------------------------------------------------
template <class THREAD_CLASS = TPthreadObj>
class TPthreadPool : public TPthreadPoolBase<THREAD_CLASS>
{
	private:
		
		typedef		TPthreadPoolBase<THREAD_CLASS>			Inherited;
	
	public:
		
		TPthreadPool (unsigned long initialSize = 0)
			:	Inherited()
			{
				if (initialSize > 0)
					AddThreads(initialSize);
			}
		
		virtual ~TPthreadPool ()
			{
			}
		
		virtual void AddThreads (unsigned long count = 1)
			{
				TLockedPthreadMutexObj		lock(this->fMutex);
				
				for (unsigned long x = 0; x < count; x++)
					this->fThreadList.push_back(new THREAD_CLASS(true));
			}
		
		virtual THREAD_CLASS* AddOneThread ()
			{
				TLockedPthreadMutexObj		lock(this->fMutex);
				THREAD_CLASS*				newThreadPtr(new THREAD_CLASS(true));
				
				this->fThreadList.push_back(newThreadPtr);
				
				return newThreadPtr;
			}
};

//---------------------------------------------------------------------
// Template Class: TContextPthreadPool
//
// Like the TPthreadPool template class, this class provides a way
// to manage an homogenous group of context threads (threads that execute
// C++ methods rather than C functions or static methods).  Each thread
// in the collection uses the exact same context object.
//---------------------------------------------------------------------
template <class CONTEXT_CLASS>
class TContextPthreadPool : public TPthreadPoolBase<TContextPthreadObj<CONTEXT_CLASS> >
{
	private:
		
		typedef		TContextPthreadObj<CONTEXT_CLASS>		THREAD_CLASS;
		typedef		TPthreadPoolBase<THREAD_CLASS>			Inherited;
	
	public:
		
		TContextPthreadPool (CONTEXT_CLASS& contextObj, unsigned long initialSize = 0)
			:	Inherited(),
				fContextObjPtr(&contextObj)
			{
				if (initialSize > 0)
					AddThreads(initialSize);
			}
		
		virtual ~TContextPthreadPool ()
			{
			}
		
		virtual void AddThreads (unsigned long count = 1)
			{
				TLockedPthreadMutexObj		lock(this->fMutex);
				
				for (unsigned long x = 0; x < count; x++)
					this->fThreadList.push_back(new THREAD_CLASS(*fContextObjPtr,false,false));
			}
		
		virtual THREAD_CLASS* AddOneThread ()
			{
				TLockedPthreadMutexObj		lock(this->fMutex);
				THREAD_CLASS*				newThreadPtr(new THREAD_CLASS(*fContextObjPtr,false,false));
				
				this->fThreadList.push_back(newThreadPtr);
				
				return newThreadPtr;
			}
	
	protected:
		
		CONTEXT_CLASS*									fContextObjPtr;
};

//---------------------------------------------------------------------
// Class TLockedPthreadTrackerObj
//
// This module tracks instances of TPthreadObj (and subclasses) through
// an STL vector.  In a multithreaded application, care must be taken
// when inserting and deleting vector members to ensure that no other
// concurrent thread makes simultaneous changes.  This class seizes
// a mutex surrounding that vector, preventing other threads from
// making changes.
//
// You should also instantiate a TLockedPthreadTrackerObj whenever you
// retrieve a pointer to a TPthreadObj via a call to FindThreadObjPtrByThreadID(),
// FindThreadObjPtrByInternalID(), or GetIndexedThreadObjPtr().
//
// Be sure that you destruct instances of this object quickly, as
// it will prevent other threads from starting or stopping, as well
// as blocking on other tracker-related functions.
//---------------------------------------------------------------------
class TLockedPthreadTrackerObj
{
	public:
		
		TLockedPthreadTrackerObj ();
		
		~TLockedPthreadTrackerObj ();
};

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

unsigned long PthreadCount (bool onlyRunning = false);
	// Returns a count of tracked threads.  If onlyRunning is true then
	// only those threads that are currently running are counted.

TPthreadObj* MyThreadObjPtr ();
	// Returns a pointer to the thread object associated with the current
	// thread, or NULL if no such object was found.

TPthreadObj* GetIndexedThreadObjPtr (unsigned long n);
	// Returns a pointer to the thread object at the indicated position
	// (zero-based).  Be sure to instantiate a TLockedPthreadTrackerObj
	// object before calling this function to ensure that the returned
	// object pointer remains valid.

TPthreadObj* FindThreadObjPtrByThreadID (pthread_t threadID);
	// Function returns a pointer to the thread object matching the argument.
	// Most useful for a running thread function to locate the thread
	// object that launched it.  Be sure to instantiate a TLockedPthreadTrackerObj
	// object before calling this function to ensure that the returned
	// object pointer remains valid, unless you are calling this function
	// from within the thread you are finding.

TPthreadObj* FindThreadObjPtrByInternalID (unsigned long internalID);
	// Function returns a pointer to the thread object matching the argument.
	// Be sure to instantiate a TLockedPthreadTrackerObj object before calling this
	// function to ensure that the returned object pointer remains valid,
	// unless you are calling this function from within the thread you are finding.

void CancelAllPthreads ();
	// Issues a cancel call against all running, tracked threads.  Tracked
	// threads are locked during this call.

void JoinAllPthreads ();
	// Issues a join call against all running, joinable, tracked threads.
	// Tracked threads are locked during this call.

void WaitForAllPthreadsToQuit (unsigned int microsecondInterval = 500);
	// Function sleeps until all tracked threads have stopped running
	// or at least ceased to be tracked.  The argument defines the number
	// of microseconds between checks; the function uses it as
	// an argument to usleep().  Tracked threads are locked during this call.

void DetachAndCancelPthread (const TPthreadObj& pthreadObj);
	// Calls pthread_detach() and pthread_cancel() on the running thread.
	// Callers should not attempt to join with the thread afterwards.

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif // SYMLIB_THREADS

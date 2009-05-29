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
#		Last Modified:				23 Apr 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_MUTEX)
#define SYMLIB_MUTEX

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include <pthread.h>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TPthreadMutexObj;
class TLockedPthreadMutexObj;
class TLockedPthreadMutexTimeoutObj;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Class TPthreadMutexObj
//
// Simple wrapper class for pthread mutexes.  Note that casting
// operators are provided so instances of this class can be used as
// pthread_mutex_t and pthread_mutex_t* arguments.  This class is
// mainly used to define a mutex, rather than manage it (see TLockedPthreadMutexObj
// for easy management).
//---------------------------------------------------------------------
class TPthreadMutexObj
{
	public:
		
		TPthreadMutexObj ();
			// Constructor
		
		TPthreadMutexObj (const pthread_mutexattr_t& attributes);
			// Constructor
	
	private:
		
		TPthreadMutexObj (const TPthreadMutexObj& obj) {}
			// Copy constructor is illegal
	
	public:
		
		~TPthreadMutexObj ();
			// Destructor
		
		void Lock ();
			// Method seizes the lock on the current mutex, blocking
			// until the lock is actually seized.
		
		bool TryLock ();
			// Attempts to seize a lock like a call to Lock() but does
			// not block if unable to actually seize the lock.  Returns
			// a boolean indicating whether the seizure was successful.
		
		void Unlock ();
			// Method unlocks the previously-sized mutex, relinquishing
			// its hold.
		
		bool IsLocked () const
			{ return fIsLocked; }
		
		inline pthread_mutex_t* MutexPtr ()
			{ return &fMutex; }
		
		inline const pthread_mutex_t* MutexPtr () const
			{ return &fMutex; }
	
	// Public castings
	public:
		
		inline operator pthread_mutex_t ()
			{ return fMutex; }
		
		inline operator const pthread_mutex_t () const
			{ return fMutex; }
		
		inline operator pthread_mutex_t* ()
			{ return &fMutex; }
		
		inline operator const pthread_mutex_t* () const
			{ return &fMutex; }
	
	protected:
		
		pthread_mutex_t								fMutex;
		bool										fIsLocked;
};

//---------------------------------------------------------------------
// Class TLockedPthreadMutexObj
//
// Simple class that seizes a mutex lock during construction and
// releases it during destruction.  Will accept either pthread_mutex_t
// mutexes or TPthreadMutexObj instances.
//---------------------------------------------------------------------
class TLockedPthreadMutexObj
{
	public:
		
		TLockedPthreadMutexObj (pthread_mutex_t& mutex) : fMutexPtr(&mutex)
			{ pthread_mutex_lock(fMutexPtr); }
		
		TLockedPthreadMutexObj (TPthreadMutexObj& mutexObj) : fMutexPtr(mutexObj.MutexPtr())
			{ pthread_mutex_lock(fMutexPtr); }
		
		~TLockedPthreadMutexObj ()
			{ pthread_mutex_unlock(fMutexPtr); }
	
	private:
		
		pthread_mutex_t*							fMutexPtr;
};

//---------------------------------------------------------------------
// Class TLockedPthreadMutexTimeoutObj
//
// Simple class that seizes a mutex lock during construction and
// releases it during destruction.  Will accept either pthread_mutex_t
// mutexes or TPthreadMutexObj instances.  Second argument to
// indicates the number of seconds to wait before giving up.
//---------------------------------------------------------------------
class TLockedPthreadMutexTimeoutObj
{
	public:
		
		TLockedPthreadMutexTimeoutObj (pthread_mutex_t& mutex, time_t seconds);
		
		TLockedPthreadMutexTimeoutObj (TPthreadMutexObj& mutexObj, time_t seconds);
		
		~TLockedPthreadMutexTimeoutObj ();
		
		inline bool IsLocked () const
			{ return fIsLocked; }
	
	private:
		
		pthread_mutex_t*							fMutexPtr;
		bool										fIsLocked;
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif // SYMLIB_MUTEX

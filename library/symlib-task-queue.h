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
#		Last Modified:				16 Mar 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_TASK_QUEUE)
#define SYMLIB_TASK_QUEUE

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-config.h"

#include "symlib-tasks.h"
#include "symlib-threads.h"

#include <string>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TQueueRunner;
class TQueue;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Class TQueueRunner
//---------------------------------------------------------------------
class TQueueRunner
{
	public:
		
		TQueueRunner ();
			// Constructor
		
		virtual ~TQueueRunner ();
			// Destructor
		
		virtual void ThreadMain (void* argPtr = NULL);
			// Main loop.  Calls TQueue::ManageTasks() at a set interval.
};

//---------------------------------------------------------------------
// Class TQueue
//---------------------------------------------------------------------
class TQueue
{
	protected:
		
		struct WaitQueueEntry
			{
				TTaskBase*						taskObjPtr;
				time_t							nextExecTime;
				WaitQueueEntry() : taskObjPtr(NULL),nextExecTime(0) {}
			};
		
		typedef std::vector<WaitQueueEntry>		WaitQueue;
		typedef WaitQueue::iterator				WaitQueue_iter;
		typedef WaitQueue::const_iterator		WaitQueue_const_iter;
		
		typedef TContextPthreadObj<TTaskBase>	TaskContext;
		
		typedef std::vector<TaskContext*>		RunQueue;
		typedef RunQueue::iterator				RunQueue_iter;
		typedef RunQueue::const_iterator		RunQueue_const_iter;
		
		typedef std::vector<TTaskBase*>			TaskObjPtrList;
		typedef TaskObjPtrList::iterator		TaskObjPtrList_iter;
		typedef TaskObjPtrList::const_iterator	TaskObjPtrList_const_iter;
		
	public:
		
		TQueue ();
			// Constructor
		
		virtual ~TQueue ();
			// Destructor
		
		virtual void ClearQueues (bool gracefully = true, bool leaveActive = true);
			// Clears both waiting and running queues.  If the argument is true
			// the running tasks are allowed to quit gracefully; if the
			// argument is false then they are summarily terminated.
		
		virtual void InsertTask (TTaskBase* taskObjPtr);
			// Inserts the given task into the waiting queue without
			// running it first.  Note that taskObjPtr is now owned
			// by the queue and will be deleted by the queue when
			// appropriate.
		
		virtual void InsertTask (TTaskBase* taskObjPtr, time_t delayInSeconds);
			// Inserts the given task into the waiting queue without
			// running it first, set to execute in delayInSeconds seconds.
			// Note that taskObjPtr is now owned by the queue and will be
			// deleted by the queue when appropriate.
		
		virtual void RunTask (TTaskBase* taskObjPtr);
			// Inserts the given task as the first task in the waiting
			// queue, so it will run during the next execution round.
			// Note that taskObjPtr is now owned by the queue and will
			// be deleted by the queue when appropriate.
		
		virtual bool DeleteTask (const TTaskBase* taskObjPtr);
			// Deletes the given task, cancelling it if it is currently running.
			// Returns a boolean indicating whether the task was actually found
			// and deleted or not.
		
		virtual void ManageTasks ();
			// Executes waiting tasks that have execution time less than
			// or equal to the current time, checks for finished tasks
			// running tasks and either moves them back to the waiting
			// queue (if they reexecute) or deletes them (if not).
		
		virtual bool IsTaskInQueue (const TTaskBase* taskObjPtr);
			// Returns true if the given task object resides in either the run
			// or wait queue, false otherwise.
		
		//---------------------------
		// Accessors
		//---------------------------
		
		inline bool IsActive () const
			{ return fIsActive; }
		
		inline unsigned long WaitingTaskCount () const
			{ return fWaitQueue.size(); }
		
		inline unsigned long RunningTaskCount () const
			{ return fRunQueue.size(); }
		
		inline bool TaskRunnerAvailability () const
			{ return fTaskRunnerAvail; }
		
		inline void SetTaskRunnerAvailability (bool avail)
			{ fTaskRunnerAvail = avail; }
	
	protected:
		
		virtual void _InsertTask (TTaskBase* taskObjPtr, time_t delayInSeconds);
			// Inserts the given task into the waiting queue without
			// running it first.
		
		virtual bool _DeleteTask (const TTaskBase* taskObjPtr);
			// Deletes the given task, cancelling it if it is currently running.
			// Returns a boolean indicating whether the task was actually found
			// and deleted or not.
		
		virtual void _DeleteChildTasks (const TaskContext* contextObjPtr);
			// Recursively deletes child tasks of the parent argument.
		
		virtual void _ManageTasks ();
			// Executes waiting tasks that have execution time less than
			// or equal to the current time, checks for finished tasks
			// running tasks and either moves them back to the waiting
			// queue (if they reexecute) or deletes them (if not).
	
	protected:
		
		TPthreadMutexObj						fQueueMutex;
		WaitQueue								fWaitQueue;
		RunQueue								fRunQueue;
		bool									fIsActive;
		bool									fTaskRunnerAvail;
};

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------
void InitTaskQueue ();
	// Initializes the task queue.  Must be called before any other
	// task-oriented methods and functions.

void DeleteTaskQueue ();
	// Destroys the task queue and all entries, killing any currently-
	// running tasks in the process.

bool IsTaskQueueAccepting ();
	// Returns true if the task queue will accept new tasks, false otherwise.

bool IsTaskQueueExecuting ();
	// Returns true if the tasks queue is running, false otherwise.

void _AddTaskToQueue (TTaskBase* taskObjPtr, bool runFirst);
	// Adds the given task to the task queue.  If runFirst is true
	// then the task is executed at the next opportunity; otherwise,
	// its execution will be delayed by the tasks execution interval.
	// Note that the taskObjPtr is now owned by the queue -- callers
	// should not mess around with it (especially delete it).

void _AddDelayedTaskToQueue (TTaskBase* taskObjPtr, time_t delayInSeconds);
	// Like _AddTaskToQueue(), except that the task is never immediately
	// executed and it will be set to execute in delayInSeconds seconds.

bool _DeleteTaskFromQueue (TTaskBase* taskObjPtr);
	// Deletes the given task, cancelling it if it is currently running.
	// Returns a boolean indicating whether the task was actually found
	// and deleted or not.

void _ClearTaskQueues (bool gracefully = true, bool leaveActive = true);
	// Clears the task queue of all queued tasks, running or waiting.
	// If the argument is true then running tasks are allowed to
	// terminate normally; otherwise, they are terminated with extreme
	// prejudice.

bool _IsTaskInQueue (const TTaskBase* taskObjPtr);
	// Returns true if the given task object resides in either the run
	// or wait queue, false otherwise.

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

#endif // SYMLIB_TASK_QUEUE

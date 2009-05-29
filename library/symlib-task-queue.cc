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
#		Last Modified:				Sat Apr  8 15:06:40 CDT 2006
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-task-queue.h"

#include "symlib-utils.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Module Globals
//*********************************************************************
static TQueue*										gTaskQueuePtr = NULL;

//*********************************************************************
// Class TQueueRunner
//*********************************************************************

//---------------------------------------------------------------------
// Constructor (protected)
//---------------------------------------------------------------------
TQueueRunner::TQueueRunner ()
{
	if (gTaskQueuePtr)
		gTaskQueuePtr->SetTaskRunnerAvailability(true);
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TQueueRunner::~TQueueRunner ()
{
	if (gTaskQueuePtr)
		gTaskQueuePtr->SetTaskRunnerAvailability(false);
}

//---------------------------------------------------------------------
// TQueueRunner::ThreadMain
//---------------------------------------------------------------------
void TQueueRunner::ThreadMain (void* /* argPtr */)
{
	double		kRunInterval = 1;	// seconds
	
	while (gTaskQueuePtr && gTaskQueuePtr->IsActive())
	{
		gTaskQueuePtr->ManageTasks();
		Pause(kRunInterval);
	}
}

//*********************************************************************
// Class TQueue
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TQueue::TQueue ()
	:	fIsActive(true),
		fTaskRunnerAvail(false)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TQueue::~TQueue ()
{
	ClearQueues(false,false);
}

//---------------------------------------------------------------------
// TQueue::ClearQueues
//---------------------------------------------------------------------
void TQueue::ClearQueues (bool gracefully, bool leaveActive)
{
	TLockedPthreadMutexObj		lock(fQueueMutex);
	
	fIsActive = false;
	
	// Delete waiting tasks
	while (!fWaitQueue.empty())
	{
		delete(fWaitQueue.back().taskObjPtr);
		fWaitQueue.pop_back();
	}
	
	if (gracefully && !fRunQueue.empty())
	{
		time_t		kWaitTime = 5;
		time_t		expireTime = time(NULL) + kWaitTime;
		
		// Give the threads time to quit
		do
		{
			_ManageTasks();
			Pause(.2);
			
			if (time(NULL) >= expireTime)
				break;
		}
		while (!fRunQueue.empty());
	}
	
	// Kill running tasks
	while (!fRunQueue.empty())
		_DeleteTask(fRunQueue.back()->ContextPtr());
	
	if (leaveActive)
		fIsActive = true;
}

//---------------------------------------------------------------------
// TQueue::InsertTask
//---------------------------------------------------------------------
void TQueue::InsertTask (TTaskBase* taskObjPtr)
{
	if (taskObjPtr && fIsActive)
	{
		TLockedPthreadMutexObj		lock(fQueueMutex);
		
		_InsertTask(taskObjPtr,taskObjPtr->ExecutionInterval());
		
		if (!fTaskRunnerAvail)
			Spawn<TQueueRunner>(new TQueueRunner);
	}
}

//---------------------------------------------------------------------
// TQueue::InsertTask
//---------------------------------------------------------------------
void TQueue::InsertTask (TTaskBase* taskObjPtr, time_t delayInSeconds)
{
	if (taskObjPtr && fIsActive)
	{
		TLockedPthreadMutexObj		lock(fQueueMutex);
		
		_InsertTask(taskObjPtr,delayInSeconds);
		
		if (!fTaskRunnerAvail)
			Spawn<TQueueRunner>(new TQueueRunner);
	}
}

//---------------------------------------------------------------------
// TQueue::RunTask
//---------------------------------------------------------------------
void TQueue::RunTask (TTaskBase* taskObjPtr)
{
	if (taskObjPtr && fIsActive)
	{
		TLockedPthreadMutexObj		lock(fQueueMutex);
		WaitQueueEntry				newQueueEntry;
		
		newQueueEntry.taskObjPtr = taskObjPtr;
		newQueueEntry.nextExecTime = 0;
		
		fWaitQueue.insert(fWaitQueue.begin(),newQueueEntry);
		
		if (!fTaskRunnerAvail)
			Spawn<TQueueRunner>(new TQueueRunner);
	}
}

//---------------------------------------------------------------------
// TQueue::DeleteTask
//---------------------------------------------------------------------
bool TQueue::DeleteTask (const TTaskBase* taskObjPtr)
{
	bool	wasDeleted = false;
	
	if (taskObjPtr)
	{
		TLockedPthreadMutexObj		lock(fQueueMutex);
		
		wasDeleted = _DeleteTask(taskObjPtr);
	}
	
	return wasDeleted;
}

//---------------------------------------------------------------------
// TQueue::ManageTasks
//---------------------------------------------------------------------
void TQueue::ManageTasks ()
{
	if (!fWaitQueue.empty() || !fRunQueue.empty())
	{
		TLockedPthreadMutexObj		lock(fQueueMutex);
		
		_ManageTasks();
	}
}

//---------------------------------------------------------------------
// TQueue::IsTaskInQueue
//---------------------------------------------------------------------
bool TQueue::IsTaskInQueue (const TTaskBase* taskObjPtr)
{
	bool						inQueue = false;
	TLockedPthreadMutexObj		lock(fQueueMutex);
	
	if (!inQueue)
	{
		for (WaitQueue_iter x = fWaitQueue.begin(); x != fWaitQueue.end(); x++)
		{
			if (x->taskObjPtr == taskObjPtr)
			{
				inQueue = true;
				break;
			}
		}
	}
	
	if (!inQueue)
	{
		for (RunQueue_iter x = fRunQueue.begin(); x != fRunQueue.end(); x++)
		{
			if ((*x)->ContextPtr() == taskObjPtr)
			{
				inQueue = true;
				break;
			}
		}
	}
	
	return inQueue;
}

//---------------------------------------------------------------------
// TQueue::_InsertTask (protected)
//---------------------------------------------------------------------
void TQueue::_InsertTask (TTaskBase* taskObjPtr, time_t delayInSeconds)
{
	WaitQueueEntry				newQueueEntry;
	WaitQueue_iter				iter = fWaitQueue.begin();
	
	newQueueEntry.taskObjPtr = taskObjPtr;
	newQueueEntry.nextExecTime = time(NULL) + delayInSeconds;
	
	while (iter != fWaitQueue.end() && iter->nextExecTime < newQueueEntry.nextExecTime)
		iter++;
	
	fWaitQueue.insert(iter,newQueueEntry);
}

//---------------------------------------------------------------------
// TQueue::_DeleteTask (protected)
//---------------------------------------------------------------------
bool TQueue::_DeleteTask (const TTaskBase* taskObjPtr)
{
	bool	wasDeleted = false;
	
	if (taskObjPtr)
	{
		// Now see if we can find our original task on the waiting queue
		for (WaitQueue_iter x = fWaitQueue.begin(); x != fWaitQueue.end(); x++)
		{
			if (x->taskObjPtr == taskObjPtr)
			{
				delete(x->taskObjPtr);
				fWaitQueue.erase(x);
				wasDeleted = true;
				break;
			}
		}
		
		if (!wasDeleted)
		{
			TaskContext*	foundParentTask = NULL;
			
			// Didn't find it on the waiting queue, try the run queue
			for (RunQueue_iter x = fRunQueue.begin(); x != fRunQueue.end(); x++)
			{
				if ((*x)->ContextPtr() == taskObjPtr)
				{
					foundParentTask = *x;
					break;
				}
			}
			
			if (foundParentTask)
			{
				// Delete running child tasks, if any
				_DeleteChildTasks(foundParentTask);
				
				// Cancel the running thread
				try
				{
					if (foundParentTask->IsRunning())
					{
						// Tell the context to delete itself when finished
						foundParentTask->SetDeleteContextWhenFinished(true);
						// Tell the thread object to delete itself when finished
						foundParentTask->SetDeleteWhenComplete(true);
						// Detach and cancel
						DetachAndCancelPthread(*foundParentTask);
					}
					else
					{
						// It's not really running, so we have to manually delete everything
						foundParentTask->Join();
						delete(foundParentTask->ContextPtr());
						delete(foundParentTask);
					}
				}
				catch (...)
				{
					
				}
				
				// Cleanup
				for (RunQueue_iter x = fRunQueue.begin(); x != fRunQueue.end(); x++)
				{
					if (*x == foundParentTask)
					{
						fRunQueue.erase(x);
						break;
					}
				}
				
				// Note that we're not really deleting the objects here, as this poses
				// problems with object destruction versus thread execution; we're
				// just marking them as deleted
				wasDeleted = true;
			}
		}
	}
	
	return wasDeleted;
}

//---------------------------------------------------------------------
// TQueue::_DeleteChildTasks (protected)
//---------------------------------------------------------------------
void TQueue::_DeleteChildTasks (const TaskContext* contextObjPtr)
{
	if (contextObjPtr)
	{
		pthread_t		parentThreadID = contextObjPtr->ThreadID();
		TaskObjPtrList	childList;
		bool			anyWaitTaskDeleted = false;
		
		// Check the wait queue for child tasks
		do
		{
			anyWaitTaskDeleted = false;
			
			for (WaitQueue_iter x = fWaitQueue.begin(); x != fWaitQueue.end(); x++)
			{
				if (x->taskObjPtr->ParentThreadID() == parentThreadID)
				{
					delete(x->taskObjPtr);
					fWaitQueue.erase(x);
					anyWaitTaskDeleted = true;
					break;
				}
			}
		}
		while (anyWaitTaskDeleted);
		
		// Check the run queue for child tasks
		for (RunQueue_iter x = fRunQueue.begin(); x != fRunQueue.end(); x++)
		{
			if (*x &&
				*x != contextObjPtr &&
				(*x)->ContextPtr() &&
				(*x)->ContextPtr()->ParentThreadID() == parentThreadID)
			{
				childList.push_back((*x)->ContextPtr());
			}
		}
		
		// Delete found child tasks (which may call this method again to determine
		// child-of-child tasks)
		for (TaskObjPtrList_const_iter x = childList.begin(); x != childList.end(); x++)
			_DeleteTask(*x);
	}
}

//---------------------------------------------------------------------
// TQueue::_ManageTasks (protected)
//---------------------------------------------------------------------
void TQueue::_ManageTasks ()
{
	bool		doCheck = true;
	
	// Check for stopped running tasks first
	while (doCheck && !fRunQueue.empty())
	{
		bool	anythingTouched = false;
		
		for (RunQueue_iter x = fRunQueue.begin(); x != fRunQueue.end(); x++)
		{
			if ((*x)->HasCompleted())
			{			
				// Found a thread that is no longer running
				try
				{
					(*x)->Join();
				}
				catch (...)
				{				
					// Squelch all errors
				}
				
				if (fIsActive && !(*x)->WasExceptionThrown() && (*x)->ContextPtr()->Rerun())
				{
					// It reexecutes; put it back on our waiting list
					_InsertTask((*x)->ContextPtr(),(*x)->ContextPtr()->ExecutionInterval());
				}
				else
				{
					// We don't reexecute the task, so we need to delete it
					delete((*x)->ContextPtr());
				}
				
				// Delete the thread object
				delete(*x);
				fRunQueue.erase(x);
				
				// Set our anythingTouched boolean to indicate that we need to
				// iterate through the list again
				anythingTouched = true;
				
				// Break out of the for() loop since the iterators are now invalid
				break;
			}
		}
		
		// If we touched anything in the loop then we need to execute again
		doCheck = anythingTouched;
	}
	
	if (fIsActive)
	{
		// Now run waiting tasks if there are any
		doCheck = true;
		
		while (doCheck && !fWaitQueue.empty() && fWaitQueue.front().nextExecTime <= time(NULL))
		{
			TaskContext*	newTaskContext = new TaskContext(fWaitQueue.front().taskObjPtr,false,false,false);
			
			// Remove task from waiting queue
			fWaitQueue.erase(fWaitQueue.begin());
			
			// Add it to the run queue
			fRunQueue.push_back(newTaskContext);
					
			// Set cancel states
			#if HAVE_DECL_PTHREAD_CANCEL_ENABLE
				newTaskContext->SetCancelState(PTHREAD_CANCEL_ENABLE);
			#endif
			
			/*
			#if HAVE_DECL_PTHREAD_CANCEL_ASYNCHRONOUS
				newTaskContext->SetCancelType(PTHREAD_CANCEL_ASYNCHRONOUS);
			#endif
			*/
			
			try
			{
				// Block some signals
				sigset_t		sigSet;
				
				sigprocmask(SIG_SETMASK,NULL,&sigSet);
				sigaddset(&sigSet,SIGABRT);
				
				newTaskContext->SetSignalSetPtr(&sigSet);
				
				newTaskContext->Run();
			}
			catch (...)
			{
				std::string		message;
				
				message = "Warning: Thrown exception while executing task " + newTaskContext->ContextPtr()->TaskName();
				WriteToMessagesLogFile(message);
				
				// We've probably exhausted the system's resources.  Put this task back on the queue
				_InsertTask(newTaskContext->ContextPtr(),0);
				
				// Delete the task object
				delete(newTaskContext);
				
				// Abort the loop
				doCheck = false;
			}
		}
	}
}

//*********************************************************************
// Global Functions
//*********************************************************************

//---------------------------------------------------------------------
// InitTaskQueue
//---------------------------------------------------------------------
void InitTaskQueue ()
{
	// Create the queue module global first
	gTaskQueuePtr = new TQueue;
}

//---------------------------------------------------------------------
// DeleteTaskQueue
//---------------------------------------------------------------------
void DeleteTaskQueue ()
{
	if (gTaskQueuePtr)
	{
		delete(gTaskQueuePtr);
		gTaskQueuePtr = NULL;
	}
}

//---------------------------------------------------------------------
// IsTaskQueueAccepting
//---------------------------------------------------------------------
bool IsTaskQueueAccepting ()
{
	bool	isAccepting = false;
	
	if (gTaskQueuePtr)
		isAccepting = gTaskQueuePtr->IsActive();
	
	return isAccepting;
}

//---------------------------------------------------------------------
// IsTaskQueueExecuting
//---------------------------------------------------------------------
bool IsTaskQueueExecuting ()
{
	bool	isActive = false;
	
	if (gTaskQueuePtr && gTaskQueuePtr->TaskRunnerAvailability())
		isActive = true;
	
	return isActive;
}

//---------------------------------------------------------------------
// _AddTaskToQueue
//---------------------------------------------------------------------
void _AddTaskToQueue (TTaskBase* taskObjPtr, bool runFirst)
{
	if (gTaskQueuePtr)
	{
		if (runFirst)
			gTaskQueuePtr->RunTask(taskObjPtr);
		else
			gTaskQueuePtr->InsertTask(taskObjPtr);
	}
}

//---------------------------------------------------------------------
// _AddDelayedTaskToQueue
//---------------------------------------------------------------------
void _AddDelayedTaskToQueue (TTaskBase* taskObjPtr, time_t delayInSeconds)
{
	if (gTaskQueuePtr)
		gTaskQueuePtr->InsertTask(taskObjPtr,delayInSeconds);
}

//---------------------------------------------------------------------
// _DeleteTaskFromQueue
//---------------------------------------------------------------------
bool _DeleteTaskFromQueue (TTaskBase* taskObjPtr)
{
	bool	wasDeleted = false;
	
	if (gTaskQueuePtr)
		wasDeleted = gTaskQueuePtr->DeleteTask(taskObjPtr);
	
	return wasDeleted;
}

//---------------------------------------------------------------------
// _ClearTaskQueues
//---------------------------------------------------------------------
void _ClearTaskQueues (bool gracefully, bool leaveActive)
{
	if (gTaskQueuePtr)
	{
		gTaskQueuePtr->ClearQueues(gracefully,leaveActive);
	}
}

//---------------------------------------------------------------------
// _IsTaskInQueue
//---------------------------------------------------------------------
bool _IsTaskInQueue (const TTaskBase* taskObjPtr)
{
	bool	inQueue = false;
	
	if (gTaskQueuePtr)
		inQueue = gTaskQueuePtr->IsTaskInQueue(taskObjPtr);
	
	return inQueue;
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

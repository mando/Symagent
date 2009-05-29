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
#		Created:					09 Sep 2003
#		Last Modified:				21 Sep 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_API)
#define SYMLIB_API

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-defs.h"
#include "symlib-exception.h"
#include "symlib-message.h"
#include "symlib-mutex.h"
#include "symlib-tasks.h"

#include <map>
#include <string>
#include <vector>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------


//---------------------------------------------------------------------
// Administration Functions
//---------------------------------------------------------------------

unsigned long SymLibVersion ();
	// Returns the version of this library.

bool SymLibInit (int argc, char** argv, const std::string& agentName);
	// Initialize the library for use.  This must be called before any
	// other function within the library.  The first two arguments
	// correspond to the arguments provided to main(); the agentName
	// argument should be the internal name of agent application.
	// The application may be converted to a daemon from within this
	// function if command-line options indicate it.  Function returns
	// true if the library was initialized correctly AND the calling
	// process should continue.  Callers should abort process if this
	// function returns false.

void SymLibCleanup ();
	// Releases objects and memory allocated while the library was in
	// use.  Call this function last, just before your application quits.

unsigned long ApplicationArgList (StdStringList& argList);
	// Destructively modifies the argument to contain the command-line
	// arguments supplied to the current application.  Returns the
	// number of items in the list.

bool DoesApplicationArgExist (const std::string& arg);
	// Returns a boolean indicating whether or not arg appears somewhere
	// in the argument list provided to the application at launch time.

std::string GetApplicationArgValue (const std::string& arg);
	// Returns the application argument argument _following_ the value
	// of arg.  This is used to extract 'values' from key/value pairs in
	// the argument list.  Example:  if the application was launched
	// with the arguments "-f foo.txt" then calling
	// GetApplicationArgValue("-f") will retrieve "foo.txt" as the result.
	// An empty string will be returned if arg does not appear in the
	// original argument list.

unsigned long long GetDynamicDebuggingFlags ();
	// Returns the current dynamic debugging flags.  These flags are
	// typically set during application invokation via command-line
	// arguments.  See the #defines in symlib-defs.h that are in the
	// format of kDynDebugXXXXXX.

bool RunningAsDaemon ();
	// Returns true if the application was executed in daemon mode via
	// command-line arguments, false otherwise.

void PauseExecution (double seconds);
	// Calls the equivalent of sleep() with the argument, which can be
	// fractional seconds, but with the best resolution timer possible
	// according to the platform.

//---------------------------------------------------------------------
// Logging
//---------------------------------------------------------------------

void WriteToErrorLog (const std::string& logEntry);
	// Writes the contents of the argument to the current error log.
	// Process ID and date/time stamping are automatically included.

void WriteToMessagesLog (const std::string& logEntry);
	// Writes the contents of the argument to the current messages log.
	// Process ID and date/time stamping are automatically included.

//---------------------------------------------------------------------
// Server Communication and Networking
//---------------------------------------------------------------------

void ConnectToServer (TLoginDataNode& additionalLoginNode);
	// Creates a secured connection to a remote server or unsecured
	// connection to a local server, depending on the local
	// configuration file entries.  The XML data included in
	// additionalLoginNode, if any will be appended to the login messages
	// used during the protocol.

void DisconnectFromServer ();
	// Destroys connection with server.  Is safe to call even we don't
	// already have a connection.

bool IsConnectedToServer ();
	// Returns a boolean indicating whether we are currently connected
	// with the server or not.

ResponseCode SendToServer (TServerMessage& xmlData,
						   TServerReply& receivedXMLData,
						   CompressionMode compressionMode = kCompressionModeUnspecified);
	// Sends the XML-formatted data to the server and returns the server's
	// reply in the receivedXMLData argument as well as a response code
	// indicating relative success.

void AdviseServer (std::string advisoryText, unsigned long priority = 0);
	// Sends advisoryText to the server in a special "notice" message
	// format, with the given priority.  Server replies are ignored.  Note
	// that you must have a current server connection for this function
	// to succeed.

bool GetServerCommand (TServerReply& serverCommand);
	// Obtains the most recent server command from the queue, destructively
	// modifying the argument to contain the parsed command.  Returns true
	// if a command was found and parsed, false otherwise.

unsigned long NetworkInterfaceList (StdStringList& interfaceList);
	// Function scans the local system for network interfaces and destructively
	// modifies the argument to contain a list of found interfaces.  Returns
	// the number of interfaces found.

std::string LocalIPAddressAsString ();
	// Returns the local IP address used by the current server connection
	// or an empty string if there is no connection.

int LocalIPPort ();
	// Returns the local port number used by the current server connection or zero
	// if there is no connection.

std::string ServerIPAddressAsString ();
	// Returns the server IP address used by the current server connection
	// or an empty string if there is no connection.

int ServerIPPort ();
	// Returns the server port number used by the current server connection or zero
	// if there is no connection.

//---------------------------------------------------------------------
// Preferences
//---------------------------------------------------------------------
TPreferenceNode GetPreferenceNode ();
	// Returns a reference to the root preference node containing all
	// server-provided configuration/preference information.  Callers
	// of this function should check TPreferenceNode::IsValid() to
	// ensure that the returned reference is good.

//---------------------------------------------------------------------
// Tasks
//---------------------------------------------------------------------

void AddTaskToQueue (TTaskBase* taskObjPtr, bool runFirst);
	// Adds the given task to the task queue.  If runFirst is true
	// then the task is executed at the next opportunity; otherwise,
	// its execution will be delayed by the task's execution interval.
	// Note that the taskObjPtr is now owned by the queue -- callers
	// should not mess around with it (especially delete it).

void AddDelayedTaskToQueue (TTaskBase* taskObjPtr, time_t delayInSeconds);
	// Like _AddTaskToQueue(), except that the task is never immediately
	// executed and it will be set to execute in delayInSeconds seconds.

void DestroyTask (TTaskBase* taskObjPtr);
	// Destroys the task referenced by the argument, removing it from all
	// task queues, freeing memory, etc..

void ClearTaskQueues (bool gracefully = true, bool leaveEnabled = true);
	// Clears the task queue of all queued tasks, running or waiting.
	// If the argument is true then running tasks are allowed to
	// terminate normally; otherwise, they are terminated with extreme
	// prejudice.

bool IsTaskInQueue (const TTaskBase* taskObjPtr);
	// Returns true if the given task object resides in either the run
	// or wait queue, false otherwise.

bool TasksAreRunnable ();
	// Returns a boolean indicating both whether new tasks can be
	// placed on the queue and whether currently-executing tasks should
	// be running currently.

bool TasksAreExecuting ();
	// Returns a boolean indicating whether the task queue is currently
	// running or not.  Tasks that loop internally (not through
	// the task queue) should check this function periodically and exit
	// if false is returned.

bool IsTask ();
	// Returns true if the current process is a spawned task, false if
	// the current process is the main application thread.

FileWatcherRef CreateFileWatcherTask (const std::string& filePath,
									  time_t executionIntervalInSeconds,
									  FileWatchStyle watchStyle = kWatchStyleTail);
	// Creates a file watcher task for the given file and returns an
	// opaque reference to it.  Callers must eventually either hand the
	// reference to QueueFileWatcherTask() or DestroyFileWatcherTask().

void DestroyFileWatcherTask (FileWatcherRef taskRef);
	// Destroys the task referenced by the argument, freeing up memory
	// structures.

void AddFileWatcherCallback (FileWatcherRef taskRef,
							 FileWatchChangeFlag triggerFlags,
							 FileWatchCallback callback,
							 void* userData = NULL);
	// Installs a callback for the file watcher task referenced by taskRef
	// (as returned by CreateFileWatcherTask()), to be called when all
	// of the conditions indicated by the flags set within triggerFlags
	// are met.  The userData argument is optional; its value will be
	// passed back to your callback routine.  This function must be called
	// before QueueFileWatcherTask() is called.

void QueueFileWatcherTask (FileWatcherRef taskRef, bool runFirst);
	// Adds the referenced file watcher task to the task queue.  If runFirst
	// is true then the task is executed at the next opportunity; otherwise,
	// its execution will be delayed by the task's execution interval.
	// Note that referenced task is now owned by the queue; callers should
	// not delete it.

std::string GetNewFileWatcherData (FileWatcherRef taskRef);
	// This function reads additional data that has been appended to a file
	// that the referenced file watcher task is tracking.  It is only
	// functional when called from within a callback triggered by the
	// kFileWatchChangeFlagDataSize flag.  taskRef is provided to the
	// callback, making it easy to gather this information.

bool IsFileWatcherTaskInQueue (FileWatcherRef taskRef);
	// Returns true if the given task object resides in either the run
	// or wait queue, false otherwise.

AppExecRef CreateAppExecTask (const std::string& appPath,
							  const std::string& appArgs,
							  const std::string& appStdInData,
							  time_t executionIntervalInSeconds);
	// Creates an application execution task for the application given in the
	// appPath argument, argument string, and appStdInData data piped to the app.  Function
	// returns an opaque reference to the task.  Callers must eventually either
	// hand the reference to QueueAppExecTask() or DestroyAppExecTask().

void DestroyAppExecTask (AppExecRef taskRef);
	// Destroys the task referenced by the argument, freeing up memory
	// structures.

void AddAppExecCallback (AppExecRef taskRef,
						 AppExecCallback callback,
						 void* userData = NULL);
	// Installs a callback for the application execution task referenced by
	// taskRef (as returned by CreateAppExecTask()).  Callback will be called
	// when the application is executed, with the application's stdout sent
	// to the callback.  The userData argument is optional; its value will be
	// passed back to your callback routine.  This function must be called
	// before QueueAppExecTask() is called.

void QueueAppExecTask (AppExecRef taskRef, bool runFirst);
	// Adds the referenced application execution task to the task queue.  If runFirst
	// is true then the task is executed at the next opportunity; otherwise,
	// its execution will be delayed by the task's execution interval.
	// Note that referenced task is now owned by the queue; callers should
	// not delete it.

bool IsAppExecTaskInQueue (AppExecRef taskRef);
	// Returns true if the given task object resides in either the run
	// or wait queue, false otherwise.

//---------------------------------------------------------------------
// Files and Directories
//---------------------------------------------------------------------

std::string GetFileSignature (const std::string& filePath);
	// Returns the SHA1 signature of the file indicated by the argument.
	// It's recommended that the path be a full path rather than a
	// relative one.

std::string ExecApplication (const std::string& appPath, const std::string appStdInData = "");
	// Executes the application references by the appPath argument with
	// the optional appStdInData data piped to the app.  Returns the
	// application's stdout output.

std::string LocateFile (const std::string& fileName, const StdStringList& directoryList);
	// Given a filename and a list of directories to search, this function
	// attempts to locate a file with that name in those directories.
	// If successful, the real path (as defined by realpath()) is returned,
	// otherwise an empty string is returned.  The first found occurrence,
	// as determined by the ordering of entries in directoryList, is returned.

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

#endif // SYMLIB_API

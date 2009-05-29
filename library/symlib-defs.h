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
#		Created:					27 Aug 2003
#		Last Modified:				21 Sep 2004
#		
#		Revision History:
#		
#		Planned:
#		
#######################################################################
*/

#if !defined(SYMLIB_DEFS)
#define SYMLIB_DEFS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include <string>
#include <map>
#include <sys/stat.h>
#include <vector>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

#if !defined(_PTHREADS)
	#define _PTHREADS
#endif

#if !defined(_REENTRANT)
	#define _REENTRANT
#endif

//---------------------------------------------------
// Standard Application Arguments
//---------------------------------------------------

#define		kAppArgKeyStart								"start"
#define		kAppArgKeyStop								"stop"
#define		kAppArgKeyRestart							"restart"
#define		kAppArgKeyStatus							"status"

#define		kAppArgKeyDaemonize							"--daemon"		// Same functionality as kAppArgKeyStart

#define		kAppArgKeyEnableCommLogging					"--enable-comm-logging"
#define		kAppArgKeyUse7200ConfFile					"--conf-use-7200"

//---------------------------------------------------
// Response codes for server communication
//---------------------------------------------------
typedef		enum
				{
					kResponseCodeUnknown,
					kResponseCodeOK,
					kResponseCodeNotProvisionedErr,
					kResponseCodeDBUnavailErr,
				}	ResponseCode;

//---------------------------------------------------
// Compression Modes
//---------------------------------------------------
typedef		enum
				{
					kCompressionModeUnspecified = 0,
					kCompressionModeNone,
					kCompressionModeZLib,	// Not supported for server communication
					kCompressionModeGZip
				}	CompressionMode;

//---------------------------------------------------
// Dynamic debugging flags
// (note: Max 64 bits)
//---------------------------------------------------

#define		kDynDebugNone								0
#define		kDynDebugLogServerCommunication				1

//---------------------------------------------------
// General-use data structures and whatnot
//---------------------------------------------------

typedef		std::vector<std::string>					StdStringList;
typedef		StdStringList::iterator						StdStringList_iter;
typedef		StdStringList::const_iterator				StdStringList_const_iter;

//---------------------------------------------------
// File Watcher definitions
//---------------------------------------------------

typedef		enum
				{
					kWatchStyleTail,
					kWatchStyleContents
				}	FileWatchStyle;

typedef 	struct
				{
					double					timestamp;
					struct stat				stat;
					bool					exists;
				}	FileWatchFileInfo;

typedef		unsigned long long							FileWatchChangeFlag;

#define		kFileWatchChangeFlagNone					0
#define		kFileWatchChangeFlagHardLinkCount			1
#define		kFileWatchChangeFlagOwner					2
#define		kFileWatchChangeFlagGroupChange				4
#define		kFileWatchChangeFlagTimeDataAccessed		8
#define		kFileWatchChangeFlagTimeDataModified		16
#define		kFileWatchChangeFlagTimeMetadataModified	32
#define		kFileWatchChangeFlagDataSize				64
#define		kFileWatchChangeFlagAppeared				128
#define		kFileWatchChangeFlagDisappeared				256
#define		kFileWatchChangeFlagRotated					512
#define		kFileWatchChangeFlagContentsModified		1024

typedef		void*										FileWatcherRef;

typedef		bool (*FileWatchCallback) (const std::string& filePath,
									   const FileWatchFileInfo& currentInfo,
									   const FileWatchFileInfo& prevInfo,
									   FileWatcherRef taskRef,
									   void* userData);
	// The callback function is called from the task watching a particular
	// file when certain conditions are met.  The filePath argument contains
	// the pathname of the file being watched.  The currentInfo and prevInfo
	// arguments show the file's current state and the previous state,
	// respectively.  The taskRef argument will contain a reference back
	// to the task, and is required when requesting more information from
	// the library (other functions require it).  The arguments are valid
	// only for the duration of the callback within the current processing
	// thread.  Note that if you use the same callback for multiple file
	// watching tasks then your callback must be thread-safe.  If the callback
	// returns true then no other callback functions for this same file/trigger
	// combination will be called; if false is returned then the next
	// callback (if any) is called.

//---------------------------------------------------
// Application Execution definitions
//---------------------------------------------------

typedef		void*										AppExecRef;

typedef		bool (*AppExecCallback) (const std::string& returnedData,
									 AppExecRef taskRef,
									 void* userData);
	// The callback function is called from the task executing an external
	// application.  The output from the application's stdout is collected
	// and sent to the callback in the returnedData argument.  The taskRef
	// argument will contain a reference back to the task; userData is
	// the (possibly NULL) pointer to user data passed to the function
	// that registered the callback.  If the callback returns true then
	// no other callback functions registered with this task will be
	// called; if false is returned then the next callback (if any)
	// will be called.

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

#endif // SYMLIB_DEFS

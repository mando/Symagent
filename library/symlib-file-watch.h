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
#		Created:					14 Nov 2003
#		Last Modified:				21 Sep 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_FILE_WATCH)
#define SYMLIB_FILE_WATCH

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-config.h"

#include "symlib-defs.h"
#include "symlib-file.h"
#include "symlib-tasks.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TTaskFileWatch;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Class TTaskFileWatch
//---------------------------------------------------------------------
class TTaskFileWatch : public TTaskBase
{
	private:
		
		typedef	TTaskBase											Inherited;
	
	protected:
		
		typedef	std::pair<FileWatchCallback,void*>					CallbackArgs;
		typedef	std::pair<FileWatchChangeFlag,CallbackArgs>			CallbackTrigger;
		
		typedef	std::vector<CallbackTrigger>						CallbackList;
		typedef	CallbackList::iterator								CallbackList_iter;
		typedef	CallbackList::const_iterator						CallbackList_const_iter;
	
	public:
		
		TTaskFileWatch (FileWatchStyle watchStyle = kWatchStyleTail);
			// Constructor
		
		TTaskFileWatch (time_t intervalInSeconds, FileWatchStyle watchStyle = kWatchStyleTail);
			// Constructor
	
	private:
		
		TTaskFileWatch (const TTaskFileWatch& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TTaskFileWatch ();
			// Destructor
		
		virtual void SetupTask (const TFileObj& fileObj, FileWatchStyle watchStyle = kWatchStyleTail);
			// Sets up the task so it can execute in the background.
		
		virtual void SetupTask (const std::string& filePath, FileWatchStyle watchStyle = kWatchStyleTail);
			// Sets up the task so it can execute in the background.
		
		virtual void AddCallback (FileWatchChangeFlag triggerFlags,
								  FileWatchCallback callbackFunction,
								  void* userData = NULL);
			// Adds the given callback to the internal list.  It's call will
			// be triggered for events of type triggerFlag that occur to the
			// current file.
		
		virtual void RunTask ();
			// Entry point for the task.
		
		virtual void GetFileInfo (FileWatchFileInfo& currentInfo, FileWatchFileInfo& prevInfo) const;
			// Retrieves the current and previous file info structures,
			// destructively modifying the arguments to contain the results.
		
		virtual std::string ReadAddedFileData ();
			// If the current data size is larger than the previous,
			// this method returns the data that was added to the file.
		
		//----------------------------------
		// Accessors
		//----------------------------------
		
		inline bool IsDefined () const
			{ return (!fFileObj.Path().empty()); }
		
		inline std::string FilePath () const
			{ return fFileObj.Path(); }
		
		inline std::string RealFilePath () const
			{ return fFileObj.RealPath(); }
	
	protected:
		
		virtual FileWatchChangeFlag _GetStat ();
			// Compares file statistics without opening the file,
			// returning flags indicating changes found.
		
		virtual void _DispatchCallbacks (FileWatchChangeFlag flag);
			// Dispatches to callbacks that trigger for the given flag.
		
		virtual std::string _ComputeFileSignature ();
			// Computes the signature of the contents of the current file and
			// returns it.  The return value will be empty if the file doesn't exist.
	
	protected:
		
		TFileObj								fFileObj;
		FileWatchFileInfo						fCurrentFileInfo;
		FileWatchFileInfo						fPrevFileInfo;
		STAT_TIME_TYPE							fInternalAccessTime;
		CallbackList							fCallbackList;
		FileWatchStyle							fWatchStyle;
		std::string								fContentSig;
		bool									fInited;
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

#endif // SYMLIB_FILE_WATCH

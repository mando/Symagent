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

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-file-watch.h"

#include "symlib-ssl-digest.h"
#include "symlib-ssl-encode.h"
#include "symlib-time.h"
#include "symlib-utils.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Module Definitions
//---------------------------------------------------------------------
#define	kDefaultExecutionInterval								60

//*********************************************************************
// Class TTaskFileWatch
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TTaskFileWatch::TTaskFileWatch (FileWatchStyle watchStyle)
	:	Inherited(gEnvironObjPtr->GetTaskName(),kDefaultExecutionInterval,true),
		fWatchStyle(watchStyle),
		fInited(false)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TTaskFileWatch::TTaskFileWatch (time_t intervalInSeconds, FileWatchStyle watchStyle)
	:	Inherited(gEnvironObjPtr->GetTaskName(),intervalInSeconds,true),
		fWatchStyle(watchStyle),
		fInited(false)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TTaskFileWatch::~TTaskFileWatch ()
{
}

//---------------------------------------------------------------------
// TTaskFileWatch::SetupTask
//---------------------------------------------------------------------
void TTaskFileWatch::SetupTask (const TFileObj& fileObj, FileWatchStyle watchStyle)
{
	// Make sure any existing file we're tracking is closed
	fFileObj.Close();
	
	// Initialize our internal slots
	fFileObj = fileObj;
	memset(&fCurrentFileInfo,0,sizeof(fCurrentFileInfo));
	memset(&fPrevFileInfo,0,sizeof(fPrevFileInfo));
	memset(&fInternalAccessTime,0,sizeof(fInternalAccessTime));
	fWatchStyle = watchStyle;
	fInited = false;
}

//---------------------------------------------------------------------
// TTaskFileWatch::SetupTask
//---------------------------------------------------------------------
void TTaskFileWatch::SetupTask (const std::string& filePath, FileWatchStyle watchStyle)
{
	SetupTask(TFileObj(filePath),watchStyle);
}

//---------------------------------------------------------------------
// TTaskFileWatch::AddCallback
//---------------------------------------------------------------------
void TTaskFileWatch::AddCallback (FileWatchChangeFlag triggerFlags,
								  FileWatchCallback callbackFunction,
								  void* userData)
{
	if (!fInited)
	{
		if (triggerFlags != kFileWatchChangeFlagNone && callbackFunction != NULL)
			fCallbackList.push_back(make_pair(triggerFlags,make_pair(callbackFunction,userData)));
	}
}

//---------------------------------------------------------------------
// TTaskFileWatch::RunTask
//---------------------------------------------------------------------
void TTaskFileWatch::RunTask ()
{
	FileWatchChangeFlag		fileChanges = kFileWatchChangeFlagNone;
	
	if (!fCallbackList.empty())
	{
		fileChanges = _GetStat();
		
		if (fileChanges != kFileWatchChangeFlagNone)
			_DispatchCallbacks(fileChanges);
	}
}

//---------------------------------------------------------------------
// TTaskFileWatch::GetFileInfo
//---------------------------------------------------------------------
void TTaskFileWatch::GetFileInfo (FileWatchFileInfo& currentInfo, FileWatchFileInfo& prevInfo) const
{
	currentInfo = fCurrentFileInfo;
	prevInfo = fPrevFileInfo;
}

//---------------------------------------------------------------------
// TTaskFileWatch::ReadAddedFileData
//---------------------------------------------------------------------
std::string TTaskFileWatch::ReadAddedFileData ()
{
	std::string		data;
	
	if (fWatchStyle == kWatchStyleTail)
	{
		if (fInited && fCurrentFileInfo.stat.st_size != fPrevFileInfo.stat.st_size)
		{
			unsigned long	startPos = 0;
			unsigned long	endPos = 0;
			
			if (fCurrentFileInfo.stat.st_size > fPrevFileInfo.stat.st_size)
			{
				startPos = fPrevFileInfo.stat.st_size;
				endPos = fCurrentFileInfo.stat.st_size;
			}
			else
			{
				startPos = 0;
				endPos = fCurrentFileInfo.stat.st_size;
			}
			
			try
			{
				if (fFileObj.IsOpen())
				{
					struct stat		info;
					
					fFileObj.SetFilePosition(startPos);
					fFileObj.Read(data,endPos - startPos);
					
					// Log our own access to the file
					fFileObj.StatInfo(info,true);
					fInternalAccessTime = info.STAT_TIME_ATIME;
				}
			}
			catch (...)
			{
				// Make sure the file is closed
				fFileObj.Close();
				throw;
			}
		}
	}
	else if (fWatchStyle == kWatchStyleContents)
	{
		if (fFileObj.Exists())
			fFileObj.ReadWholeFile(data);
	}
	
	return data;
}

//---------------------------------------------------------------------
// TTaskFileWatch::_GetStat (protected)
//---------------------------------------------------------------------
FileWatchChangeFlag TTaskFileWatch::_GetStat ()
{
	FileWatchChangeFlag		changes = kFileWatchChangeFlagNone;
	
	// Move current stats to prev
	fPrevFileInfo = fCurrentFileInfo;
	
	if (!fInited)
	{
		// First call to the method -- initialize things
		if (fFileObj.Exists())
		{
			fCurrentFileInfo.exists = true;
			fFileObj.Open();
			fFileObj.StatInfo(fCurrentFileInfo.stat,true);
			
			if (fWatchStyle == kWatchStyleContents)
				fContentSig = _ComputeFileSignature();
		}
		else
		{
			fCurrentFileInfo.exists = false;
		}
		
		fCurrentFileInfo.timestamp = CurrentMilliseconds();
		fInited = true;
	}
	else
	{
		if (!fFileObj.IsOpen())
		{
			// See if the file is present
			if (fFileObj.Exists())
			{
				if (!fPrevFileInfo.exists)
				{
					// The file didn't exist before
					fCurrentFileInfo.exists = true;
					changes |= kFileWatchChangeFlagAppeared;
					fFileObj.Open();
					fFileObj.StatInfo(fCurrentFileInfo.stat,true);
					
					if (fWatchStyle == kWatchStyleContents)
						fContentSig = _ComputeFileSignature();
				}
				else
				{
					// The file _did_ exist before, so it's been rotated
					fCurrentFileInfo.exists = true;
					changes |= kFileWatchChangeFlagRotated;
					fFileObj.Open();
					memset(&fCurrentFileInfo.stat,0,sizeof(fCurrentFileInfo.stat));
					fContentSig = "";
				}
			}
			else
			{
				if (fPrevFileInfo.exists)
				{
					// The file existed before and doesn't now
					changes |= kFileWatchChangeFlagDisappeared;
				}
				
				memset(&fCurrentFileInfo.stat,0,sizeof(fCurrentFileInfo.stat));
				fCurrentFileInfo.exists = false;
				fContentSig = "";
			}
			
			fCurrentFileInfo.timestamp = CurrentMilliseconds();
		}
		else
		{
			TFileObj		tempFileObj(fFileObj.Path());
			struct stat		tempFileInfo;
			
			// We already opened a file for tracking; get updated stats
			fCurrentFileInfo.exists = true;
			fFileObj.StatInfo(fCurrentFileInfo.stat,true);
			fCurrentFileInfo.timestamp = CurrentMilliseconds();
			
			// Compare and set other flags
			if (fCurrentFileInfo.stat.st_nlink != fPrevFileInfo.stat.st_nlink)
				changes |= kFileWatchChangeFlagHardLinkCount;
			if (fCurrentFileInfo.stat.st_uid != fPrevFileInfo.stat.st_uid)
				changes |= kFileWatchChangeFlagOwner;
			if (fCurrentFileInfo.stat.st_gid != fPrevFileInfo.stat.st_gid)
				changes |= kFileWatchChangeFlagGroupChange;
			// We use memcmp's here because we don't know exactly what kind of data type these time
			// fields are
			if (memcmp(&fCurrentFileInfo.stat.STAT_TIME_ATIME,&fPrevFileInfo.stat.STAT_TIME_ATIME,sizeof(fPrevFileInfo.stat.STAT_TIME_ATIME)) != 0 &&
				memcmp(&fCurrentFileInfo.stat.STAT_TIME_ATIME,&fInternalAccessTime,sizeof(fInternalAccessTime)) != 0)
				changes |= kFileWatchChangeFlagTimeDataAccessed;
			if (memcmp(&fCurrentFileInfo.stat.STAT_TIME_MTIME,&fPrevFileInfo.stat.STAT_TIME_MTIME,sizeof(fPrevFileInfo.stat.STAT_TIME_MTIME)) != 0)
				changes |= kFileWatchChangeFlagTimeDataModified;
			if (memcmp(&fCurrentFileInfo.stat.STAT_TIME_CTIME,&fPrevFileInfo.stat.STAT_TIME_CTIME,sizeof(fPrevFileInfo.stat.STAT_TIME_CTIME)) != 0)
				changes |= kFileWatchChangeFlagTimeMetadataModified;
			if (fCurrentFileInfo.stat.st_size != fPrevFileInfo.stat.st_size)
				changes |= kFileWatchChangeFlagDataSize;
			
			if (fWatchStyle == kWatchStyleContents)
			{
				std::string		newSig = _ComputeFileSignature();
				
				if (fContentSig != newSig)
				{
					changes |= kFileWatchChangeFlagContentsModified;
					fContentSig = newSig;
				}
			}
			
			// Make sure our currently-opened file hasn't been
			// renamed and another file has taken its place
			
			if (tempFileObj.Exists())
			{
				tempFileObj.StatInfo(tempFileInfo,true);
				if (tempFileInfo.st_ino != fCurrentFileInfo.stat.st_ino || tempFileInfo.st_dev != fCurrentFileInfo.stat.st_dev)
				{
					// There is now another file with our name on the disk;
					// close our open pipe so the new file's info will be
					// picked up over the next two method calls
					fFileObj.Close();
				}
			}
			else
			{
				// Looks like we've been closed and deleted; close our open
				// pipe to pick up the status on the next method call.
				fFileObj.Close();
			}
		}
	}
	
	return changes;
}

//---------------------------------------------------------------------
// TTaskFileWatch::_DispatchCallbacks (protected)
//---------------------------------------------------------------------
void TTaskFileWatch::_DispatchCallbacks (FileWatchChangeFlag flag)
{
	for (CallbackList_const_iter x = fCallbackList.begin(); x != fCallbackList.end(); x++)
	{
		if (BitTest(flag,x->first))
		{
			FileWatchCallback		functionPtr = x->second.first;
			void*					userData = x->second.second;
			
			if ((*functionPtr)(fFileObj.Path(),fCurrentFileInfo,fPrevFileInfo,this,userData))
			{
				// User function returned true, indicating that processing should stop
				break;
			}
		}
	}
}

//---------------------------------------------------------------------
// TTaskFileWatch::_ComputeFileSignature (protected)
//---------------------------------------------------------------------
std::string TTaskFileWatch::_ComputeFileSignature ()
{
	std::string		sig;
	
	if (fFileObj.Exists())
	{
		TDigest			fileSigDigestObj("SHA1");
		TDigestContext	fileSigDigestContextObj;
		TEncodeContext	encodeContext;
		
		// Compute the signature of this executable
		fileSigDigestContextObj.Initialize(fileSigDigestObj);
		fileSigDigestContextObj.Update(fFileObj);
		sig = encodeContext.Encode(fileSigDigestContextObj.Final());
	}
	
	return sig;
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

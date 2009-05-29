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
#		Created:					24 Oct 2003
#		Last Modified:				22 Feb 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-file.h"

#include "symlib-threads.h"
#include "symlib-utils.h"

#if HAVE_DIRENT_H
	#include <dirent.h>
	#define NAMLEN(dirent) strlen((dirent)->d_name)
#else
	#define dirent direct
	#define NAMLEN(dirent) (dirent)->d_namlen
	#if HAVE_SYS_NDIR_H
		#include <sys/ndir.h>
	#endif
	#if HAVE_SYS_DIR_H
		#include <sys/dir.h>
	#endif
	#if HAVE_NDIR_H
		#include <ndir.h>
	#endif
#endif

#include <ctime>
#include <fnmatch.h>
#include <grp.h>
#include <memory>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Object Static Member Initializations
//---------------------------------------------------------------------
const int				TFileObj::kInvalidFD = -1;
const unsigned long		TFileObj::kReadWriteBlockSize = 4096;

const OS_Flags			TLogFileObj::kRequiredOSFlags = (O_WRONLY | O_CREAT | O_APPEND);

//---------------------------------------------------------------------
// Module Global Variables
//---------------------------------------------------------------------
static		TPthreadMutexObj							gRealPathMutex;

//*********************************************************************
// Module Class TKillProcess
//*********************************************************************
class TKillProcess
{
	public:
		
		TKillProcess (pid_t procPID) : fPID(procPID)
			{}
		
		~TKillProcess ()
			{
				kill(fPID,SIGKILL);
			}
	
	private:
		
		pid_t							fPID;
};

//*********************************************************************
// Class TFSObject
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TFSObject::TFSObject ()
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TFSObject::TFSObject (const std::string& path)
	:	fPath(path)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TFSObject::TFSObject (const TFSObject& obj)
	:	fPath(obj.fPath)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TFSObject::~TFSObject ()
{
}

//---------------------------------------------------------------------
// TFSObject::SetPath
//---------------------------------------------------------------------
void TFSObject::SetPath (const std::string& newPath)
{
	fPath = newPath;
}

//---------------------------------------------------------------------
// TFSObject::FileName
//---------------------------------------------------------------------
std::string TFSObject::FileName () const
{
	StdStringList	pathComponents;
	std::string		filename;
	
	if (!Path().empty())
		SplitStdString(kPathDelimiterAsChar,Path(),pathComponents,false);
	
	if (!pathComponents.empty())
		filename = pathComponents.back();
	
	return filename;
}

//---------------------------------------------------------------------
// TFSObject::DirectoryPath
//---------------------------------------------------------------------
std::string TFSObject::DirectoryPath () const
{
	std::string		dirPath;
	StdStringList	pathComponents;
	bool			initialDelim = ((!fPath.empty() && fPath[0] == kPathDelimiterAsChar) ? true : false);
	
	SplitStdString(kPathDelimiterAsChar,Path(),pathComponents,false);
	pathComponents.pop_back();
	if (initialDelim)
		dirPath += kPathDelimiterAsString;
	dirPath += JoinStdStringList(kPathDelimiterAsChar,pathComponents);
	dirPath += kPathDelimiterAsString;
	
	return dirPath;
}

//---------------------------------------------------------------------
// TFSObject::RealPath
//---------------------------------------------------------------------
std::string TFSObject::RealPath () const
{
	std::string	realPath;
	char		pathBuffer[PATH_MAX];
	char*		sysResult = NULL;
	
	#if HAVE_BROKEN_REALPATH
		// Seize a mutex so we're not tromping all over someone else's realpath() call
		TLockedPthreadMutexObj			lock(gRealPathMutex);
		
		// Open a pointer to our current directory
		DIR*	currentDirPtr = opendir(".");
	#endif
	
	sysResult = realpath(Path().c_str(),pathBuffer);
	
	#if HAVE_BROKEN_REALPATH
		if (currentDirPtr)
		{
			// Make sure we're back at our current directory
			fchdir(dirfd(currentDirPtr));
			closedir(currentDirPtr);
		}
	#endif
	
	if (sysResult)
	{
		// Success
		realPath = pathBuffer;
	}
	else
	{
		std::string		errString;
		
		errString += "While attempting to obtain the real path for '" + Path() + "'";
		throw TSymLibErrorObj(errno,errString);
	}
	
	if (IsDir())
	{
		if (realPath.empty() || realPath[realPath.length()-1] != kPathDelimiterAsChar)
			realPath += kPathDelimiterAsChar;
	}
	
	return realPath;
}

//---------------------------------------------------------------------
// TFSObject::Rename
//---------------------------------------------------------------------
void TFSObject::Rename (const std::string& newName)
{
	if (rename(Path().c_str(),newName.c_str()) != 0)
	{
		std::string		errString;
		
		errString += "While attempting to rename '" + Path() + "' to '" + newName + "'";
		throw TSymLibErrorObj(errno,errString);
	}
	
	SetPath(newName);
}

//---------------------------------------------------------------------
// TFSObject::Exists
//---------------------------------------------------------------------
bool TFSObject::Exists (bool followSymLinks) const
{
	bool	exists = false;
	
	if (!Path().empty())
		exists = (access(Path().c_str(),F_OK) == 0);
	
	return exists;
}

//---------------------------------------------------------------------
// TFSObject::StatInfo
//---------------------------------------------------------------------
void TFSObject::StatInfo (struct stat& statInfo, bool followSymLinks) const
{
	if (Path().empty())
		throw TSymLibErrorObj(EFAULT,"No pathname is specified while trying to obtain stat info");
	
	if (followSymLinks)
	{
		if (stat(Path().c_str(),&statInfo) != 0)
		{
			std::string		errString;
			
			errString += "While attempting to get stat info for '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
	else
	{
		if (lstat(Path().c_str(),&statInfo) != 0)
		{
			std::string		errString;
			
			errString += "While attempting to get stat info for '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
}

//---------------------------------------------------------------------
// TFSObject::Permissions
//---------------------------------------------------------------------
OS_Mode TFSObject::Permissions (bool followSymLinks) const
{
	struct stat		statInfo;
	const OS_Mode	kFilePermMask = (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO);
	
	StatInfo(statInfo,followSymLinks);
	
	return (statInfo.st_mode & kFilePermMask);
}

//---------------------------------------------------------------------
// TFSObject::SetPermissions
//---------------------------------------------------------------------
void TFSObject::SetPermissions (OS_Mode newPerms) const
{
	const OS_Mode	kFilePermMask = (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO);
	
	if (Path().empty())
		throw TSymLibErrorObj(EFAULT,"No pathname is specified while trying to change permission");
	
	if (chmod(Path().c_str(),(newPerms & kFilePermMask)) != 0)
	{
		std::string		errString;
		
		errString += "While attempting to change access permissions for '" + Path() + "'";
		throw TSymLibErrorObj(errno,errString);
	}
}

//---------------------------------------------------------------------
// TFSObject::HasPermissions
//---------------------------------------------------------------------
bool TFSObject::HasPermissions (bool canRead, bool canWrite, bool canExecute, bool allRequired) const
{
	bool		hasPerms = false;
	OS_Mode		perms;
	
	if (Path().empty())
		throw TSymLibErrorObj(EFAULT,"No pathname is specified while trying to check permissions");
	
	if (getuid() == 0)
	{
		// Root always has permissions
		hasPerms = true;
	}
	else
	{
		if (allRequired)
		{
			perms = (canRead ? R_OK : 0) | (canWrite ? W_OK : 0) | (canExecute ? X_OK : 0);
			hasPerms = (access(Path().c_str(),perms) == 0);
		}
		else
		{
			if (canRead)
				hasPerms |= (access(Path().c_str(),R_OK) == 0);
			if (canWrite)
				hasPerms |= (access(Path().c_str(),W_OK) == 0);
			if (canExecute)
				hasPerms |= (access(Path().c_str(),X_OK) == 0);
		}
	}
	
	return hasPerms;
}

//---------------------------------------------------------------------
// TFSObject::OwnerID
//---------------------------------------------------------------------
uid_t TFSObject::OwnerID (bool followSymLinks) const
{
	struct stat		statInfo;
	
	StatInfo(statInfo,followSymLinks);
	
	return statInfo.st_uid;
}

//---------------------------------------------------------------------
// TFSObject::OwnerName
//---------------------------------------------------------------------
std::string TFSObject::OwnerName (bool followSymLinks) const
{
	std::string		ownerName;
	uid_t			ownerID = OwnerID(followSymLinks);
	struct passwd*	ownerInfoPtr = getpwuid(ownerID);
	
	if (!ownerInfoPtr)
	{
		std::string		errString;
		
		if (errno == 0)
		{
			// Owner name not found; return the owner ID
			ownerName = NumToString(ownerID);
		}
		else
		{
			errString += "While attempting to retrieve the owner name for '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
	else
		ownerName = ownerInfoPtr->pw_name;
	
	return ownerName;
}

//---------------------------------------------------------------------
// TFSObject::SetOwner
//---------------------------------------------------------------------
void TFSObject::SetOwner (uid_t ownerID, bool followSymLinks) const
{
	#if !defined(HAVE_LCHOWN) || !HAVE_LCHOWN
		// Force symlink following
		followSymLinks = true;
	#endif
	
	if (followSymLinks)
	{
		if (chown(Path().c_str(),ownerID,static_cast<gid_t>(-1)) != 0)
		{
			std::string		errString;
			
			errString += "While attempting to change the owner for '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
	#if defined(HAVE_LCHOWN) && HAVE_LCHOWN
		else
		{
			if (lchown(Path().c_str(),ownerID,static_cast<gid_t>(-1)) != 0)
			{
				std::string		errString;
				
				errString += "While attempting to change the owner for '" + Path() + "'";
				throw TSymLibErrorObj(errno,errString);
			}
		}
	#endif
}

//---------------------------------------------------------------------
// TFSObject::SetOwner
//---------------------------------------------------------------------
void TFSObject::SetOwner (const std::string& ownerName, bool followSymLinks) const
{
	uid_t		ownerID = MapUserNameToUID(ownerName.c_str());
	
	if (ownerID == static_cast<uid_t>(-1))
	{
		std::string		errString;
		
		errString += "User '" + ownerName + "' not found while attempting to set owner for '" + Path() + "'";
		throw TSymLibErrorObj(ENXIO,errString);
	}
	
	SetOwner(ownerID,followSymLinks);
}

//---------------------------------------------------------------------
// TFSObject::GroupID
//---------------------------------------------------------------------
gid_t TFSObject::GroupID (bool followSymLinks) const
{
	struct stat		statInfo;
	
	StatInfo(statInfo,followSymLinks);
	
	return statInfo.st_gid;
}

//---------------------------------------------------------------------
// TFSObject::GroupName
//---------------------------------------------------------------------
std::string TFSObject::GroupName (bool followSymLinks) const
{
	std::string		groupName;
	gid_t			groupID = GroupID(followSymLinks);
	struct group*	groupInfoPtr = getgrgid(groupID);
	
	if (!groupInfoPtr)
	{
		std::string		errString;
		
		if (errno == 0)
		{
			// Group name not found; return the group ID
			groupName = NumToString(groupID);
		}
		else
		{
			errString += "While attempting to retrieve the owning group name for '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
	else
		groupName = groupInfoPtr->gr_name;
	
	return groupName;
}

//---------------------------------------------------------------------
// TFSObject::SetGroup
//---------------------------------------------------------------------
void TFSObject::SetGroup (gid_t groupID, bool followSymLinks) const
{
	#if !defined(HAVE_LCHOWN) || !HAVE_LCHOWN
		// Force symlink following
		followSymLinks = true;
	#endif
	
	if (followSymLinks)
	{
		if (chown(Path().c_str(),static_cast<uid_t>(-1),groupID) != 0)
		{
			std::string		errString;
			
			errString += "While attempting to change the owning group for '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
	#if defined(HAVE_LCHOWN) && HAVE_LCHOWN
		else
		{
			if (lchown(Path().c_str(),static_cast<uid_t>(-1),groupID) != 0)
			{
				std::string		errString;
				
				errString += "While attempting to change the owning group for '" + Path() + "'";
				throw TSymLibErrorObj(errno,errString);
			}
		}
	#endif
}

//---------------------------------------------------------------------
// TFSObject::SetGroup
//---------------------------------------------------------------------
void TFSObject::SetGroup (const std::string& groupName, bool followSymLinks) const
{
	gid_t		groupID = MapGroupNameToGID(groupName.c_str());
	
	if (groupID == static_cast<gid_t>(-1))
	{
		std::string		errString;
		
		errString += "Group '" + groupName + "' not found while attempting to set owning group for '" + Path() + "'";
		throw TSymLibErrorObj(ENXIO,errString);
	}
	
	SetGroup(groupID,followSymLinks);
}

//---------------------------------------------------------------------
// TFSObject::LastAccessTime
//---------------------------------------------------------------------
TTimeObj TFSObject::LastAccessTime (bool followSymLinks) const
{
	TTimeObj		timeObj;
	struct stat		statInfo;
	
	StatInfo(statInfo,followSymLinks);
	timeObj.SetDateTime(statInfo.st_atime);
	
	return timeObj;
}

//---------------------------------------------------------------------
// TFSObject::ModificationTime
//---------------------------------------------------------------------
TTimeObj TFSObject::ModificationTime (bool followSymLinks) const
{
	TTimeObj		timeObj;
	struct stat		statInfo;
	
	StatInfo(statInfo,followSymLinks);
	timeObj.SetDateTime(statInfo.st_mtime);
	
	return timeObj;
}

//---------------------------------------------------------------------
// TFSObject::StatModificationTime
//---------------------------------------------------------------------
TTimeObj TFSObject::StatModificationTime (bool followSymLinks) const
{
	TTimeObj		timeObj;
	struct stat		statInfo;
	
	StatInfo(statInfo,followSymLinks);
	timeObj.SetDateTime(statInfo.st_ctime);
	
	return timeObj;
}

//*********************************************************************
// Class TFileObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TFileObj::TFileObj ()
	:	fFileDescriptor(kInvalidFD),
		fEOF(false),
		fOpenFlags(0),
		fOpenMode(0)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TFileObj::TFileObj (const std::string& path)
	:	Inherited(path),
		fFileDescriptor(kInvalidFD),
		fEOF(false),
		fOpenFlags(0),
		fOpenMode(0)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TFileObj::TFileObj (const TFileObj& obj)
	:	Inherited(obj),
		fFileDescriptor(kInvalidFD),
		fEOF(false),
		fOpenFlags(0),
		fOpenMode(0)
{
	if (obj.IsOpen())
	{
		// We need to open the file as well.  Make sure we don't do
		// anything bad like truncate the file on open
		OS_Flags	newFlags = obj.fOpenFlags & (~O_TRUNC);
		
		if (obj.fOpenMode == 0)
			Open(newFlags);
		else
			Open(newFlags,obj.fOpenMode);
		
		SetFilePosition(obj.GetFilePosition());
	}
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TFileObj::~TFileObj ()
{
	if (IsOpen())
	{
		try
		{
			CloseWithoutInterrupts(FileDescriptor());
		}
		catch (...)
		{
			// Ignore all errors
		}
		
		fFileDescriptor = kInvalidFD;
		fEOF = false;
		fOpenFlags = 0;
		fOpenMode = 0;
	}
}

//---------------------------------------------------------------------
// TFileObj::SetPath
//---------------------------------------------------------------------
void TFileObj::SetPath (const std::string& newPath)
{
	// Don't allow this to succeed if we're open
	if (IsOpen())
	{
		std::string		errString;
		
		errString += "Attempt to set internal path from '" + Path() + "' to '" + newPath + "' while file is open";
		throw TSymLibErrorObj(EPERM,errString);
	}
	
	Inherited::SetPath(newPath);
}

//---------------------------------------------------------------------
// TFileObj::Create
//---------------------------------------------------------------------
void TFileObj::Create (OS_Mode mode, bool overwriteIfExists)
{
	if (Path().empty())
		throw TSymLibErrorObj(EFAULT,"No pathname is specified while attempting to create a file");
	
	// Close our open file, if we have one
	Close();
	
	// If overwrite is true attempt to delete the file
	if (overwriteIfExists)
	{
		if (unlink(Path().c_str()) != 0)
		{
			// Ignore does-not-exist errors, throw all others
			if (errno != ENOENT)
			{
				std::string		errString;
				
				errString += "While attempting to create file '" + Path() + "'";
				throw TSymLibErrorObj(errno,errString);
			}
		}
	}
	
	// Now create the file
	fFileDescriptor = CreatWithoutInterrupts(Path().c_str(),mode);
	if (FileDescriptor() != -1)
	{
		// Create actually opens the damn thing.  If someone called this method
		// explicitly then they don't want it open.  Immediately close it.
		Close();
	}
	else
	{
		std::string		errString;
		
		errString += "While attempting to create file '" + Path() + "'";
		throw TSymLibErrorObj(errno,errString);
	}
}

//---------------------------------------------------------------------
// TFileObj::Create
//---------------------------------------------------------------------
void TFileObj::Create (const std::string& path, OS_Mode mode, bool overwriteIfExists)
{
	Close();
	
	SetPath(path);
	
	Create(mode,overwriteIfExists);
}

//---------------------------------------------------------------------
// TFileObj::Open
//---------------------------------------------------------------------
void TFileObj::Open (OS_Flags flags)
{
	if (Path().empty())
		throw TSymLibErrorObj(EFAULT,"No pathname is specified while attempting to open a file");
	
	// Close our open file, if we have one
	Close();
	
	// Open the new file
	fFileDescriptor = OpenWithoutInterrupts(Path().c_str(),flags);
	
	if (FileDescriptor() <= 0)
	{
		std::string		errString;
		
		errString += "While attempting to open file '" + Path() + "'";
		fFileDescriptor = kInvalidFD;
		throw TSymLibErrorObj(errno,errString);
	}
	
	fOpenFlags = flags;
	
	ResetEOF();
}

//---------------------------------------------------------------------
// TFileObj::Open
//---------------------------------------------------------------------
void TFileObj::Open (OS_Flags flags, OS_Mode mode)
{
	if (Path().empty())
		throw TSymLibErrorObj(EFAULT,"No pathname is specified while attempting to open a file");
	
	// Close our open file, if we have one
	Close();
	
	// Open the new file
	fFileDescriptor = OpenWithoutInterrupts(Path().c_str(),flags,mode);
	
	if (FileDescriptor() <= 0)
	{
		std::string		errString;
		
		errString += "While attempting to open file '" + Path() + "'";
		fFileDescriptor = kInvalidFD;
		throw TSymLibErrorObj(errno,errString);
	}
	
	fOpenFlags = flags;
	fOpenMode = mode;
	
	ResetEOF();
}

//---------------------------------------------------------------------
// TFileObj::Open
//---------------------------------------------------------------------
void TFileObj::Open (const std::string& path, OS_Flags flags)
{
	// Close our open file, if we have one
	Close();
	
	// Set our path
	SetPath(path);
	
	// Call one of our other Open() methods
	Open(flags);
}

//---------------------------------------------------------------------
// TFileObj::Open
//---------------------------------------------------------------------
void TFileObj::Open (const std::string& path, OS_Flags flags, OS_Mode mode)
{
	// Close our open file, if we have one
	Close();
	
	// Set our path
	SetPath(path);
	
	// Call one of our other Open() methods
	Open(flags,mode);
}

//---------------------------------------------------------------------
// TFileObj::Close
//---------------------------------------------------------------------
void TFileObj::Close (bool throwOnError)
{
	if (IsOpen())
	{
		while (close(FileDescriptor()) < 0)
		{
			if (errno != EINTR)
			{
				if (throwOnError)
				{
					std::string		errString;
					
					errString += "While attempting to close file descriptor " + FileDescriptor();
					throw TSymLibErrorObj(errno,errString);
				}
				else
					break;
			}
		}
		
		fFileDescriptor = kInvalidFD;
		fOpenFlags = 0;
		fOpenMode = 0;
		ResetEOF();
	}
}

//---------------------------------------------------------------------
// TFileObj::Exists
//---------------------------------------------------------------------
bool TFileObj::Exists (bool followSymLinks) const
{
	bool	exists = false;
	
	if (IsOpen())
		exists = true;
	else
		exists = (access(Path().c_str(),F_OK) == 0);
	
	return exists;
}

//---------------------------------------------------------------------
// TFileObj::Delete
//---------------------------------------------------------------------
void TFileObj::Delete (bool throwOnError)
{
	if (Path().empty())
	{
		if (throwOnError)
			throw TSymLibErrorObj(EFAULT,"No pathname is specified while attempting to delete a file");
	}
	else
	{
		// Make sure our current file is closed
		Close(throwOnError);
		
		if (unlink(Path().c_str()) != 0 && throwOnError)
		{
			std::string		errString;
			
			errString += "While attempting to delete file '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
}

//---------------------------------------------------------------------
// TFileObj::StatInfo
//---------------------------------------------------------------------
void TFileObj::StatInfo (struct stat& statInfo, bool followSymLinks) const
{
	if (IsOpen())
	{
		if (fstat(FileDescriptor(),&statInfo) != 0)
		{
			std::string		errString;
			
			errString += "While attempting to get stat info for '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
	else
	{
		Inherited::StatInfo(statInfo,followSymLinks);
	}
}

//---------------------------------------------------------------------
// TFileObj::SetPermissions
//---------------------------------------------------------------------
void TFileObj::SetPermissions (OS_Mode newMode) const
{
	
	if (IsOpen())
	{
		if (fchmod(FileDescriptor(),newMode) != 0)
		{
			std::string		errString;
			
			errString += "While attempting to change access permissions for '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
	else
	{
		Inherited::SetPermissions(newMode);
	}
}

//---------------------------------------------------------------------
// TFileObj::SetOwner
//---------------------------------------------------------------------
void TFileObj::SetOwner (uid_t ownerID, bool followSymLinks) const
{
	if (IsOpen())
	{
		if (fchown(FileDescriptor(),ownerID,static_cast<gid_t>(-1)) != 0)
		{
			std::string		errString;
			
			errString += "While attempting to change the owner for '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
	else
	{
		Inherited::SetOwner(ownerID,followSymLinks);
	}
}

//---------------------------------------------------------------------
// TFileObj::SetGroup
//---------------------------------------------------------------------
void TFileObj::SetGroup (gid_t groupID, bool followSymLinks) const
{
	if (IsOpen())
	{
		if (fchown(FileDescriptor(),static_cast<uid_t>(-1),groupID) != 0)
		{
			std::string		errString;
			
			errString += "While attempting to change the owning group for '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
	else
	{
		Inherited::SetGroup(groupID,followSymLinks);
	}
}

//---------------------------------------------------------------------
// TFileObj::Size
//---------------------------------------------------------------------
unsigned long TFileObj::Size (bool followSymLinks) const
{
	struct stat			statInfo;
	
	StatInfo(statInfo,followSymLinks);
	
	return statInfo.st_size;
}

//---------------------------------------------------------------------
// TFileObj::GetFilePosition
//---------------------------------------------------------------------
unsigned long TFileObj::GetFilePosition () const
{
	return SetFilePosition(0,SEEK_CUR);
}

//---------------------------------------------------------------------
// TFileObj::SetFilePosition
//---------------------------------------------------------------------
unsigned long TFileObj::SetFilePosition (long position, OS_Position fromWhere) const
{
	off_t		newAbsolutePos = lseek(FileDescriptor(),position,fromWhere);
	
	if (newAbsolutePos == -1)
	{
		std::string		errString;
		
		errString += "While attempting to get/set the file position within '" + Path() + "'";
		throw TSymLibErrorObj(errno,errString);
	}
	
	return static_cast<unsigned long>(newAbsolutePos);
}

//---------------------------------------------------------------------
// TFileObj::Truncate
//---------------------------------------------------------------------
void TFileObj::Truncate (unsigned long newFileSize) const
{
	if (IsOpen())
	{
		unsigned long	currentPos = GetFilePosition();
		
		if (ftruncate(FileDescriptor(),newFileSize) != 0)
		{
			std::string		errString;
			
			errString += "While attempting to truncate file '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
		
		if (currentPos > newFileSize)
			SetFilePosition(newFileSize);
	}
	else
	{
		if (Path().empty())
			throw TSymLibErrorObj(EFAULT,"No pathname is specified while attempting to truncate a file");
		
		if (truncate(Path().c_str(),newFileSize) != 0)
		{
			std::string		errString;
			
			errString += "While attempting to truncate file '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
}

//---------------------------------------------------------------------
// TFileObj::Read
//---------------------------------------------------------------------
void TFileObj::Read (std::string& bufferObj, unsigned long length, bool exclusiveAccess)
{
	ssize_t								bytesRead = 0;
	unsigned long						totalBytesRead = 0;
	std::auto_ptr<TExclusiveFileLock>	fileLockObjPtr(NULL);
	
	if (!IsOpen())
	{
		std::string		errString;
		
		if (Path().empty())
			errString += "File cannot be read because it is not open";
		else
			errString += "File '" + Path() + "' cannot be read because it is not open";
		throw TSymLibErrorObj(EBADF,errString);
	}
	
	if (exclusiveAccess)
	{
		// Obtain an exclusive lock on the file
		fileLockObjPtr.reset(new TExclusiveFileLock(FileDescriptor()));
	}
	
	// Reset our EOF indicator
	ResetEOF();
	
	do
	{
		std::string		interimBuffer;
		char*			buffStartPtr = NULL;
		
		interimBuffer.resize(kReadWriteBlockSize);
		buffStartPtr = const_cast<char*>(interimBuffer.data());
		bytesRead = read(FileDescriptor(),buffStartPtr,std::min(kReadWriteBlockSize,length-totalBytesRead));
		if (bytesRead < 0)
		{
			std::string		errString;
			
			errString += "While attempting to read from file '" + Path() + "' with file descriptor ";
			errString += NumToString(FileDescriptor());
			throw TSymLibErrorObj(errno,errString);
		}
		else if (bytesRead > 0)
		{
			bufferObj.append(interimBuffer,0,bytesRead);
			totalBytesRead += bytesRead;
		}
		else
		{
			// End of file
			SetEOF();
		}
	}
	while (!IsEOF() && totalBytesRead < length);
}

//---------------------------------------------------------------------
// TFileObj::Write
//---------------------------------------------------------------------
void TFileObj::Write (const std::string& bufferObj,
					  unsigned long bufferOffset,
					  unsigned long segmentLength,
					  bool exclusiveAccess)
{
	if (bufferOffset < bufferObj.length())
	{
		unsigned long						bytesToWrite = 0;
		ssize_t								bytesWritten = 0;
		unsigned long						totalBytesWritten = 0;
		std::auto_ptr<TExclusiveFileLock>	fileLockObjPtr(NULL);
		
		if (!IsOpen())
		{
			std::string		errString;
			
			if (Path().empty())
				errString += "Cannot write to file because it is not open";
			else
				errString += "Cannot write to file '" + Path() + "' because it is not open";
			throw TSymLibErrorObj(EBADF,errString);
		}
		
		if (exclusiveAccess)
		{
			// Obtain an exclusive lock on the file
			fileLockObjPtr.reset(new TExclusiveFileLock(FileDescriptor()));
		}
		
		// If the default segment length was given then compute it
		if (segmentLength == 0)
			segmentLength = bufferObj.length()-bufferOffset;
		
		// Determine the number of bytes we need to write
		bytesToWrite = std::min(bufferObj.length()-bufferOffset,segmentLength);
		
		while (totalBytesWritten < bytesToWrite)
		{
			bytesWritten = write(FileDescriptor(),bufferObj.data()+bufferOffset+totalBytesWritten,std::min(kReadWriteBlockSize,bytesToWrite - totalBytesWritten));
			if (bytesWritten < 0)
			{
				if (errno == EAGAIN)
				{
					// Non-blocking I/O, and something prevented us from writing
					// immediately.  Just ignore it and try again.
				}
				else
				{
					std::string		errString;
					
					errString += "While attempting to write to file '" + Path() + "'";
					throw TSymLibErrorObj(errno,errString);
				}
			}
			else if (bytesWritten > 0)
			{
				totalBytesWritten += bytesWritten;
			}
		}
		
		ResetEOF();
	}
}

//---------------------------------------------------------------------
// TFileObj::ReadWholeFile
//---------------------------------------------------------------------
void TFileObj::ReadWholeFile (std::string& bufferObj, bool exclusiveAccess)
{
	std::auto_ptr<TExclusiveFileLock>	fileLockObjPtr(NULL);
	bool								wasOpen = IsOpen();
	
	if (!wasOpen)
	{
		// Open the file in read-only mode
		Open(O_RDONLY);
	}
	
	if (!IsOpen())
	{
		std::string		errString;
		
		if (Path().empty())
			errString += "File cannot be read because it is not open";
		else
			errString += "File '" + Path() + "' cannot be read because it is not open";
		throw TSymLibErrorObj(EBADF,errString);
	}
	
	// Zero out the buffer argument
	bufferObj = "";
	
	if (exclusiveAccess)
	{
		// Obtain an exclusive lock on the file
		fileLockObjPtr.reset(new TExclusiveFileLock(FileDescriptor()));
	}
	
	// Make sure we're reading from the beginning
	SetFilePosition(0);
	
	Read(bufferObj,Size(),false);
	
	if (!wasOpen)
	{
		// The file wasn't open before, so close it now
		Close();
	}
}

//---------------------------------------------------------------------
// TFileObj::ReadWholeFile
//---------------------------------------------------------------------
void TFileObj::ReadWholeFile (StdStringList& stringList, char lineDelimiter, bool exclusiveAccess)
{
	std::auto_ptr<TExclusiveFileLock>	fileLockObjPtr(NULL);
	bool								wasOpen = IsOpen();
	std::string							oneLine;
	std::string							delimString;
	
	delimString += lineDelimiter;
	
	if (!wasOpen)
	{
		// Open the file in read-only mode
		Open(O_RDONLY);
	}
	
	if (!IsOpen())
	{
		std::string		errString;
		
		if (Path().empty())
			errString += "File cannot be read because it is not open";
		else
			errString += "File '" + Path() + "' cannot be read because it is not open";
		throw TSymLibErrorObj(EBADF,errString);
	}
	
	// Zero out the string list
	stringList.clear();
	
	if (exclusiveAccess)
	{
		// Obtain an exclusive lock on the file
		fileLockObjPtr.reset(new TExclusiveFileLock(FileDescriptor()));
	}
	
	// Make sure we're reading from the beginning
	SetFilePosition(0);
	
	while (!IsEOF())
	{
		oneLine = "";
		
		ReadUpToDelimiter(oneLine,delimString);
		
		if (!oneLine.empty() && oneLine[oneLine.length()-1] == lineDelimiter)
			oneLine.resize(oneLine.length() - sizeof(lineDelimiter));
		
		stringList.push_back(oneLine);
	}
	
	if (!wasOpen)
	{
		// The file wasn't open before, so close it now
		Close();
	}
}

//---------------------------------------------------------------------
// TFileObj::WriteWholeFile
//---------------------------------------------------------------------
void TFileObj::WriteWholeFile (const std::string& bufferObj, OS_Mode createPerms, bool exclusiveAccess)
{
	std::auto_ptr<TExclusiveFileLock>		fileLockObjPtr(NULL);
	
	if (IsOpen())
	{
		if (exclusiveAccess)
		{
			// Obtain an exclusive lock on the file
			fileLockObjPtr.reset(new TExclusiveFileLock(FileDescriptor()));
		}
		
		// Truncate the file
		Truncate(0);
	}
	else
	{
		// Open the file, truncating/deleting anything already present
		Open((O_WRONLY|O_CREAT|O_TRUNC),createPerms);
		
		if (exclusiveAccess)
		{
			// Obtain an exclusive lock on the file
			fileLockObjPtr.reset(new TExclusiveFileLock(FileDescriptor()));
		}
	}
	
	Write(bufferObj,0,bufferObj.length(),false);
}

//---------------------------------------------------------------------
// TFileObj::ReadUpToDelimiter
//---------------------------------------------------------------------
void TFileObj::ReadUpToDelimiter (std::string& bufferObj, const std::string& delim, bool exclusiveAccess)
{
	char								aChar;
	ssize_t								bytesRead = 0;
	unsigned long						totalBytesRead = 0;
	unsigned long						delimSize = delim.length();
	bool								doRead = true;
	std::auto_ptr<TExclusiveFileLock>	fileLockObjPtr(NULL);
	
	if (!IsOpen())
	{
		std::string		errString;
		
		if (Path().empty())
			errString += "File cannot be read because it is not open";
		else
			errString += "File '" + Path() + "' cannot be read because it is not open";
		throw TSymLibErrorObj(EBADF,errString);
	}
	
	if (exclusiveAccess)
	{
		// Obtain an exclusive lock on the file
		fileLockObjPtr.reset(new TExclusiveFileLock(FileDescriptor()));
	}
	
	// Reset our EOF indicator
	ResetEOF();
	
	while (doRead)
	{
		bytesRead = read(FileDescriptor(),&aChar,1);
		if (bytesRead < 0)
		{
			std::string		errString;
			
			errString += "While attempting to read from file '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
		else if (bytesRead > 0)
		{
			bufferObj += aChar;
			++totalBytesRead;
			
			// Determine if we've read the delimiter
			if (totalBytesRead >= delimSize)
			{
				if (memcmp(bufferObj.data()+totalBytesRead-delimSize,delim.data(),delimSize) == 0)
				{
					// Found it!
					doRead = false;
				}
			}
		}
		else
		{
			// End of file
			doRead = false;
			SetEOF();
		}
	}
}

//---------------------------------------------------------------------
// TFileObj::Append
//---------------------------------------------------------------------
void TFileObj::Append (const std::string& bufferObj, OS_Mode createPerms, bool exclusiveAccess)
{
	std::auto_ptr<TExclusiveFileLock>		fileLockObjPtr(NULL);
	
	if (!IsOpen())
	{
		// Open the file in write mode, optionally creating it.
		Open((O_WRONLY|O_CREAT|O_APPEND),createPerms);
	}
	
	if (exclusiveAccess)
	{
		// Obtain an exclusive lock on the file
		fileLockObjPtr.reset(new TExclusiveFileLock(FileDescriptor()));
	}
	
	if ((fOpenFlags & O_APPEND) == 0)
	{
		// We're not in append mode, so make sure we're located at the end
		SetFilePosition(0,SEEK_END);
	}
	
	Write(bufferObj,0,bufferObj.length(),false);
}

//---------------------------------------------------------------------
// TFileObj::Execute
//---------------------------------------------------------------------
std::string TFileObj::Execute (const unsigned char* appData, size_t appDataLength)
{
	#if HAVE_WORKING_FORK
		StdStringList		emptyArgList;
		
		return Execute(emptyArgList,appData,appDataLength);
	#else
		return std::string();
	#endif
}

//---------------------------------------------------------------------
// TFileObj::Execute
//---------------------------------------------------------------------
std::string TFileObj::Execute (const StdStringList& args, const unsigned char* appData, size_t appDataLength)
{
	#if HAVE_WORKING_FORK
		std::string		command;
		
		if (Path().empty())
			throw TSymLibErrorObj(EFAULT,"No pathname is specified while attempting to execute a file");
		
		if (!Exists())
		{
			std::string		errString;
			
			errString += "File '" + Path() + "' does not exist to execute";
			throw TSymLibErrorObj(ENOENT,errString);
		}
		
		// Build the command to execute
		command += Path();
		for (StdStringList_const_iter x = args.begin(); x != args.end(); x++)
		{
			command += " ";
			
			// Wrap the argument in quotes if it contains a space
			if (x->find(' ') >= 0)
				command += "\"" + *x + "\"";
			else
				command += *x;
		}
		
		return ExecWithIO(command,appData,appDataLength);
	#else
		return std::string();
	#endif
}

//---------------------------------------------------------------------
// TFileObj::Rotate
//---------------------------------------------------------------------
void TFileObj::Rotate (unsigned int maxVersionNum)
{
	if (Exists())
	{
		bool					wasOpen = IsOpen();
		OS_Flags				savedOpenFlags(fOpenFlags);
		mode_t					savedOpenMode(fOpenMode);
		uid_t					savedOwnerID(OwnerID());
		gid_t					savedGroupID(GroupID());
		OS_Mode					savedPerms(Permissions());
		std::string				dirPath(DirectoryPath());
		std::string				leafName(FileName());
		std::string				tempFilePath;
		TFileObj				tempFileObj;
		
		if (wasOpen)
		{
			// Close the file
			Close();
		}
		
		// Delete last file in the backup chain, if it exists
		tempFilePath = dirPath + leafName + "." + NumToString(maxVersionNum);
		tempFileObj.SetPath(tempFilePath);
		tempFileObj.Delete(false);
		
		// Rename files, in order
		for (unsigned int x = maxVersionNum; x > 0; x--)
		{
			tempFilePath = dirPath + leafName;
			if (x > 1)
				tempFilePath += "." + NumToString(x-1);
			tempFileObj.SetPath(tempFilePath);
			if (tempFileObj.Exists())
			{
				std::string		newPath;
				
				newPath = dirPath + leafName + "." + NumToString(x);
				tempFileObj.Rename(newPath);
			}
		}
		
		// Create a new file to replace the one we had
		Create(savedPerms,false);
		SetGroup(savedGroupID);
		SetOwner(savedOwnerID);
		
		if (wasOpen)
		{
			// Our file was open before, so open a new one
			Open(savedOpenFlags,savedOpenMode);
		}
	}
}

//*********************************************************************
// Class TLogFileObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TLogFileObj::TLogFileObj ()
	:	fMaxFileSize(0)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TLogFileObj::TLogFileObj (const std::string& path)
	:	Inherited(path),
		fMaxFileSize(0)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TLogFileObj::TLogFileObj (const TLogFileObj& obj)
	:	Inherited(obj),
		fMaxFileSize(0)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TLogFileObj::~TLogFileObj ()
{
}

//---------------------------------------------------------------------
// TLogFileObj::Open
//---------------------------------------------------------------------
void TLogFileObj::Open (OS_Flags flags)
{
	OS_Mode		defaultMode = (S_IRUSR | S_IWUSR);
	
	// Make sure that certain flags are set
	flags = EnsureRestrictedFlags(flags);
	
	// Now call our parent to actually do this
	Inherited::Open(flags,defaultMode);
}

//---------------------------------------------------------------------
// TLogFileObj::Open
//---------------------------------------------------------------------
void TLogFileObj::Open (OS_Flags flags, OS_Mode mode)
{
	// Make sure that certain flags are set
	flags = EnsureRestrictedFlags(flags);
	
	// Now call our parent to actually do this
	Inherited::Open(flags,mode);
}

//---------------------------------------------------------------------
// TLogFileObj::Open
//---------------------------------------------------------------------
void TLogFileObj::Open (const std::string& path, OS_Flags flags)
{
	OS_Mode		defaultMode = (S_IRUSR | S_IWUSR);
	
	// Make sure that certain flags are set
	flags = EnsureRestrictedFlags(flags);
	
	// Now call our parent to actually do this
	Inherited::Open(path,flags,defaultMode);
}

//---------------------------------------------------------------------
// TLogFileObj::Open
//---------------------------------------------------------------------
void TLogFileObj::Open (const std::string& path, OS_Flags flags, OS_Mode mode)
{
	// Make sure that certain flags are set
	flags = EnsureRestrictedFlags(flags);
	
	// Now call our parent to actually do this
	Inherited::Open(path,flags,mode);
}

//---------------------------------------------------------------------
// TLogFileObj::WriteEntry
//---------------------------------------------------------------------
void TLogFileObj::WriteEntry (const std::string& logEntry, bool throwOnError, bool exclusiveAccess)
{
	std::string		entry;
	std::string		timeHMS;
	std::string		date;
	OS_Mode			kDefaultMode = (S_IRUSR | S_IWUSR);
	const char*		kNewLine = "\n";
	const char*		kDelim = "\t";
	TTimeObj		timeObj;
	
	try
	{
		// Get current date/time
		timeObj.SetDateTime();
		
		// Create the actual entry
		entry += timeObj.GetFormattedDateTime("%Y-%m-%d");		// Current date
		entry += kDelim;
		entry += timeObj.GetFormattedDateTime("%H:%M:%S");		// Current time
		entry += kDelim;
		entry += "[";
		entry += NumToString(getpid());
		
		// Insert thread-aware information if we have it
		if (gEnvironObjPtr)
		{
			TPthreadObj*		threadObjPtr = MyThreadObjPtr();
			
			if (threadObjPtr && threadObjPtr->InternalID() != 0)
			{
				if (gEnvironObjPtr->AppPID() != getpid())
				{
					entry += " (" + NumToString(gEnvironObjPtr->AppPID());
					if (threadObjPtr)
						entry += ":" + NumToString(threadObjPtr->InternalID());
					entry += ")";
				}
				else
				{
					entry += ":" + NumToString(threadObjPtr->InternalID());
				}
			}
		}
		
		entry += "]";
		entry += kDelim;
		entry += logEntry;										// Given log entry
		
		// Add a final linefeed
		entry += kNewLine;
		
		if (Path().empty())
			throw TSymLibErrorObj(EFAULT,"No pathname is specified while attempting to write to a log file");
		
		if (fMaxFileSize > 0 && Exists() && Size() >= fMaxFileSize)
		{
			// Rotate files
			Rotate();
		}
		
		// Make sure we're open
		if (!IsOpen())
			Inherited::Open((O_WRONLY|O_CREAT|O_APPEND),kDefaultMode);
		
		// Write entry to logfile
		Inherited::Append(entry,kDefaultMode,exclusiveAccess);
	}
	catch (...)
	{
		if (throwOnError)
			throw;
	}
}

//---------------------------------------------------------------------
// TLogFileObj::EnsureRestrictedFlags (protected)
//---------------------------------------------------------------------
OS_Flags TLogFileObj::EnsureRestrictedFlags (OS_Flags flags)
{
	OS_Flags	notFlags = (O_RDONLY | O_RDWR);
	
	// Make sure that certain flags are not set
	flags &= ~notFlags;
	
	// Make sure that certain flags are set
	flags |= kRequiredOSFlags;
	
	return flags;
}

//*********************************************************************
// Class TDirObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TDirObj::TDirObj ()
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TDirObj::TDirObj (const std::string& path)
	:	Inherited(path)
{
	if (fPath.empty() || (fPath[fPath.length()-1] != kPathDelimiterAsChar))
		fPath += kPathDelimiterAsChar;
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TDirObj::TDirObj (const TDirObj& obj)
	:	Inherited(obj)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TDirObj::~TDirObj ()
{
}

//---------------------------------------------------------------------
// TDirObj::SetPath
//---------------------------------------------------------------------
void TDirObj::SetPath (const std::string& newPath)
{
	Inherited::SetPath(newPath);
	if (fPath.empty() || (fPath[fPath.length()-1] != kPathDelimiterAsChar))
		fPath += kPathDelimiterAsChar;
}

//---------------------------------------------------------------------
// TDirObj::Create
//---------------------------------------------------------------------
void TDirObj::Create (OS_Mode mode)
{
	if (Path().empty())
		throw TSymLibErrorObj(EFAULT,"No pathname is specified while attempting to create a directory");
		
	// Now create the directory
	if (mkdir(Path().c_str(),mode) != 0)
	{
		std::string		errString;
		
		errString += "While attempting to create directory '" + Path() + "'";
		throw TSymLibErrorObj(errno,errString);
	}
}

//---------------------------------------------------------------------
// TDirObj::Create
//---------------------------------------------------------------------
void TDirObj::Create (const std::string& path, OS_Mode mode)
{
	SetPath(path);
	
	Create(mode);
}

//---------------------------------------------------------------------
// TDirObj::HeirarchicalCreate
//---------------------------------------------------------------------
void TDirObj::HeirarchicalCreate (const std::string& path,
								  OS_Mode mode,
								  uid_t ownerID,
								  gid_t groupID)
{
	std::string		fullPath;
	StdStringList	pathComponents;
	TDirObj			tempDirObj;
	
	if (path.empty())
		throw TSymLibErrorObj(EFAULT,"No pathname is specified while attempting to create a directory");
	
	// Generate our beginning path
	if (!path.empty() && path[0] == kPathDelimiterAsChar)
		fullPath = kPathDelimiterAsString;
	else
		fullPath = GetCurrentDirectory();
	
	// Split the given path into discreet names
	SplitStdString(kPathDelimiterAsChar,path,pathComponents,false);
	
	for (StdStringList_const_iter x = pathComponents.begin(); x != pathComponents.end(); x++)
	{
		fullPath += *x + kPathDelimiterAsString;
		tempDirObj.SetPath(fullPath);
		if (!tempDirObj.Exists())
		{
			// Directory is missing; create it
			tempDirObj.Create(mode);
			
			// Set the owner and group if necessary
			if (ownerID != static_cast<uid_t>(-1))
				tempDirObj.SetOwner(ownerID);
			if (groupID != static_cast<gid_t>(-1))
				tempDirObj.SetGroup(groupID);
		}
	}
	
	// Set our internal path to whatever was passed in
	SetPath(path);
}

//---------------------------------------------------------------------
// TDirObj::HeirarchicalCreate
//---------------------------------------------------------------------
void TDirObj::HeirarchicalCreate (const std::string& path,
								  OS_Mode mode,
								  std::string ownerName,
								  std::string groupName)
{
	uid_t		ownerID = static_cast<uid_t>(-1);
	gid_t		groupID = static_cast<gid_t>(-1);
	
	if (!ownerName.empty())
	{
		ownerID = MapUserNameToUID(ownerName.c_str());
		
		if (ownerID == static_cast<uid_t>(-1))
		{
			std::string		errString;
			
			errString += "User '" + ownerName + "' not found while attempting to set owner for '" + Path() + "'";
			throw TSymLibErrorObj(ENXIO,errString);
		}
	}
	
	if (!groupName.empty())
	{
		groupID = MapGroupNameToGID(groupName.c_str());
		
		if (groupID == static_cast<gid_t>(-1))
		{
			std::string		errString;
			
			errString += "Group '" + groupName + "' not found while attempting to set owning group for '" + Path() + "'";
			throw TSymLibErrorObj(ENXIO,errString);
		}
	}
	
	HeirarchicalCreate(path,mode,ownerID,groupID);
}

//---------------------------------------------------------------------
// TDirObj::HeirarchicalCreate
//---------------------------------------------------------------------
void TDirObj::HeirarchicalCreate (const std::string& path, OS_Mode mode)
{
	HeirarchicalCreate(path,mode,static_cast<uid_t>(-1),static_cast<gid_t>(-1));
}

//---------------------------------------------------------------------
// TDirObj::Delete
//---------------------------------------------------------------------
void TDirObj::Delete (bool throwOnError)
{
	if (Path().empty())
	{
		if (throwOnError)
			throw TSymLibErrorObj(EFAULT,"No pathname is specified while attempting to delete a directory");
	}
	else
	{
		if (rmdir(Path().c_str()) != 0 && throwOnError)
		{
			std::string		errString;
			
			errString += "While attempting to delete directory '" + Path() + "'";
			throw TSymLibErrorObj(errno,errString);
		}
	}
}

//*********************************************************************
// Global Functions
//*********************************************************************

//---------------------------------------------------------------------
// ReadWholeFile
//---------------------------------------------------------------------
void ReadWholeFile (const std::string& path, std::string& bufferObj, bool exclusiveAccess)
{
	TFileObj		fileObj(path);
	
	fileObj.Open();
	fileObj.ReadWholeFile(bufferObj,exclusiveAccess);
	fileObj.Close();
}

//---------------------------------------------------------------------
// WriteWholeFile
//---------------------------------------------------------------------
void WriteWholeFile (const std::string& path, const std::string& bufferObj, OS_Mode createPerms, bool exclusiveAccess)
{
	TFileObj		fileObj(path);
	
	fileObj.WriteWholeFile(bufferObj,createPerms,exclusiveAccess);
}

//---------------------------------------------------------------------
// ReadSymbolicLink
//---------------------------------------------------------------------
std::string ReadSymbolicLink (const std::string& path)
{
	std::string			linkPath;
	
	linkPath.resize(256);
	
	if (TFileObj(path).Exists(false))
	{
		std::string		bufferObj;
		int				bufferChars = 0;
		bool			keepLooking = true;
		
		while (keepLooking)
		{
			bufferChars = readlink(path.c_str(),const_cast<char*>(linkPath.data()),linkPath.capacity()-1);
			if (bufferChars == -1)
			{
				// We had an error of some kind
				if (errno == ENAMETOOLONG)
				{
					// Our buffer is too small
					linkPath.resize(linkPath.capacity() * 2);
				}
				else
				{
					// Unknown error
					throw TSymLibErrorObj(errno);
				}
			}
			else
			{
				keepLooking = false;
			}
		}
		
		// The system call inserted a NULL terminating character, but the string
		// object doesn't know about it.  Tell the object how long the string really is.
		linkPath.resize(strlen(linkPath.c_str()));
	}
	
	return linkPath;
}

//---------------------------------------------------------------------
// WriteLogEntryToFile
//---------------------------------------------------------------------
void WriteLogEntryToFile (const std::string& fullPath, const std::string& logEntry, bool throwOnError)
{
	TLogFileObj(fullPath).WriteEntry(logEntry,throwOnError,true);
}

//---------------------------------------------------------------------
// MakeLogPath
//---------------------------------------------------------------------
std::string MakeLogPath (const std::string& pathPrefix)
{
	std::string 		fullPath;
	TTimeObj		timeObj;
	
	// Get current date/time
	timeObj.SetDateTime();
	
	// Create path in the format pathPrefix_YYYY_MM
	fullPath += pathPrefix;
	fullPath += "_" + timeObj.GetFormattedDateTime("%Y_%m");
	
	return fullPath;
}

//---------------------------------------------------------------------
// ExecWithIO
//---------------------------------------------------------------------
std::string ExecWithIO (const std::string& appCommand, const unsigned char* appData, size_t appDataLength)
{
	std::string		output;
	
	#if HAVE_WORKING_FORK
		int					ioPipe[2];
		int					forkResult;
		const int			kInput = 0;
		const int			kOutput = 1;
		struct sigaction	mySigAction;
		struct sigaction	oldSigAction;
		
		if (BitTest(gEnvironObjPtr->DynamicDebugFlags(),kDynDebugLogServerCommunication))
		{
			std::string		logString;
			
			logString = "Beginning execution of system command: " + appCommand;
			WriteToMessagesLogFile(logString);
		}
		
		// We don't want to get a signal when our child process stops
		mySigAction.sa_handler = SIG_IGN;
		mySigAction.sa_flags = SA_NOCLDSTOP;
		sigemptyset(&mySigAction.sa_mask);
		sigaction(SIGCHLD,&mySigAction,&oldSigAction);
		
		// Create pipes to use for communication
		if (pipe(ioPipe) == 0)
		{
			// Fork
			forkResult = fork();
			if (forkResult == 0)
			{
				// Child process
				FILE*			appPipe = NULL;
				sigset_t		signalSet;
				
				sigprocmask(SIG_SETMASK,NULL,&signalSet);
				sigaddset(&signalSet,SIGPIPE);
				sigprocmask(SIG_SETMASK,&signalSet,NULL);
				
				pthread_sigmask(SIG_SETMASK,NULL,&signalSet);
				sigaddset(&signalSet,SIGPIPE);
				pthread_sigmask(SIG_SETMASK,&signalSet,NULL);
				
				errno = 0;
				dup2(ioPipe[kOutput],fileno(stdout));
				// setvbuf(stdout,NULL,_IONBF,BUFSIZ);
				close(ioPipe[kInput]);
				
				try
				{
					fflush(NULL);
					appPipe = popen(appCommand.c_str(),"w");
					if (appPipe)
					{
						if (appData && appDataLength > 0)
						{
							for (size_t x = 0; x < appDataLength; x++)
								fprintf(appPipe,"%c",appData[x]);
						}
						pclose(appPipe);
					}
				}
				catch (...)
				{
					// Do nothing here, since we're just about to exit anyway
				}
				
				// Stop the child process
				exit(0);
			}
			else if (forkResult > 0)
			{
				// Parent process
				char			oneChar;
				int				oldFlags = fcntl(ioPipe[kInput],F_GETFL);
				
				{
					TKillProcess	killProc(forkResult);
					
					fcntl(ioPipe[kInput],F_SETFL,oldFlags|O_NONBLOCK);
					
					if (BitTest(gEnvironObjPtr->DynamicDebugFlags(),kDynDebugLogServerCommunication))
					{
						std::string		logString;
						
						logString = "Executing system command: '" + appCommand + "' from parent ppid " + NumToString(forkResult);
						WriteToMessagesLogFile(logString);
					}
					
					close(ioPipe[kOutput]);
					
					try
					{
						// Bump the timeout up --ME
						int		expireTime = time(NULL) + 3600;
						
						while (time(NULL) <= expireTime)
						{
							int		bytesRead = read(ioPipe[kInput],&oneChar,sizeof(oneChar));
							
							if (bytesRead == 0)
							{
								// We're done
								break;
							}
							else if (bytesRead > 0)
							{
								output += oneChar;
								expireTime = time(NULL) + 3600;
								// Bump the timeout up --ME
							}
							else
							{
								if (errno == EAGAIN)
								{
									// No data cause we're non-blocking
									Pause(.5);
								}
								else
								{
									// Error condition
									std::string		logString;
									
									logString = "OS error while reading data from external app: " + NumToString(errno);
									WriteToErrorLogFile(logString);
									WriteToMessagesLogFile(logString);
									break;
								}
							}
						}
					}
					catch (...)
					{
						// Do nothing here
					}
					
					close(ioPipe[kInput]);
				}
				
				if (BitTest(gEnvironObjPtr->DynamicDebugFlags(),kDynDebugLogServerCommunication))
				{
					std::string		logString;
					
					logString = "Ending execution of system command: " + appCommand + "; waiting for pid to terminate";
					WriteToMessagesLogFile(logString);
				}
				
				// Make sure the process terminates
				waitpid(forkResult,NULL,0);
			}
			else
			{
				// Cleanup pipes
				close(ioPipe[kInput]);
				close(ioPipe[kOutput]);
			}
		}
		
		if (BitTest(gEnvironObjPtr->DynamicDebugFlags(),kDynDebugLogServerCommunication))
		{
			std::string		logString;
			
			logString = "Ending execution of system command: " + appCommand;
			WriteToMessagesLogFile(logString);
		}
		
		sigaction(SIGCHLD,&oldSigAction,NULL);
		
	#endif
	
	return output;
}

//---------------------------------------------------------------------
// GetCurrentDirectory
//---------------------------------------------------------------------
std::string GetCurrentDirectory ()
{
	std::string		currentDir;
	
	currentDir.resize(256);
	
	while (getcwd(const_cast<char*>(currentDir.data()),currentDir.capacity()-1) == NULL)
	{
		if (errno == ERANGE)
		{
			// Our buffer is too small
			currentDir.resize(currentDir.capacity() * 2);
		}
		else
		{
			// Unknown error
			throw TSymLibErrorObj(errno);
		}
	}
	
	// The system call added a terminating NULL to the end of the string.
	// We have to tell the string object what it's length is.
	currentDir.resize(strlen(currentDir.c_str()));
	
	// Append a final delimiter
	if (currentDir.empty() || currentDir[currentDir.length()-1] != kPathDelimiterAsChar)
		currentDir += kPathDelimiterAsChar;
	
	return currentDir;
}

//---------------------------------------------------------------------
// FindFile
//---------------------------------------------------------------------
std::string FindFile (const std::string& fileName, const StdStringList& dirList)
{
	std::string		foundPath;
	std::string		testPath;
	TFileObj		testFileObj;
	
	for (StdStringList_const_iter x = dirList.begin(); x != dirList.end(); x++)
	{
		testPath = *x;
		if (!testPath.empty() && testPath[testPath.length()-1] != kPathDelimiterAsChar)
			testPath += kPathDelimiterAsString;
		testPath += fileName;
		testFileObj.SetPath(testPath);
		if (testFileObj.Exists())
		{
			foundPath = testFileObj.RealPath();
			break;
		}
	}
	
	return foundPath;
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

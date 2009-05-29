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
#		Last Modified:				28 Jan 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_FILE)
#define SYMLIB_FILE

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-config.h"

#include "symlib-defs.h"
#include "symlib-exception.h"
#include "symlib-time.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <map>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TFSObject;
class TFileObj;
class TLogFileObj;
class TDirObj;
class TExclusiveFileLock;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define		kPathDelimiterAsChar							'/'
#define		kPathDelimiterAsString							"/"

typedef		int												OS_Flags;
typedef		mode_t											OS_Mode;
typedef		int												OS_Position;

typedef		std::vector<TFSObject*>							TFSObjectPtrList;
typedef		TFSObjectPtrList::iterator						TFSObjectPtrList_iter;
typedef		TFSObjectPtrList::const_iterator				TFSObjectPtrList_const_iter;

//---------------------------------------------------------------------
// Class TFSObject
//---------------------------------------------------------------------
class TFSObject
{
	public:
		
		TFSObject ();
			// Constructor
		
		TFSObject (const std::string& path);
			// Constructor
		
		TFSObject (const TFSObject& obj);
			// Copy constructor
		
		virtual ~TFSObject ();
			// Destructor
		
		inline std::string Path () const
			{ return fPath; }
		
		virtual void SetPath (const std::string& newPath);
		
		virtual std::string FileName () const;
			// Returns only the filename portion of the current path.  Directory
			// objects will return their leafname.
		
		virtual std::string DirectoryPath () const;
			// Returns only the directory portion of the current path.
		
		virtual std::string RealPath () const;
			// Resolves any symbolic links in the current path and returns
			// the real, absolute pathname.
		
		virtual void Rename (const std::string& newName);
			// Issues a call to the operating system to change the name/path
			// of the current file system object.
		
		virtual bool Exists (bool followSymLinks = true) const;
			// Returns a boolean indicating whether the file system object cited
			// by the current path exists or not.
		
		virtual void StatInfo (struct stat& statInfo, bool followSymLinks = true) const;
			// Populates the statInfo argument with the stat data for the current
			// file system object.  If followSymLinks is true and the current path
			// points to a symbolic link then the links are resolved and the stat info
			// retrieved will be for the 'real' object.  Otherwise, the stat info
			// for the link itself is returned.
		
		virtual OS_Mode Permissions (bool followSymLinks = true) const;
			// Returns the permissions on the current file system object.
		
		virtual void SetPermissions (OS_Mode newPerms) const;
			// Changes the access permissions on the current file system object.
		
		virtual bool HasPermissions (bool canRead, bool canWrite, bool canExecute, bool allRequired = true) const;
			// Returns a boolean indicating whether the current user has the
			// permissions indicated by the first three arguments on the current
			// file system object.  If allRequired is true then all of the
			// permissions must be allowed for this method to return true; if
			// allRequired is false then the method will return true if any
			// permission is allowed.  Obviously, the semantics for the three
			// canXXX arguments will differ, depending on whether the current
			// object is a file or a directory.
		
		virtual uid_t OwnerID (bool followSymLinks = true) const;
			// Returns the ID of the owner of the current file system object.
		
		virtual std::string OwnerName (bool followSymLinks = true) const;
			// Returns the name of the owner of the current file system object.
		
		virtual void SetOwner (uid_t ownerID, bool followSymLinks = true) const;
			// Sets the owner of the current file system object to the given owner ID.
		
		virtual void SetOwner (const std::string& ownerName, bool followSymLinks = true) const;
			// Sets the owner of the current file system object to the given owner name.
		
		virtual gid_t GroupID (bool followSymLinks = true) const;
			// Returns the ID of the group owning the current file system object.
		
		virtual std::string GroupName (bool followSymLinks = true) const;
			// Returns the name of the group owning the current file system object.
		
		virtual void SetGroup (gid_t groupID, bool followSymLinks = true) const;
			// Sets the owning group of the current file system object to the given group ID.
		
		virtual void SetGroup (const std::string& groupName, bool followSymLinks = true) const;
			// Sets the owning group of the current file system object to the given group name.
		
		virtual TTimeObj LastAccessTime (bool followSymLinks = true) const;
			// Returns a temporary time object denoting the date/time of the
			// last file system object access event.
		
		virtual TTimeObj ModificationTime (bool followSymLinks = true) const;
			// Returns a temporary time object denoting the date/time of the
			// last file system object content change event.
		
		virtual TTimeObj StatModificationTime (bool followSymLinks = true) const;
			// Returns a temporary time object denoting the date/time of the
			// last file system object stat (owner/group/perm change) event.
	
	// Functions that must be overridden in subclasses
	public:
		
		virtual TFSObject* New () const = 0;
		
		virtual TFSObject* New (const TFSObject& obj) const = 0;
		
		virtual bool IsFile () const = 0;
		
		virtual bool IsDir () const = 0;
		
		virtual void Delete (bool throwOnError = true) = 0;
	
	// Casting overloads
	public:
		
		inline operator const char* ()
			{ return fPath.c_str(); }
		
		inline operator const std::string () const
			{ return fPath; }
	
	protected:
		
		std::string											fPath;
};

//---------------------------------------------------------------------
// Class TFileObj
//---------------------------------------------------------------------
class TFileObj : public TFSObject
{
	private:
		
		typedef							TFSObject			Inherited;
		
	protected:
		
		static const int				kInvalidFD;
		static const unsigned long		kReadWriteBlockSize;
		
	public:
		
		TFileObj ();
			// Constructor
		
		TFileObj (const std::string& path);
			// Constructor
		
		TFileObj (const TFileObj& obj);
			// Copy constructor
		
		virtual ~TFileObj ();
			// Destructor
		
		virtual TFileObj* New () const
			{ return new TFileObj; }
		
		virtual TFileObj* New (const TFSObject& obj) const
			{ return new TFileObj(obj); }
		
		virtual bool IsFile () const
			{ return true; }
		
		virtual bool IsDir () const
			{ return false; }
		
		virtual void SetPath (const std::string& newPath);
			// Override to ensure that our file isn't open.
		
		virtual void Create (OS_Mode mode = (S_IRUSR | S_IWUSR), bool overwriteIfExists = false);
			// Creates a new file at the current path, with the given modes.
			// If a file exists at the same location and overwriteIfExists is true
			// then the existing file will be overwritten, otherwise an error
			// is thrown.  If the current object points to a currently-opened
			// file then the file is closed before this function attempts to
			// create a new file.
		
		virtual void Create (const std::string& path, OS_Mode mode = (S_IRUSR | S_IWUSR), bool overwriteIfExists = false);
			// Creates a new file at the given path, with the given modes.
			// If a file exists at the same location and overwriteIfExists is true
			// then the existing file will be overwritten, otherwise an error
			// is thrown.  If the current object points to a currently-opened
			// file then the file is closed before this function attempts to
			// create a new file.
		
		virtual void Open (OS_Flags flags = O_RDONLY);
			// Method opens the current file, using the given flags.  If the current
			// object points to an already-opened file then that file is closed first.
		
		virtual void Open (OS_Flags flags, OS_Mode mode);
			// Method opens the current file, using the given flags and mode.  If the
			// current object points to an already-opened file then that file is closed
			// first.
		
		virtual void Open (const std::string& path, OS_Flags flags = O_RDONLY);
			// Method opens the file cited by the path argument, using the given
			// flags, and the internal state is adjusted to point the just-opened
			// file.  If the current object points to an already-opened file then
			// that file is closed first.
		
		virtual void Open (const std::string& path, OS_Flags flags, OS_Mode mode);
			// Method opens the file cited by the path argument, using the given
			// flags and mode, and the internal state is adjusted to point the
			// just-opened file.  If the current object points to an already-opened
			// file then that file is closed first.
		
		virtual void Close (bool throwOnError = true);
			// Closes the current file.
		
		virtual bool Exists (bool followSymLinks = true) const;
			// Returns a boolean indicating whether the file cited
			// by this object exists or not.
		
		virtual void Delete (bool throwOnError = true);
			// Deletes the current file.
		
		virtual void StatInfo (struct stat& statInfo, bool followSymLinks = true) const;
			// Populates the statInfo argument with the stat data for the current
			// file.  If the file is currently open then followSymLinks is ignored
			// and the information is retrieved using the open file descriptor.
			// Otherwise, followSymLinks is honored while resolving the current
			// path.
		
		virtual void SetPermissions (OS_Mode newMode) const;
			// Changes the access permissions on the current file.
		
		virtual void SetOwner (uid_t ownerID, bool followSymLinks = true) const;
			// Sets the owner of the current file system object to the given owner ID.
		
		virtual void SetOwner (const std::string& ownerName, bool followSymLinks = true) const
			{ Inherited::SetOwner(ownerName,followSymLinks); }
		
		virtual void SetGroup (gid_t groupID, bool followSymLinks = true) const;
			// Sets the owning group of the current file system object to the given group ID.
		
		virtual void SetGroup (const std::string& groupName, bool followSymLinks = true) const
			{ Inherited::SetGroup(groupName,followSymLinks); }
		
		virtual unsigned long Size (bool followSymLinks = true) const;
			// Returns the size of the current file.  If the file is currently open
			// then followSymLinks is ignored and the information is retrieved using
			// the open file descriptor. Otherwise, followSymLinks is honored while
			// resolving the current path.
		
		virtual unsigned long GetFilePosition () const;
			// Returns the current absolute file position within the open file.
		
		virtual unsigned long SetFilePosition (long position, OS_Position fromWhere = SEEK_SET) const;
			// Sets the file position within the file and returns the new absolute
			// position.  The position argument is considered relative from the
			// value of fromWhere argument (start, end, or current file position).
		
		virtual void Truncate (unsigned long newFileSize) const;
			// Truncates the current file to the given size (in bytes).
		
		virtual void Read (std::string& bufferObj, unsigned long length, bool exclusiveAccess = false);
			// Reads length bytes from the current file, beginning at the current file
			// position, and appends the data to the buffer argument.  The contents of
			// the buffer argument are not reset in this call.  If exclusiveAccess is true
			// then an exclusive file lock is obtained on the file before the read begins.
		
		virtual void Write (const std::string& bufferObj,
							unsigned long bufferOffset = 0,
							unsigned long segmentLength = 0,
							bool exclusiveAccess = false);
			// Writes segmentLength bytes from the buffer object, beginning at position
			// bufferOffset, to the file at the current file position.  If exclusiveAccess
			// is true then an exclusive file lock is obtained on the file before the write
			// begins.
		
		virtual void ReadWholeFile (std::string& bufferObj, bool exclusiveAccess = false);
			// Reads the current file into the given buffer.  If exclusiveAccess is true
			// then an exclusive file lock is obtained on the file before the read
			// begins.
		
		virtual void ReadWholeFile (StdStringList& stringList, char lineDelimiter = '\n', bool exclusiveAccess = false);
			// Reads the current file into the stringList argument, one line at a time, with
			// each line delimited by the lineDelimter argument.  If exclusiveAccess is
			// true then an exclusive file lock is obtained on the file before the
			// read begins.  Note that empty lines (lines composed of only the lineDelimiter)
			// are inserted as empty strings.  Also note that the delimiter characters
			// are stripped.
		
		virtual void WriteWholeFile (const std::string& bufferObj,
									 OS_Mode createPerms = (S_IRUSR | S_IWUSR),
									 bool exclusiveAccess = false);
			// Writes the buffer to the current filepath, overwriting anything that's
			// already there.  A new file with the given permissions will be created
			// if necessary.  If this object points to an already-opened file then it
			// will be closed (and therefore flushed) before the write begins.  If
			// exclusiveAccess is true then an exclusive file lock is obtained on the
			// file before the write begins.
		
		virtual void ReadUpToDelimiter (std::string& bufferObj, const std::string& delim, bool exclusiveAccess = false);
			// Reads from the current file up to and including the next occurence of the
			// value of the delim argument, appending the read data to the bufferObj
			// argument.  The contents of the buffer argument are not reset in this call.
			// if exclusiveAccess is true then an exclusive file lock is obtained on the
			// file before the read begins.
		
		virtual void Append (const std::string& bufferObj, OS_Mode createPerms = (S_IRUSR | S_IWUSR), bool exclusiveAccess = false);
			// Appends the given buffer to the current file.  If the file is not already
			// open then it will be opened with append+write access.  If exclusiveAccess
			// is true then an exclusive file lock is obtained on the file before the write
			// begins.
		
		virtual std::string Execute (const unsigned char* appData = NULL, size_t appDataLength = 0);
			// The path cited in the current object is executed as a new process.  If
			// appData is provided then it is piped to the new process (where it can be
			// collected from STDIN).  The process' output is collected and returned
			// by this method as a temporary string.
		
		virtual std::string Execute (const StdStringList& args, const unsigned char* appData = NULL, size_t appDataLength = 0);
			// Same as previous version of Execute() except you can specify a list of
			// arguments to supply to the process.
		
		virtual void Rotate (unsigned int maxVersionNum = 4);
			// Creates backups of the current file.  Backups are named <filename>.nnn where
			// nnn is between 1 and maxVersionNum, inclusive.  Existing backups will be
			// copied to the next-higher numeric suffix, the current file's contents
			// will be copied to <filename>.1, then the current file will be truncated.
	
	// Public Accessors
	public:
		
		inline const int FileDescriptor () const
			{ return fFileDescriptor; }
		
		inline bool IsOpen () const
			{ return fFileDescriptor != kInvalidFD; }
		
		inline bool IsEOF () const
			{ return fEOF; }
	
	// Protected Accessors
	protected:
		
		inline void ResetEOF ()
			{ fEOF = false; }
		
		inline void SetEOF ()
			{ fEOF = true; }
	
	// Casting overloads
	public:
		
		inline operator const int () const
			{ return fFileDescriptor; }
	
	protected:
		
		int												fFileDescriptor;
		bool											fEOF;
		OS_Flags										fOpenFlags;
		mode_t											fOpenMode;
};

//---------------------------------------------------------------------
// Class TLogFileObj
//---------------------------------------------------------------------
class TLogFileObj : public TFileObj
{
	private:
		
		typedef							TFileObj			Inherited;
	
	protected:
		
		static const	OS_Flags		kRequiredOSFlags;
		
	public:
		
		TLogFileObj ();
			// Constructor
		
		TLogFileObj (const std::string& path);
			// Constructor
		
		TLogFileObj (const TLogFileObj& obj);
			// Copy constructor
		
		virtual ~TLogFileObj ();
			// Destructor
		
		virtual TLogFileObj* New () const
			{ return new TLogFileObj; }
		
		virtual TLogFileObj* New (const TLogFileObj& obj) const
			{ return new TLogFileObj(obj); }
		
		virtual void Open (OS_Flags flags = kRequiredOSFlags);
			// Override to ensure that the file is opened correctly for a log
			// file.
		
		virtual void Open (OS_Flags flags, OS_Mode mode);
			// Override to ensure that the file is opened correctly for a log
			// file.
		
		virtual void Open (const std::string& path, OS_Flags flags = kRequiredOSFlags);
			// Override to ensure that the file is opened correctly for a log
			// file.
		
		virtual void Open (const std::string& path, OS_Flags flags, OS_Mode mode);
			// Override to ensure that the file is opened correctly for a log
			// file.
		
		virtual void WriteEntry (const std::string& logEntry, bool throwOnError = true, bool exclusiveAccess = true);
			// Writes the given logEntry to the current file, inserting the current
			// date, time and process ID number.  If throwOnError is false then
			// all exceptions will be silently caught by this method.
		
		inline unsigned long MaxFileSize () const
			{ return fMaxFileSize; }
		
		inline void SetMaxFileSize (unsigned long maxFileSize)
			{ fMaxFileSize = maxFileSize; }
			
	
	protected:
		
		virtual OS_Flags EnsureRestrictedFlags (OS_Flags flags);
			// Returns an adjusted version of the argument, guaranteeing that
			// certain flags are set correctly for log file access.
	
	// Certain inherited methods in our parent should be illegal for this object
	private:
		
		virtual void Read (std::string& bufferObj, unsigned long length, bool exclusiveAccess = false) {}
		
		virtual void Write (const std::string& bufferObj,
							unsigned long bufferOffset = 0,
							unsigned long segmentLength = 0,
							bool exclusiveAccess = false)
			{ Inherited::Write(bufferObj,bufferOffset,segmentLength,exclusiveAccess); }
		
		virtual void ReadWholeFile (std::string& bufferObj, bool exclusiveAccess = false) {}
		
		virtual void ReadWholeFile (StdStringList& stringList, char lineDelimiter = '\n', bool exclusiveAccess = false) {}
		
		virtual void WriteWholeFile (const std::string& bufferObj,
									 OS_Mode createPerms = (S_IRUSR | S_IWUSR),
									 bool exclusiveAccess = false) {}
		
		virtual std::string Execute (const unsigned char* appData = NULL, size_t appDataLength = 0) { return std::string(); }
		
		virtual std::string Execute (const StdStringList& args, const unsigned char* appData = NULL, size_t appDataLength = 0) { return std::string(); }
	
	protected:
		
		unsigned long									fMaxFileSize;
};

//---------------------------------------------------------------------
// Class TDirObj
//---------------------------------------------------------------------
class TDirObj : public TFSObject
{
	private:
		
		typedef							TFSObject			Inherited;
		
	public:
		
		TDirObj ();
			// Constructor
		
		TDirObj (const std::string& path);
			// Constructor
		
		TDirObj (const TDirObj& obj);
			// Copy constructor
		
		virtual ~TDirObj ();
			// Destructor
		
		virtual TDirObj* New () const
			{ return new TDirObj; }
		
		virtual TDirObj* New (const TFSObject& obj) const
			{ return new TDirObj(obj); }
		
		virtual bool IsFile () const
			{ return false; }
		
		virtual bool IsDir () const
			{ return true; }
		
		virtual void SetPath (const std::string& newPath);
			// Override to ensure that the path ends with a delimiter.
		
		virtual void Create (OS_Mode mode = S_IRWXU);
			// Creates a new directory at the current path, with the given mode.
		
		virtual void Create (const std::string& path, OS_Mode mode = S_IRWXU);
			// Creates a new directory at the given path, with the given mode.
		
		virtual void HeirarchicalCreate (const std::string& path,
										 OS_Mode mode,
										 uid_t ownerID,
										 gid_t groupID);
			// Creates a new directory at the given path, with the given mode.
			// Intervening directories are created if they are missing.
			// All newly-created directories will have the given mode, owner
			// and group settings.  Specify -1 for ownerID and groupID to
			// use the current user settings.
		
		virtual void HeirarchicalCreate (const std::string& path,
										 OS_Mode mode,
										 std::string ownerName,
										 std::string groupName);
			// Creates a new directory at the given path, with the given mode.
			// Intervening directories are created if they are missing.
			// All newly-created directories will have the given mode, owner
			// and group settings.  Specify an empty string for ownername
			// and groupName to use the current user settings.
		
		virtual void HeirarchicalCreate (const std::string& path, OS_Mode mode = S_IRWXU);
			// Convenience call for the previous two methods.
		
		virtual void Delete (bool throwOnError = true);
			// Deletes the current directory.  The directory must be empty for this to
			// succeed.
};

//---------------------------------------------------------------------
// Class TExclusiveFileLock
//---------------------------------------------------------------------
class TExclusiveFileLock
{
	public:
		
		TExclusiveFileLock (int fileDescriptor) : fFD(fileDescriptor)
			{
				Init();
			}
		
		TExclusiveFileLock (const TFileObj& fileObj) : fFD(fileObj.FileDescriptor())
			{
				Init();
			}
		
		~TExclusiveFileLock ()
			{
				fLockStruct.l_type = F_UNLCK;
				
				fcntl(fFD,F_SETLK,&fLockStruct);
			}
	
	private:
		
		void Init ()
			{
				memset(&fLockStruct,0,sizeof(fLockStruct));
				fLockStruct.l_type = F_WRLCK;
				fLockStruct.l_start = 0;
				fLockStruct.l_whence = SEEK_SET;
				fLockStruct.l_len = 0;
				fLockStruct.l_pid = getpid();

				while (fcntl(fFD,F_SETLKW,&fLockStruct) == -1)
				{
					if (errno == EACCES || errno == EAGAIN)
					{
						// Someone else has a lock.  Sleep and try again.
						usleep(100);
					}
					else
					{
						std::string		errString;
						
						errString += "Cannot obtain file lock on file descriptor ";
						errString += fFD;
						throw TSymLibErrorObj(errno,errString);
					}
				}
			}
	
	private:
		int				fFD;
		struct flock	fLockStruct;
};

//*********************************************************************
// Global Function Prototypes
//*********************************************************************

void ReadWholeFile (const std::string& path, std::string& bufferObj, bool exclusiveAccess = false);
	// Function creates a temporary TFileObj, sets it to the given path, opens
	// the file, calls the object's ReadWholeFile() method to destructively
	// modify the bufferObj variable, then closes the file and disposes of the
	// object.

void WriteWholeFile (const std::string& path,
					 const std::string& bufferObj,
					 OS_Mode createPerms = (S_IRUSR | S_IWUSR),
					 bool exclusiveAccess = false);
	// Function creates a temporary TFileObj, sets it to the given path, calls
	// the object's WriteWholeFile() method with the given bufferObj and
	// createPerms, then closes the file and disposes of the object.

std::string ReadSymbolicLink (const std::string& path);
	// Given a path to a symbolic link, this function returns the contents
	// of that link (ie, the file system object that the link points to).

void WriteLogEntryToFile (const std::string& fullPath, const std::string& logEntry, bool throwOnError = true);
	// Writes the given logEntry to fullPath, inserting the current
	// date, time and process ID number.

std::string MakeLogPath (const std::string& pathPrefix);
	// Returns a log path with the current year and month added, in the
	// format pathPrefix_YYYY_MM.

std::string ExecWithIO (const std::string& appCommand, const unsigned char* appData = NULL, size_t appDataLength = 0);
	// Function executes a command designated by the appCommand argument
	// in a forked process and collects the command's output into the
	// returned temporary string.  If appData is present, that data
	// is piped to the command after launch.

std::string GetCurrentDirectory ();
	// Returns the current working directory as a temporary string.

std::string FindFile (const std::string& fileName, const StdStringList& dirList);
	// Given a filename and a list of directories to search, this function
	// attempts to locate a file with that name in those directories.
	// If successful, the real path (as defined by realpath()) is returned,
	// otherwise an empty string is returned.  The first found occurrence,
	// as determined by the ordering of entries in dirList, is returned.

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif // SYMLIB_FILE

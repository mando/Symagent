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
#		Last Modified:				15 Sep 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-utils.h"

#include "symlib-ssl-encode.h"
#include "symlib-ssl-digest.h"
#include "symlib-task-queue.h"
#include "symlib-threads.h"

#include <cstdio>
#include <grp.h>
#include <map>
#include <math.h>
#include <pwd.h>
#include <signal.h>
#include <vector>
#include <zlib.h>

#if HAVE_SYSINFO && HAVE_SYS_SYSINFO_H
	#define kLoadAvgViaSysinfo 1
	#include <sys/sysinfo.h>
#elif HAVE_GETLOADAVG
	#define kLoadAvgViaLoadAvg 1
#endif

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define		kErrorLogFileName				"symagent_error_log.txt"
#define		kMessagesLogFileName			"symagent_message_log.txt"

#define		kMaxLogFileSize					4000000

//--------------------------------------------------------------------
// Global Variables
//--------------------------------------------------------------------
TSymLibEnvironObj*							gEnvironObjPtr = NULL;
static bool                             	gSRANDCalled = false;

//*********************************************************************
// Class TSymLibEnvironObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSymLibEnvironObj::TSymLibEnvironObj (int argc, char** argv)
	:	fDynDebugFlags(kDynDebugNone),
		fLogUserID(0),
		fAppPID(getpid()),
		fIsDaemon(false)
{
	TFileObj		tempFileObj(argv[0]);
	TFileObj		appFileObj(tempFileObj.RealPath());
	TDigest			appSigDigestObj("SHA1");
	TDigestContext	appSigDigestContextObj;
	TEncodeContext	encodeContext;
	
	// Save the name of this executable.
	fAppName = appFileObj.FileName();
	
	// Compute the signature of this executable
	appSigDigestContextObj.Initialize(appSigDigestObj);
	try
	{
		appSigDigestContextObj.Update(appFileObj);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (errObj.GetError() == ENOENT && std::string(PLATFORM).find("cygwin") != std::string::npos)
		{
			// Weirdly, the open() system call seems to fail to map .exe extensions
			// properly.  Let's add it and see what happens.
			std::string		newPath;
			
			newPath = appFileObj.Path() + ".exe";
			appFileObj.SetPath(newPath);
			fAppName = appFileObj.FileName();
			appSigDigestContextObj.Update(appFileObj);
		}
		else
		{
			throw;
		}
	}
	fAppSignature = encodeContext.Encode(appSigDigestContextObj.Final());
	
	// Save our arguments.
	for (int x = 0; x < argc; x++)
		fAppArgList.push_back(argv[x]);
	
	// Set the max sizes for our log files (if they exceed this size
	// then they'll automatically rotate)
	fErrorLogFileObj.SetMaxFileSize(kMaxLogFileSize);
	fMessagesLogFileObj.SetMaxFileSize(kMaxLogFileSize);
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSymLibEnvironObj::~TSymLibEnvironObj ()
{
}

//---------------------------------------------------------------------
// TSymLibEnvironObj::SetLogDirectory
//---------------------------------------------------------------------
void TSymLibEnvironObj::SetLogDirectory (const std::string& logDir, bool createIfNotFound)
{
	TDirObj		logDirObj(logDir);
	
	if (!logDirObj.Exists() && createIfNotFound)
		logDirObj.HeirarchicalCreate(logDirObj.Path());
	
	if (!logDirObj.Exists())
	{
		std::string		errString;
		
		errString = "Log directory '" + logDirObj.Path() + "' does not exist";
		throw TSymLibErrorObj(ENOENT,errString);
	}
	
	fLogDir = logDirObj.Path();
	fErrorLogFileObj.SetPath(fLogDir + kErrorLogFileName);
	fMessagesLogFileObj.SetPath(fLogDir + kMessagesLogFileName);
}

//---------------------------------------------------------------------
// TSymLibEnvironObj::WriteToErrorLogFile
//---------------------------------------------------------------------
void TSymLibEnvironObj::WriteToErrorLogFile (const std::string& logEntry)
{
	if (!fErrorLogFileObj.Path().empty())
	{
		std::string		myEntry;
		bool			logFileExists = fErrorLogFileObj.Exists();
		
		myEntry += GetTaskName() + ": " + logEntry;
		
		fErrorLogFileObj.WriteEntry(myEntry,false,true);
		
		if (!logFileExists && fErrorLogFileObj.Exists())
		{
			if (fLogUserID > 0)
			{
				try
				{
					fErrorLogFileObj.SetOwner(fLogUserID,true);
				}
				catch (...)
				{
					// Ignore all errors
				}
			}
			
			if (fLogGroupID > 0)
			{
				try
				{
					fErrorLogFileObj.SetGroup(fLogGroupID,true);
				}
				catch (...)
				{
					// Ignore all errors
				}
			}
		}
	}
}

//---------------------------------------------------------------------
// TSymLibEnvironObj::WriteToMessagesLogFile
//---------------------------------------------------------------------
void TSymLibEnvironObj::WriteToMessagesLogFile (const std::string& logEntry)
{
	if (!fMessagesLogFileObj.Path().empty())
	{
		std::string		myEntry;
		bool			logFileExists = fMessagesLogFileObj.Exists();
		
		myEntry += GetTaskName() + ": " + logEntry;
		
		fMessagesLogFileObj.WriteEntry(myEntry,false,true);
		
		if (!logFileExists && fMessagesLogFileObj.Exists())
		{
			if (fLogUserID > 0)
			{
				try
				{
					fMessagesLogFileObj.SetOwner(fLogUserID,true);
				}
				catch (...)
				{
					// Ignore all errors
				}
			}
			
			if (fLogGroupID > 0)
			{
				try
				{
					fMessagesLogFileObj.SetGroup(fLogGroupID,true);
				}
				catch (...)
				{
					// Ignore all errors
				}
			}
		}
	}
}

//---------------------------------------------------------------------
// TSymLibEnvironObj::SetLogUser
//---------------------------------------------------------------------
void TSymLibEnvironObj::SetLogUser (uid_t userID)
{
	fLogUserID = userID;
}

//---------------------------------------------------------------------
// TSymLibEnvironObj::SetLogUser
//---------------------------------------------------------------------
void TSymLibEnvironObj::SetLogUser (const std::string& userName)
{
	if (!userName.empty())
		fLogUserID = MapUserNameToUID(userName.c_str());
}

//---------------------------------------------------------------------
// TSymLibEnvironObj::SetLogGroup
//---------------------------------------------------------------------
void TSymLibEnvironObj::SetLogGroup (gid_t groupID)
{
	fLogGroupID = groupID;
}

//---------------------------------------------------------------------
// TSymLibEnvironObj::SetLogGroup
//---------------------------------------------------------------------
void TSymLibEnvironObj::SetLogGroup (const std::string& groupName)
{
	if (!groupName.empty())
		fLogGroupID = MapGroupNameToGID(groupName.c_str());
}

//---------------------------------------------------------------------
// TSymLibEnvironObj::CloseFiles
//---------------------------------------------------------------------
void TSymLibEnvironObj::CloseFiles ()
{
	if (fErrorLogFileObj.IsOpen())
		fErrorLogFileObj.Close();
	if (fMessagesLogFileObj.IsOpen())
		fMessagesLogFileObj.Close();
}

//---------------------------------------------------------------------
// TSymLibEnvironObj::SetTaskName
//---------------------------------------------------------------------
void TSymLibEnvironObj::SetTaskName (const std::string& taskName)
{
	TLockedPthreadMutexObj	lock(fTaskNameMapMutex);
	unsigned long			threadID = 0;
	TPthreadObj*			threadObjPtr = MyThreadObjPtr();
	
	if (threadObjPtr)
		threadID = threadObjPtr->InternalID();
	
	fTaskNameMap[threadID] = taskName;
}

//---------------------------------------------------------------------
// TSymLibEnvironObj::GetTaskName
//---------------------------------------------------------------------
std::string TSymLibEnvironObj::GetTaskName (bool fallbackToAgentName)
{
	std::string		taskName;
	TPthreadObj*	threadObjPtr = MyThreadObjPtr();
	
	if (threadObjPtr)
	{
		unsigned long	threadID = threadObjPtr->InternalID();
		
		if (threadID > 0)
		{
			TLockedPthreadMutexObj	lock(fTaskNameMapMutex);
			TaskNameMap_const_iter	foundIter = fTaskNameMap.find(threadID);
			
			if (foundIter != fTaskNameMap.end())
				taskName = foundIter->second;
		}
	}
	
	if (taskName.empty() && fallbackToAgentName)
		taskName = fAgentName;
	
	return taskName;
}

//---------------------------------------------------------------------
// TSymLibEnvironObj::RemoveTaskName
//---------------------------------------------------------------------
void TSymLibEnvironObj::RemoveTaskName ()
{
	TLockedPthreadMutexObj	lock(fTaskNameMapMutex);
	TPthreadObj*			threadObjPtr = MyThreadObjPtr();
	
	if (threadObjPtr)
		fTaskNameMap.erase(threadObjPtr->InternalID());
}

//*********************************************************************
// Global Functions
//*********************************************************************

//---------------------------------------------------------------------
// LibraryInit
//---------------------------------------------------------------------
void LibraryInit (int argc, char** argv, const std::string& agentName)
{
	gEnvironObjPtr = new TSymLibEnvironObj(argc,argv);
	
	gEnvironObjPtr->SetAgentName(agentName);
	
	if (find(gEnvironObjPtr->ArgListBegin() + 1,gEnvironObjPtr->ArgListEnd(),kAppArgKeyEnableCommLogging) != gEnvironObjPtr->ArgListEnd())
		gEnvironObjPtr->SetDynamicDebugFlag(kDynDebugLogServerCommunication);
		
	if (find(gEnvironObjPtr->ArgListBegin() + 1,gEnvironObjPtr->ArgListEnd(),kAppArgKeyUse7200ConfFile) != gEnvironObjPtr->ArgListEnd()) {
		gEnvironObjPtr->SetConfFileLoc("7200.symagent.xml");
	}
}

//---------------------------------------------------------------------
// WriteToErrorLogFile
//---------------------------------------------------------------------
void WriteToErrorLogFile (const std::string& logEntry)
{
	try
	{
		if (gEnvironObjPtr)
			gEnvironObjPtr->WriteToErrorLogFile(logEntry);
	}
	catch (...)
	{
		// Silently ignore all errors
	}
}

//---------------------------------------------------------------------
// WriteToMessagesLogFile
//---------------------------------------------------------------------
void WriteToMessagesLogFile (const std::string& logEntry)
{
	try
	{
		if (gEnvironObjPtr)
			gEnvironObjPtr->WriteToMessagesLogFile(logEntry);
	}
	catch (...)
	{
		// Silently ignore all errors
	}
}

//---------------------------------------------------------------------
// PIDFileObj
//---------------------------------------------------------------------
TFileObj PIDFileObj ()
{
	TFileObj		fileObj;
	std::string		pidFilePath;
	
	pidFilePath = "/var/run/" + gEnvironObjPtr->AppName() + ".pid";
	fileObj.SetPath(pidFilePath);
	
	return fileObj;
}

//---------------------------------------------------------------------
// CreatePIDFile
//---------------------------------------------------------------------
void CreatePIDFile ()
{
	PIDFileObj().WriteWholeFile(NumToString(getpid()),S_IRWXU|S_IRWXG|S_IROTH);
}

//---------------------------------------------------------------------
// ReadPIDFile
//---------------------------------------------------------------------
unsigned long ReadPIDFile ()
{
	unsigned long	pid = 0;
	TFileObj		pidFileObj(PIDFileObj());
	
	if (pidFileObj.Exists())
	{
		std::string		buffer;
		
		pidFileObj.ReadWholeFile(buffer);
		pid = static_cast<unsigned long>(StringToNum(buffer));
	}
	
	return pid;
}

//---------------------------------------------------------------------
// DeletePIDFile
//---------------------------------------------------------------------
void DeletePIDFile ()
{
	PIDFileObj().Delete(false);
}

//---------------------------------------------------------------------
// Compress
//---------------------------------------------------------------------
void Compress (const std::string& inBuffer, std::string& outBuffer, CompressionMode mode)
{
	switch (mode)
	{
		case kCompressionModeUnspecified:
		case kCompressionModeNone:
			outBuffer = inBuffer;
			break;
		
		case kCompressionModeZLib:
			ZLibCompress(inBuffer,outBuffer);
			break;
		
		case kCompressionModeGZip:
			GZipCompress(inBuffer,outBuffer);
			break;
	}
}

//---------------------------------------------------------------------
// Compress
//---------------------------------------------------------------------
void Compress (std::string& buffer, CompressionMode mode)
{
	switch (mode)
	{
		case kCompressionModeUnspecified:
		case kCompressionModeNone:
			break;
		
		case kCompressionModeZLib:
			ZLibCompress(buffer);
			break;
		
		case kCompressionModeGZip:
			GZipCompress(buffer);
			break;
	}
}

//---------------------------------------------------------------------
// AsCompressed
//---------------------------------------------------------------------
std::string AsCompressed (const std::string& buffer, CompressionMode mode)
{
	std::string		compressedBuffer;
	
	switch (mode)
	{
		case kCompressionModeUnspecified:
		case kCompressionModeNone:
			compressedBuffer = buffer;
			break;
		
		case kCompressionModeZLib:
			compressedBuffer = AsZLibCompressed(buffer);
			break;
		
		case kCompressionModeGZip:
			compressedBuffer = AsGZipCompressed(buffer);
			break;
	}
	
	return compressedBuffer;
}

//---------------------------------------------------------------------
// ZLibCompress
//---------------------------------------------------------------------
void ZLibCompress (const std::string& inBuffer, std::string& outBuffer, bool forGZip)
{
	z_stream	zlibStream;
	int			zlibResult = 0;
	int			windowBits = (forGZip ? -MAX_WBITS : MAX_WBITS);
	
	// Reserve the memory for our outbound buffer
	outBuffer = "";
	outBuffer.resize(inBuffer.length()*2);
	
	// Initialize the zLib stream parameter
	zlibStream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(inBuffer.data()));
	zlibStream.avail_in = inBuffer.length();
	zlibStream.total_in = 0;
	zlibStream.next_out = reinterpret_cast<Bytef*>(const_cast<char*>(outBuffer.data()));
	zlibStream.avail_out = outBuffer.length();
	zlibStream.total_out = 0;
	zlibStream.zalloc = NULL;
	zlibStream.zfree = NULL;
	
	// Initialize the deflation function
	zlibResult = deflateInit2(&zlibStream,Z_BEST_COMPRESSION,Z_DEFLATED,windowBits,MAX_MEM_LEVEL,Z_DEFAULT_STRATEGY);
	
	if (zlibResult == Z_STREAM_ERROR)
		throw TSymLibErrorObj(EINVAL,"Invalid argument to zLib compression");
	if (zlibResult == Z_MEM_ERROR)
		throw TSymLibErrorObj(ENOMEM,"Cannot allocate memory for zLib compression");
	
	try
	{
		// Do the whole compress at once
		zlibResult = deflate(&zlibStream,Z_FINISH);
		if (zlibResult != Z_OK && zlibResult != Z_STREAM_END)
			throw zlibResult;
		
		// Resize our output buffer to exactly what zLib created
		outBuffer.resize(zlibStream.total_out);
		
		// Cleanup zLib
		deflateEnd(&zlibStream);
	}
	catch (...)
	{
		// Cleanup zLib
		deflateEnd(&zlibStream);
		
		// Re-throw exception
		throw;
	}
}

//---------------------------------------------------------------------
// ZLibCompress
//---------------------------------------------------------------------
void ZLibCompress (std::string& buffer, bool forGZip)
{
	std::string		compressedBuffer;
	
	ZLibCompress(buffer,compressedBuffer,forGZip);
	buffer = compressedBuffer;
}

//---------------------------------------------------------------------
// AsZLibCompressed
//---------------------------------------------------------------------
std::string AsZLibCompressed (const std::string& dataBuffer, bool forGZip)
{
	std::string		compressedBuffer;
	
	ZLibCompress(dataBuffer,compressedBuffer,forGZip);
	
	return compressedBuffer;
}

//---------------------------------------------------------------------
// GZipCompress
//---------------------------------------------------------------------
void GZipCompress (const std::string& inBuffer, std::string& outBuffer)
{
	std::string		interimBuffer;
	uint32_t		inputLength = inBuffer.length();
	uint32_t		inputCRC;
	uint32_t		tempUInt;
	const char		kOSCode = 0x03;		// Unix -- will need cross-plat adjustment
	const int		kGZipHeaderSize = 10;
	char			GZipHeader[kGZipHeaderSize] = {0x1f,0x8b,Z_DEFLATED,0,0,0,0,0,0,kOSCode};
	
	// Compress the input into our interim buffer using zLib
	ZLibCompress(inBuffer,interimBuffer,true);
	
	// Checksum the original input
	inputCRC = crc32(0L,Z_NULL,0);
    inputCRC = crc32(inputCRC,reinterpret_cast<const Bytef*>(inBuffer.data()),inputLength);
    
    // Now put it all together
    outBuffer = "";
    outBuffer.append(GZipHeader,kGZipHeaderSize);
    outBuffer.append(interimBuffer);
    tempUInt = LittleEndianFromNative(inputCRC);
    outBuffer.append(reinterpret_cast<char*>(&tempUInt),sizeof(tempUInt));
    tempUInt = LittleEndianFromNative(inputLength);
    outBuffer.append(reinterpret_cast<char*>(&tempUInt),sizeof(tempUInt));
}

//---------------------------------------------------------------------
// GZipCompress
//---------------------------------------------------------------------
void GZipCompress (std::string& buffer)
{
	std::string		compressedBuffer;
	
	GZipCompress(buffer,compressedBuffer);
	buffer = compressedBuffer;
}

//---------------------------------------------------------------------
// AsGZipCompressed
//---------------------------------------------------------------------
std::string AsGZipCompressed (const std::string& dataBuffer)
{
	std::string		compressedBuffer;
	
	GZipCompress(dataBuffer,compressedBuffer);
	
	return compressedBuffer;
}

//---------------------------------------------------------------------
// Expand
//---------------------------------------------------------------------
void Expand (const std::string& inBuffer, std::string& outBuffer, CompressionMode mode)
{
	switch (mode)
	{
		case kCompressionModeUnspecified:
		case kCompressionModeNone:
			outBuffer = inBuffer;
			break;
		
		case kCompressionModeZLib:
			ZLibExpand(inBuffer,outBuffer);
			break;
		
		case kCompressionModeGZip:
			throw TSymLibErrorObj(-1,"Expansion of gzipped data not supported");
			break;
	}
}

//---------------------------------------------------------------------
// Expand
//---------------------------------------------------------------------
void Expand (std::string& buffer, CompressionMode mode)
{
	switch (mode)
	{
		case kCompressionModeUnspecified:
		case kCompressionModeNone:
			break;
		
		case kCompressionModeZLib:
			ZLibExpand(buffer);
			break;
		
		case kCompressionModeGZip:
			throw TSymLibErrorObj(-1,"Expansion of gzipped data not supported");
			break;
	}
}

//---------------------------------------------------------------------
// AsExpanded
//---------------------------------------------------------------------
std::string AsExpanded (const std::string& buffer, CompressionMode mode)
{
	std::string		expandededBuffer;
	
	switch (mode)
	{
		case kCompressionModeUnspecified:
		case kCompressionModeNone:
			expandededBuffer = buffer;
			break;
		
		case kCompressionModeZLib:
			expandededBuffer = AsZLibExpanded(buffer);
			break;
		
		case kCompressionModeGZip:
			throw TSymLibErrorObj(-1,"Expansion of gzipped data not supported");
			break;
	}
	
	return expandededBuffer;
}

//---------------------------------------------------------------------
// ZLibExpand
//---------------------------------------------------------------------
void ZLibExpand (const std::string& inBuffer, std::string& outBuffer)
{
	z_stream	zlibStream;
	std::string	tempOutBuffer;
	int			zlibResult = 0;
	
	// Clear the output argument
	outBuffer = "";
	
	// Reserve the memory for our temp outbound buffer
	tempOutBuffer.resize(inBuffer.length()*2);
	
	// Initialize the zLib stream parameter
	zlibStream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(inBuffer.data()));
	zlibStream.avail_in = inBuffer.length();
	zlibStream.total_in = 0;
	zlibStream.zalloc = NULL;
	zlibStream.zfree = NULL;
	
	// Initialize the inflation function
	zlibResult = inflateInit(&zlibStream);
	
	if (zlibResult == Z_STREAM_ERROR)
		throw TSymLibErrorObj(EINVAL,"Invalid argument to zLib expansion");
	if (zlibResult == Z_MEM_ERROR)
		throw TSymLibErrorObj(ENOMEM,"Cannot allocate memory for zLib expansion");
	
	try
	{
		// Loop through the inflate process
		do
		{
			zlibStream.next_out = reinterpret_cast<Bytef*>(const_cast<char*>(tempOutBuffer.data()));
			zlibStream.avail_out = tempOutBuffer.length();
			zlibStream.total_out = 0;
			
			zlibResult = inflate(&zlibStream,Z_SYNC_FLUSH);
			if (zlibResult == Z_OK || zlibResult == Z_STREAM_END)
			{
				outBuffer.append(tempOutBuffer,0,zlibStream.total_out);
			}
			else
			{
				throw TSymLibErrorObj(zlibResult,"Error during zlib expansion");
			}
		}
		while (zlibResult != Z_STREAM_END);
		
		// Cleanup zLib
		inflateEnd(&zlibStream);
	}
	catch (...)
	{
		// Cleanup zLib
		inflateEnd(&zlibStream);
		
		// Re-throw exception
		throw;
	}
}

//---------------------------------------------------------------------
// ZLibExpand
//---------------------------------------------------------------------
void ZLibExpand (std::string& buffer)
{
	std::string		expandedBuffer;
	
	ZLibExpand(buffer,expandedBuffer);
	buffer = expandedBuffer;
}

//---------------------------------------------------------------------
// AsZLibExpanded
//---------------------------------------------------------------------
std::string AsZLibExpanded (const std::string& dataBuffer)
{
	std::string		expandedBuffer;
	
	ZLibExpand(dataBuffer,expandedBuffer);
	
	return expandedBuffer;
}

//---------------------------------------------------------------------
// SplitStdString
//---------------------------------------------------------------------
void SplitStdString (char delimiter, const std::string& s, StdStringList& stdStringList, bool includeEmpties)
{
	// Clear the destination argument
	stdStringList.clear();
	
	if (!s.empty())
	{
		std::string		tempString;
		
		for (unsigned long x = 0; x < s.length(); x++)
		{
			if (s[x] == delimiter)
			{
				if (!tempString.empty() || includeEmpties)
					stdStringList.push_back(tempString);
				tempString = "";
			}
			else
			{
				tempString += s[x];
			}
		}
		
		// Make sure we get the tailings.
		if (!tempString.empty())
			stdStringList.push_back(tempString);
		else if (s[s.length()-1] == delimiter && includeEmpties)
			stdStringList.push_back("");
	}
}

//---------------------------------------------------------------------
// SplitStdString
//---------------------------------------------------------------------
void SplitStdString (const std::string& delimiter, std::string s, StdStringList& stdStringList, bool includeEmpties)
{
	unsigned long	foundPos = std::string::npos;
	
	// Clear any existing field list
	stdStringList.clear();
	
	if (!s.empty())
	{
		// Search for delimiter
		foundPos = s.find(delimiter);
		while (foundPos != std::string::npos)
		{
			if (foundPos > 0)
			{
				stdStringList.push_back(s.substr(0,foundPos));
			}
			else if (includeEmpties)
			{
				// Caller wants the empty strings
				stdStringList.push_back(std::string());
			}
			
			// Erase what we've parsed so far
			s.erase(0,foundPos + delimiter.length());
			
			// Search some more
			foundPos = s.find(delimiter);
		}
		
		if (!s.empty())
		{
			// Push last line onto the field list
			stdStringList.push_back(s);
		}
	}
}

//---------------------------------------------------------------------
// JoinStdStringList
//---------------------------------------------------------------------
std::string JoinStdStringList (char delimiter, const StdStringList& stdStringList)
{
	std::string		s;
	
	for (StdStringList_const_iter x = stdStringList.begin(); x != stdStringList.end(); x++)
	{
		if (!s.empty())
			s += delimiter;
		s += *x;
	}
	
	return s;
}

//---------------------------------------------------------------------
// StringToNum
//---------------------------------------------------------------------
double StringToNum (const std::string& s)
{
	double				num = 0.0;
	std::istringstream	tempStringStream(s);
	
	tempStringStream >> num;
	
	return num;
}

//---------------------------------------------------------------------
// MapGroupNameToGID
//---------------------------------------------------------------------
gid_t MapGroupNameToGID (const char* groupName)
{
	gid_t			groupID = static_cast<gid_t>(-1);
	struct group*	groupInfoPtr;
	
	groupInfoPtr = getgrnam(groupName);
	if (groupInfoPtr)
		groupID = groupInfoPtr->gr_gid;
	else if (errno != ENOENT)
	{
		std::string		errString;
		
		errString = "Group '";
		errString += groupName;
		errString += "' does not exist";
		throw TSymLibErrorObj(errno,errString);
	}
	
	return groupID;
}

//---------------------------------------------------------------------
// MapUserNameToUID
//---------------------------------------------------------------------
uid_t MapUserNameToUID (const char* userName)
{
	uid_t			userID = static_cast<uid_t>(-1);
	struct passwd*	userInfoPtr;
	
	userInfoPtr = getpwnam(userName);
	if (userInfoPtr)
		userID = userInfoPtr->pw_uid;
	else if (errno != ENOENT)
	{
		std::string		errString;
		
		errString = "User '";
		errString += userName;
		errString += "' does not exist";
		throw TSymLibErrorObj(errno,errString);
	}
	
	return userID;
}

//---------------------------------------------------------------------
// OpenWithoutInterrupts
//---------------------------------------------------------------------
int OpenWithoutInterrupts (const char *pathname, int flags)
{
	int		fd;
	
	do
	{
		fd = open(pathname,flags);
	}
	while (fd <= 0 && (errno == EINTR || errno == EINPROGRESS));
	
	return fd;
}

//---------------------------------------------------------------------
// OpenWithoutInterrupts
//---------------------------------------------------------------------
int OpenWithoutInterrupts (const char *pathname, int flags, mode_t mode)
{
	int		fd;
	
	do
	{
		fd = open(pathname,flags,mode);
	}
	while (fd <= 0 && (errno == EINTR || errno == EINPROGRESS));
	
	return fd;
}

//---------------------------------------------------------------------
// CreatWithoutInterrupts
//---------------------------------------------------------------------
int CreatWithoutInterrupts (const char *pathname, mode_t mode)
{
	int		fd;
	
	do
	{
		fd = creat(pathname,mode);
	}
	while (fd <= 0 && (errno == EINTR || errno == EINPROGRESS));
	
	return fd;
}

//---------------------------------------------------------------------
// CloseWithoutInterrupts
//---------------------------------------------------------------------
void CloseWithoutInterrupts (int fd, bool throwOnError)
{
	while (close(fd) < 0)
	{
		if (errno != EINTR)
		{
			if (throwOnError)
				throw TSymLibErrorObj(errno,"While closing file descriptor");
			else
				break;
		}
	}
}

//---------------------------------------------------------------------
// Pause
//---------------------------------------------------------------------
void Pause (double seconds)
{
	if (seconds > 0.0)
	{
		#if HAVE_NANOSLEEP
			struct timespec		timeInfo;
			
			timeInfo.tv_sec = static_cast<time_t>(seconds);
			timeInfo.tv_nsec = static_cast<long>(1000000 * (seconds - floor(seconds)));
			
			nanosleep(&timeInfo,NULL);
		#else
			#if HAVE_USLEEP
				usleep(static_cast<unsigned long>((1000 * floor(seconds)) + (1000 * (seconds - floor(seconds)))));
			#else
				#if HAVE_SLEEP
					sleep(static_cast<unsigned int>(ceil(seconds)));
				#endif
			#endif
		#endif
	}
}

//---------------------------------------------------------------------
// RandomBytes
//---------------------------------------------------------------------
void RandomBytes (size_t bytesToGet, char* outBuffer, bool canBlock)
{
	size_t				bytesRead = 0;
	FILE*				devRandom = NULL;
	
	if (canBlock)
	{
		#if defined(HAVE__DEV_RANDOM) && HAVE__DEV_RANDOM
			devRandom = fopen("/dev/random","r");
		#endif
	}
	else
	{
		#if defined(HAVE__DEV_URANDOM) && HAVE__DEV_URANDOM
			devRandom = fopen("/dev/urandom","r");
		#endif
	}
	
	if (devRandom)
	{
		bytesRead = fread(outBuffer,bytesToGet,1,devRandom);
		fclose(devRandom);
	}
	
	if (bytesRead < bytesToGet)
	{
		if (!gSRANDCalled)
		{
			srand(time(NULL) ^ getpid());
			gSRANDCalled = true;
		}
		
		for (size_t x = bytesRead; x < bytesToGet; x++)
			outBuffer[x] = static_cast<unsigned char>(256.0*rand()/(RAND_MAX+1.0));
	}
}

//---------------------------------------------------------------------
// RandomULong
//---------------------------------------------------------------------
unsigned long RandomULong (bool canBlock)
{
	unsigned long		randomNum = 0;
	
	RandomBytes(sizeof(randomNum),reinterpret_cast<char*>(&randomNum),canBlock);
	
	return randomNum;
}

//---------------------------------------------------------------------
// ByteSwapped
//---------------------------------------------------------------------
int16_t ByteSwapped (const int16_t& n)
{
	return ByteSwapped(static_cast<uint16_t>(n));
}

//---------------------------------------------------------------------
// ByteSwapped
//---------------------------------------------------------------------
uint16_t ByteSwapped (const uint16_t& n)
{
	return ((n & 0x00FFU) << 8) |
		   ((n & 0xFF00U) >> 8);
}

//---------------------------------------------------------------------
// ByteSwapped
//---------------------------------------------------------------------
int32_t ByteSwapped (const int32_t& n)
{
	return ByteSwapped(static_cast<uint32_t>(n));
}

//---------------------------------------------------------------------
// ByteSwapped
//---------------------------------------------------------------------
uint32_t ByteSwapped (const uint32_t& n)
{
	return ((n & 0x000000FFU) << 24) |
		   ((n & 0x0000FF00U) << 8) |
		   ((n & 0x00FF0000U) >> 8) |
		   ((n & 0xFF000000U) >> 24);
}

//---------------------------------------------------------------------
// ByteSwapped
//---------------------------------------------------------------------
int64_t ByteSwapped (const int64_t& n)
{
	return ByteSwapped(static_cast<uint64_t>(n));
}

//---------------------------------------------------------------------
// ByteSwapped
//---------------------------------------------------------------------
uint64_t ByteSwapped (const uint64_t& n)
{
	return ((n & 0x00000000000000FFULL) << 56) |
		   ((n & 0x000000000000FF00ULL) << 40) |
		   ((n & 0x0000000000FF0000ULL) << 24) |
		   ((n & 0x00000000FF000000ULL) << 8) |
		   ((n & 0x000000FF00000000ULL) >> 8) |
		   ((n & 0x0000FF0000000000ULL) >> 24) |
		   ((n & 0x00FF000000000000ULL) >> 40) |
		   ((n & 0xFF00000000000000ULL) >> 56);
}

//---------------------------------------------------------------------
// GetSystemLoads
//---------------------------------------------------------------------
void GetSystemLoads (double& oneMin, double& fiveMin, double& fifteenMin)
{
	// Initialize the outbound arguments
	oneMin = 0.0;
	fiveMin = 0.0;
	fifteenMin = 0.0;
	
	#if defined(kLoadAvgViaSysinfo)
		struct sysinfo			systemInfo;
		
		if (sysinfo(&systemInfo) != 0)
			throw TSymLibErrorObj(errno,"While calling sysinfo()");
		
		oneMin = static_cast<double>(systemInfo.loads[0]) / static_cast<double>(1<<SI_LOAD_SHIFT);
		fiveMin = static_cast<double>(systemInfo.loads[1]) / static_cast<double>(1<<SI_LOAD_SHIFT);
		fifteenMin = static_cast<double>(systemInfo.loads[2]) / static_cast<double>(1<<SI_LOAD_SHIFT);
	#elif defined(kLoadAvgViaLoadAvg)
		double					averages[3];
		
		if (getloadavg(averages,3) <= 0)
			throw TSymLibErrorObj(errno,"While calling getloadavg()");
		
		oneMin = averages[0];
		fiveMin = averages[1];
		fifteenMin = averages[2];
	#endif
}

//---------------------------------------------------------------------
// ProcessInstanceID
//---------------------------------------------------------------------
std::string ProcessInstanceID ()
{
	std::string		idStr;
	unsigned long	idNum = 0;
	TPthreadObj*	currentThreadObjPtr = MyThreadObjPtr();
	
	if (currentThreadObjPtr)
		idNum = currentThreadObjPtr->InternalID();
	
	idStr = NumToString(idNum);
	
	return idStr;
}

//---------------------------------------------------------------------
// ForkDaemon
//---------------------------------------------------------------------
bool ForkDaemon ()
{
	bool	isDaemon = false;
	
	#if HAVE_FORK
		
		// Close any files we might have open
		if (gEnvironObjPtr)
			gEnvironObjPtr->CloseFiles();
		
		// Ignore our children's demise
		signal(SIGCHLD,SIG_IGN);
		
		// Fork one time
		switch (fork())
		{
			case 0:
				// Interim child process.  Ignore the children's demise, again
				signal(SIGCHLD,SIG_IGN);
				
				// Create a new session
				if (setsid() < 0)
				{
					// We can't create a new session.  Die.
					exit(0);
				}
				
				// Fork again to make sure we don't have a tty
				switch (fork())
				{
					case 0:
						{
							// Final child process.
							int	fdlimit = sysconf(_SC_OPEN_MAX);
							int	fd = 0;
							
							// Close all open streams/files
							while (fd < fdlimit)
								close(fd++);
							
							// Fix streams
							open("/dev/null",O_RDWR);
							dup(0);
							dup(0);
							
							// Set the function result so the caller knows we're
							// now a daemon
							isDaemon = true;
							
							// It's now okay to just let the function terminate.
							// We're a daemon, we don't have an error, things are
							// cool.
						}
						break;
					
					case -1:
						// Error.  Die.
						exit(0);
						break;
					
					default:
						// Interim parent process.  Die gracefully.
						exit(0);
						break;
				}
				break;
			
			case -1:
				// Error.  Throw.
				throw errno;
				break;
			
			default:
				// Actual parent process.
				break;
		}
	#endif
	
	return isDaemon;
}

//---------------------------------------------------------------------
// BecomeDaemon
//---------------------------------------------------------------------
bool BecomeDaemon ()
{
	bool	isDaemon = false;
	
	#if HAVE_FORK
		if (!ForkDaemon())
		{
			// We're the original process; die gracefully.
			exit(0);
		}
		
		isDaemon = true;
	#endif
	
	return isDaemon;
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

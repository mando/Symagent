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
#		Last Modified:				23 May 2005
#		
#######################################################################
*/

#if !defined(SYMLIB_UTILS)
#define SYMLIB_UTILS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-config.h"

#include "symlib-defs.h"
#include "symlib-exception.h"
#include "symlib-file.h"
#include "symlib-mutex.h"

#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdint.h>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TSymLibEnvironObj;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//--------------------------------------------------------------------
// Global Variable Declaractions
//--------------------------------------------------------------------
extern		TSymLibEnvironObj*							gEnvironObjPtr;

//---------------------------------------------------------------------
// Class TSymLibEnvironObj
//---------------------------------------------------------------------
class TSymLibEnvironObj
{
	private:
		
		typedef	std::map<unsigned long,std::string>		TaskNameMap;
		typedef	TaskNameMap::iterator					TaskNameMap_iter;
		typedef	TaskNameMap::const_iterator				TaskNameMap_const_iter;
	
	public:
		
		TSymLibEnvironObj (int argc, char** argv);
			// Constructor
	
	private:
		
		TSymLibEnvironObj (const TSymLibEnvironObj& obj) {}
			// Copy constructor illegal
	
	public:
		
		~TSymLibEnvironObj ();
			// Destructor
		
		void SetLogDirectory (const std::string& logDir, bool createIfNotFound = false);
			// Sets the log directory internal slot as well as other,
			// logging-related slots.
		
		void WriteToErrorLogFile (const std::string& logEntry);
			// Writes the argument to the current error log file.
		
		void WriteToMessagesLogFile (const std::string& logEntry);
			// Writes the argument to the current messages log file.
		
		void CloseFiles ();
			// Closes any files the environmental object may have open.
		
		void SetTaskName (const std::string& taskName);
			// Sets the task name for the current execution thread.
		
		std::string GetTaskName (bool fallbackToAgentName = true);
			// Returns the current task name.  If a task name has not been set
			// and fallbackToAgentName is true, the contents of fAgentName
			//is returned instead.
		
		void RemoveTaskName ();
			// Removes the task name associated with the current execution thread
			// from the internal map.
		
		// ------------------------------------
		// Accessors
		// ------------------------------------
		
		inline std::string AppName () const
			{ return fAppName; }
		
		inline StdStringList ArgList () const
			{ return fAppArgList; }
		
		inline StdStringList_const_iter ArgListBegin () const
			{ return fAppArgList.begin(); }
		
		inline StdStringList_const_iter ArgListEnd () const
			{ return fAppArgList.end(); }
		
		inline unsigned long ArgListCount ()
			{ return fAppArgList.size(); }
		
		inline std::string AppSignature () const
			{ return fAppSignature; }
		
		inline std::string LogDirectory () const
			{ return fLogDir; }
		
		inline std::string ErrorLogPath () const
			{ return fErrorLogFileObj.Path(); }
		
		inline std::string MessagesLogPath () const
			{ return fMessagesLogFileObj.Path(); }
		
		inline std::string AgentName () const
			{ return fAgentName; }
		
		inline void SetAgentName (const std::string& agentName)
			{ fAgentName = agentName; }
		
		inline std::string ServerNonce () const
			{ return fServerNonce; }
		
		inline void SetServerNonce (const std::string& serverNonce)
			{ fServerNonce = serverNonce; }
		
		inline std::string ConfFileLoc () const
			{ return fConfigFileLoc; }	
			
		inline void SetConfFileLoc (const std::string& confFileLoc)
			{ fConfigFileLoc = confFileLoc; }
			
		inline unsigned long long DynamicDebugFlags () const
			{ return fDynDebugFlags; }
		
		inline void SetDynamicDebugFlag (unsigned long long flag)
			{ fDynDebugFlags |= flag; }
		
		inline uid_t LogUserID () const
			{ return fLogUserID; }
		
		void SetLogUser (uid_t userID);
		
		void SetLogUser (const std::string& userName);
		
		inline gid_t LogGroupID () const
			{ return fLogGroupID; }
		
		void SetLogGroup (gid_t groupID);
		
		void SetLogGroup (const std::string& groupName);
		
		inline pid_t AppPID () const
			{ return fAppPID; }
		
		inline void SetAppPID (pid_t appPID)
			{ fAppPID = appPID; }
		
		inline void MarkAsDaemon (bool isDaemon)
			{ fIsDaemon = isDaemon; }
		
		inline bool IsDaemon () const
			{ return fIsDaemon; }
	
	private:
		
		std::string								fAppName;
		StdStringList							fAppArgList;
		std::string								fAppSignature;
		std::string								fLogDir;
		TLogFileObj								fErrorLogFileObj;
		TLogFileObj								fMessagesLogFileObj;
		std::string								fAgentName;
		TaskNameMap								fTaskNameMap;
		TPthreadMutexObj						fTaskNameMapMutex;
		std::string								fServerNonce;
		std::string								fConfigFileLoc;
		unsigned long long						fDynDebugFlags;
		uid_t									fLogUserID;
		gid_t									fLogGroupID;
		pid_t									fAppPID;
		bool									fIsDaemon;
};

//---------------------------------------------------------------------
// Global Template Functions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// NumToString
//---------------------------------------------------------------------
template <typename T>
inline std::string NumToString (T num)
{
	std::string				numStr;
	std::ostringstream		tempStringStream;
	
	if (tempStringStream << num)
		numStr = tempStringStream.str();
	
	return numStr;
}

template <>
inline std::string NumToString<double> (double num)
{
	std::string				numStr;
	std::ostringstream		tempStringStream;
	
	if (tempStringStream << std::setprecision(16) << num)
		numStr = tempStringStream.str();
	
	return numStr;
}

template <>
inline std::string NumToString<float> (float num)
{
	std::string				numStr;
	std::ostringstream		tempStringStream;
	
	if (tempStringStream << std::setprecision(16) << num)
		numStr = tempStringStream.str();
	
	return numStr;
}

//---------------------------------------------------------------------
// BitTest
//---------------------------------------------------------------------
template <typename T1, typename T2>
inline bool BitTest (const T1& testValue, const T2& bitValue)
{
	return (static_cast<T2>(testValue) & bitValue) != 0;
}

//---------------------------------------------------------------------
// Global Function Declaration
//---------------------------------------------------------------------

void LibraryInit (int argc, char** argv, const std::string& agentName);
	// Sets up a few globals, blah blah blah.  Should be called with
	// the arguments given to main().

void WriteToErrorLogFile (const std::string& logEntry);
	// Writes the argument to the current error log file.

void WriteToMessagesLogFile (const std::string& logEntry);
	// Writes the argument to the current messages log file.

TFileObj PIDFileObj ();
	// Returns a TFileObj pointing to the PID file for this application.
	// Note that the file might not exist; this function merely constructs
	// the right kind of file object.

void CreatePIDFile ();
	// Creates a PID file for the current application in standard location
	// for such files.

unsigned long ReadPIDFile ();
	// Reads the contents of the PID file created by CreatePIDFile().  If the
	// file does not exist then zero is returned.

void DeletePIDFile ();
	// Deletes an existing PID file for the application.  Will not throw an error
	// if the file does not exist.

void Compress (const std::string& inBuffer, std::string& outBuffer, CompressionMode mode);
	// Compresses the contents of inBuffer using the mode indicated by
	// the mode argument, destructively modifying outBuffer to contain
	// the result.  Will throw exceptions for failures.

void Compress (std::string& buffer, CompressionMode mode);
	// Same as above, except the compressed data overwrites the original.

std::string AsCompressed (const std::string& buffer, CompressionMode mode);
	// Compresses the data in buffer according to the scheme indicated by
	// mode, returning the results in a new temporary buffer.

void ZLibCompress (const std::string& inBuffer, std::string& outBuffer, bool forGZip = false);
	// Compresses the contents of inBuffer using zLib, destructively
	// modifying outBuffer to contain the results.  Will throw exceptions
	// for failures.  The forGZip argument, if true, tells the function to
	// omit the normal zlib header/footer from the compressed package.

void ZLibCompress (std::string& buffer, bool forGZip = false);
	// Same as above, except the compressed data overwrites the original.

std::string AsZLibCompressed (const std::string& dataBuffer, bool forGZip = false);
	// Same as above, except the compressed data is returned in a temporary
	// std::string.

void GZipCompress (const std::string& inBuffer, std::string& outBuffer);
	// Compresses the contents of inBuffer using zLib, then wraps the result
	// in a gzip-compatible envelope.  The results are written to outBuffer,
	// destructively modifying it.

void GZipCompress (std::string& buffer);
	// Same as above, except the compressed data overwrites the original.

std::string AsGZipCompressed (const std::string& dataBuffer);
	// Performs a zLib-based compression on the argument, returning the
	// result.  Will throw exceptions in the event of failures.

void Expand (const std::string& inBuffer, std::string& outBuffer, CompressionMode mode);
	// Expands the contents of inBuffer using the mode indicated by
	// the mode argument, destructively modifying outBuffer to contain
	// the result.  Will throw exceptions for failures.

void Expand (std::string& buffer, CompressionMode mode);
	// Same as above, except the expanded data overwrites the original.

std::string AsExpanded (const std::string& buffer, CompressionMode mode);
	// Expands the data in buffer according to the scheme indicated by
	// mode, returning the results in a new temporary buffer.

void ZLibExpand (const std::string& inBuffer, std::string& outBuffer);
	// Expands the contents of inBuffer using zLib, destructively
	// modifying outBuffer to contain the results.  Will throw exceptions
	// for failures.

void ZLibExpand (std::string& buffer);
	// Same as above, except the expanded data overwrites the original.

std::string AsZLibExpanded (const std::string& dataBuffer);
	// Performs a zLib-based expansion on the argument, returning the
	// result.  Will throw exceptions in the event of failures.

void SplitStdString (char delimiter, const std::string& s, StdStringList& stdStringList, bool includeEmpties = true);
	// Function parses the string 's', splitting it into a list of strings
	// delimited by character 'delimiter'.  The 'stdStringList' argument
	// is destructively modified to contain the result.  If 'includeEmpties'
	// is true then zero-length strings will be inserted into the result
	// list; otherwise, zero-length strings are ignored.

void SplitStdString (const std::string& delimiter, std::string s, StdStringList& stdStringList, bool includeEmpties = true);
	// Just like the previous version except this one splits the given field
	// on a string, not a character.

std::string JoinStdStringList (char delimiter, const StdStringList& stdStringList);
	// Returns a temporary string composed of all the elements of stdStringList
	// concatenated together with the character delimiter separating them.

double StringToNum (const std::string& s);
	// Converts the argument to a double, which can be coerced to any
	// numeric type the caller needs.

gid_t MapGroupNameToGID (const char* groupName);
	// Linux-specific function.  Given a group name, this function
	// returns the corresponding group ID.  Zero is returned on error.

uid_t MapUserNameToUID (const char* userName);
	// Linux-specific function.  Given a user name, this function
	// returns the corresponding user ID.  Zero is returned on error.

int OpenWithoutInterrupts (const char *pathname, int flags);
	// Calls the kernel open() function in an interrupt-aware manner.

int OpenWithoutInterrupts (const char *pathname, int flags, mode_t mode);
	// Calls the kernel open() function in an interrupt-aware manner.

int CreatWithoutInterrupts (const char *pathname, mode_t mode);
	// Calls the kernel creat() function in an interrupt-aware manner.

void CloseWithoutInterrupts (int fd, bool throwOnError = true);
	// Calls the kernel close() function in an interrupt-aware manner.

void Pause (double seconds);
	// Calls the equivalent of sleep() with the argument, which can be
	// fractional seconds, but with the best resolution timer possible
	// according to the platform.

void RandomBytes (size_t bytesToGet, char* outBuffer, bool canBlock = false);
	// Obtains bytesToGet number of random bytes, placing them into the
	// location pointed to by outBuffer.  If canBlock is false, the bytes
	// are pulled from /dev/urandom; if true, /dev/random is used.  If
	// either source cannot fulfill the entire request then the balance
	// is made up by iterative calls to rand().

unsigned long RandomULong (bool canBlock = false);
	// Returns a random unsigned long integer, using RandomBytes() as
	// a source.

int16_t ByteSwapped (const int16_t& n);
	// Returns a copy of the argument with its bytes swapped.

uint16_t ByteSwapped (const uint16_t& n);
	// Returns a copy of the argument with its bytes swapped.

int32_t ByteSwapped (const int32_t& n);
	// Returns a copy of the argument with its bytes swapped.

uint32_t ByteSwapped (const uint32_t& n);
	// Returns a copy of the argument with its bytes swapped.

int64_t ByteSwapped (const int64_t& n);
	// Returns a copy of the argument with its bytes swapped.

uint64_t ByteSwapped (const uint64_t& n);
	// Returns a copy of the argument with its bytes swapped.

template <class NUMBER_CLASS>
void LittleEndianToNative (NUMBER_CLASS& n)
	{
		#if WORDS_BIGENDIAN
			if (sizeof(n) > 1)
				n = ByteSwapped(n);
		#endif
	}

template <class NUMBER_CLASS>
void BigEndianToNative (NUMBER_CLASS& n)
	{
		#if !WORDS_BIGENDIAN
			if (sizeof(n) > 1)
				n = ByteSwapped(n);
		#endif
	}

template <class NUMBER_CLASS>
void NativeToLittleEndian (NUMBER_CLASS& n)
	{
		#if WORDS_BIGENDIAN
			if (sizeof(n) > 1)
				n = ByteSwapped(n);
		#endif
	}

template <class NUMBER_CLASS>
void NativeToBigEndian (NUMBER_CLASS& n)
	{
		#if !WORDS_BIGENDIAN
			if (sizeof(n) > 1)
				n = ByteSwapped(n);
		#endif
	}

template <class NUMBER_CLASS>
NUMBER_CLASS NativeFromLittleEndian (const NUMBER_CLASS& n)
	{
		NUMBER_CLASS	newN;
		
		#if WORDS_BIGENDIAN
			if (sizeof(n) > 1)
				newN = ByteSwapped(n);
			else
				newN = n;
		#else
			newN = n;
		#endif
		
		return newN;
	}

template <class NUMBER_CLASS>
NUMBER_CLASS NativeFromBigEndian (const NUMBER_CLASS& n)
	{
		NUMBER_CLASS	newN;
		
		#if !WORDS_BIGENDIAN
			if (sizeof(n) > 1)
				newN = ByteSwapped(n);
			else
				newN = n;
		#else
			newN = n;
		#endif
		
		return newN;
	}

template <class NUMBER_CLASS>
NUMBER_CLASS LittleEndianFromNative (const NUMBER_CLASS& n)
	{
		NUMBER_CLASS	newN;
		
		#if WORDS_BIGENDIAN
			if (sizeof(n) > 1)
				newN = ByteSwapped(n);
			else
				newN = n;
		#else
			newN = n;
		#endif
		
		return newN;
	}

template <class NUMBER_CLASS>
NUMBER_CLASS BigEndianFromNative (const NUMBER_CLASS& n)
	{
		NUMBER_CLASS	newN;
		
		#if !WORDS_BIGENDIAN
			if (sizeof(n) > 1)
				newN = ByteSwapped(n);
			else
				newN = n;
		#else
			newN = n;
		#endif
		
		return newN;
	}

void GetSystemLoads (double& oneMin, double& fiveMin, double& fifteenMin);
	// Destructively modifies the given arguments to contain the system
	// loads over the last one, five and fifteen minute intervals, respectively.

std::string ProcessInstanceID ();
	// Returns the current internal process/thread ID as a temporary string.

bool ForkDaemon ();
	// Function performs the necessary forks and environmental setup
	// to create a daemon running alongside the current application.
	// Returns true if the current process is now the daemon, false
	// if it is the original application.

bool BecomeDaemon ();
	// Function performs the necessary forks and environmental setup
	// to turn the current application into a daemon.  Returns true
	// if the current process is now a daemon.

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

#endif // SYMLIB_UTILS

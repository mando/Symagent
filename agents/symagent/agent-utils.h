/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		UberAgent file
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					18 Dec 2003
#		Last Modified:				17 Aug 2004
#		
#######################################################################
*/

#if !defined(UBERAGENT_UTILS)
#define UBERAGENT_UTILS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "agent-config.h"

#include "agent-defs.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <iomanip>
#include <iostream>
#include <sstream>

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef	enum
	{
		kRunStateUnknown = 0,
		kRunStateRun,
		kRunStateStop,
		kRunStateTerminate,
		kRunStateRestart,
	}	AgentRunState;

//---------------------------------------------------------------------
// Global Template Function
//---------------------------------------------------------------------

bool DoMainEventLoop ();
	// Returns true if the main event loop in the application should run,
	// false otherwise.

AgentRunState CurrentRunState ();
	// Returns the current run state indicator.

void SetRunState (AgentRunState newRunState);
	// Sets the current run state to the argument's value.

double StringToNumber (const string& s);
	// Converts the argument to a double, which can be coerced to any
	// numeric type the caller needs.

void LogSignalAndReraise (int sigNum);
	// Default signal handler, which simply logs the signal and
	// re-raises it.

void SetSignalHandlers (int oneSigNum = 0);
	// Sets up our signal handlers.  If a signal is provided as an
	// argument, only that signal is set.

void GetLoadInformation (double& oneMin, double& fiveMin, double& fifteenMin);
	// Gets the current system load information, destructively
	// modifying the arguments to contain the results.

bool VerifyExactFilePerms (const string& filePath, mode_t exactPerms, uid_t ownerID);
	// Function checks the permissions on the file indicated by the filePath
	// argument against the value of exactPerms, returning true if they
	// are an exact match, false otherwise.

int GetSystemLimit (RESOURCE_LIMIT_TYPE resource);
	// Returns the current limit of the given resource.

void MaxSystemLimit (RESOURCE_LIMIT_TYPE resource);
	// Tries to increase the current user's system limit, cited as
	// the argument.  Does not throw an exception if it fails.

//---------------------------------------------------------------------
// NumberToString
//---------------------------------------------------------------------
template <typename T>
inline string NumberToString (T num)
{
	string				numStr;
	std::ostringstream		tempStringStream;
	
	if (tempStringStream << num)
		numStr = tempStringStream.str();
	
	return numStr;
}

template <>
inline string NumberToString<double> (double num)
{
	string				numStr;
	std::ostringstream		tempStringStream;
	
	if (tempStringStream << std::setprecision(16) << num)
		numStr = tempStringStream.str();
	
	return numStr;
}

template <>
inline string NumberToString<float> (float num)
{
	string				numStr;
	std::ostringstream		tempStringStream;
	
	if (tempStringStream << std::setprecision(16) << num)
		numStr = tempStringStream.str();
	
	return numStr;
}

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

//---------------------------------------------------------------------
#endif // UBERAGENT_UTILS

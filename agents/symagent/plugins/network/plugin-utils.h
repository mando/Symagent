/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Plugin to report network activity in realtime
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					18 Dec 2003
#		Last Modified:				22 Apr 2004
#		
#######################################################################
*/

#if !defined(PLUGIN_UTILS)
#define PLUGIN_UTILS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"

#include <errno.h>
#include <iomanip>
#include <iostream>
#include <sstream>

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
struct	ModEnviron
	{
		ModEnviron*		parentEnvironPtr;
		bool			runState;
		
		bool GetRunState () { return runState && (!parentEnvironPtr || parentEnvironPtr->GetRunState()); }
		void SetRunState (bool newState)
			{
				runState = newState;
				if (parentEnvironPtr && newState)
					parentEnvironPtr->SetRunState(newState);
			}
	};

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

void InitModEnviron ();
	// Initializes our per-thread environmental variable.  This function
	// can be called from the plugin's AgentEnvironment() function.

void DestroyModEnviron (void* arg);
	// Function automatically called when our thread terminates to destroy
	// the environmental variable.

void CreateModEnviron (ModEnviron* parentEnvironPtr = NULL);
	// Function populates the environmental variable for the current thread.
	// Until this function is called, the environment variable will be NULL.

ModEnviron* GetModEnviron ();
	// Returns a pointer to the environmental variable specific to the calling
	// thread.

bool DoPluginEventLoop ();
	// Returns true if the main event loop in the application should run,
	// false otherwise.

void SetRunState (bool newState);
	// Sets the run state to either true or false.

double StringToNum (const std::string& s);
	// Converts the argument to a double, which can be coerced to any
	// numeric type the caller needs.

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
#endif // PLUGIN_UTILS

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
#		Created:					11 Jan 2004
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

void SplitStdString (char delimiter, const string& s, StdStringList& stdStringList, bool includeEmpties = true);
	// Function parses the string 's', splitting it into a list of strings
	// delimited by character 'delimiter'.  The 'stdStringList' argument
	// is destructively modified to contain the result.  If 'includeEmpties'
	// is true then zero-length strings will be inserted into the result
	// list; otherwise, zero-length strings are ignored.

void SplitStdString (const string& delimiter, string s, StdStringList& stdStringList, bool includeEmpties = true);
	// Just like the previous version except this one splits the given field
	// on a string, not a character.

string JoinStdStringList (char delimiter, const StdStringList& stdStringList);
	// Returns a temporary string composed of all the elements of stdStringList
	// concatenated together with the character delimiter separating them.

void Trim (string& s);
	// Destructively modifies the argument by trimming whitespace characters
	// from the beginning and end.

void MakeLowerCase (string& s);
	// Destructively modifies the argument by lowercasing all alphabetic
	// characters.

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

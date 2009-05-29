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
#		Last Modified:				23 Mar 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-utils.h"

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Module Global Variables
//---------------------------------------------------------------------
static	pthread_key_t									gEnvironKey;
static	ModEnviron*										gMainModEnvironPtr = NULL;

//---------------------------------------------------------------------
// InitModEnviron
//---------------------------------------------------------------------
void InitModEnviron ()
{
	int		errNum = 0;
	
	errNum = pthread_key_create(&gEnvironKey,DestroyModEnviron);
	if (errNum != 0)
		throw TSymLibErrorObj(errNum,"Unable to initialize thread environment");
	
	// Setup a toplevel environmental pointer
	CreateModEnviron();
	SetRunState(true);
	gMainModEnvironPtr = GetModEnviron();
}

//---------------------------------------------------------------------
// DestroyModEnviron
//---------------------------------------------------------------------
void DestroyModEnviron (void* arg)
{
	if (arg)
		delete(reinterpret_cast<ModEnviron*>(arg));
}

//---------------------------------------------------------------------
// CreateModEnviron
//---------------------------------------------------------------------
void CreateModEnviron (ModEnviron* parentEnvironPtr)
{
	ModEnviron*		environPtr = new ModEnviron;
	int				errNum = 0;
	
	if (!parentEnvironPtr && gMainModEnvironPtr)
		parentEnvironPtr = gMainModEnvironPtr;
	
	environPtr->parentEnvironPtr = parentEnvironPtr;
	if (parentEnvironPtr)
		environPtr->runState = parentEnvironPtr->runState;
	else
		environPtr->runState = false;
	
	errNum = pthread_setspecific(gEnvironKey,environPtr);
	if (errNum != 0)
	{
		delete(environPtr);
		throw TSymLibErrorObj(errNum,"Unable to initialize thread environment");
	}
}

//---------------------------------------------------------------------
// GetModEnviron
//---------------------------------------------------------------------
ModEnviron* GetModEnviron ()
{
	return static_cast<ModEnviron*>(pthread_getspecific(gEnvironKey));
}

//---------------------------------------------------------------------
// DoPluginEventLoop
//---------------------------------------------------------------------
bool DoPluginEventLoop ()
{
	bool			result = false;
	ModEnviron*		environPtr = GetModEnviron();
	
	if (environPtr)
		result = environPtr->GetRunState();
	
	return result;
}

//---------------------------------------------------------------------
// SetRunState
//---------------------------------------------------------------------
void SetRunState (bool newState)
{
	ModEnviron*		environPtr = GetModEnviron();
	
	if (environPtr)
		environPtr->SetRunState(newState);
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
// SplitStdString
//---------------------------------------------------------------------
void SplitStdString (char delimiter, const string& s, StdStringList& stdStringList, bool includeEmpties)
{
	// Clear the destination argument
	stdStringList.clear();
	
	if (!s.empty())
	{
		string		tempString;
		
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
void SplitStdString (const string& delimiter, string s, StdStringList& stdStringList, bool includeEmpties)
{
	unsigned long	foundPos = string::npos;
	
	// Clear any existing field list
	stdStringList.clear();
	
	// Remove beginning and trailing whitespaces from log line
	Trim(s);
	
	// Search for delimiter
	foundPos = s.find(delimiter);
	while (foundPos != string::npos)
	{
		if (foundPos > 0)
		{
			string	aField(s.substr(0,foundPos));
			
			// Trim the field of whitespaces
			while (!aField.empty() && isspace(aField[aField.length()-1]))
				aField.erase(aField.length()-1,1);
			while (!aField.empty() && isspace(aField[0]))
				aField.erase(0,1);
			
			stdStringList.push_back(aField);
		}
		else if (includeEmpties)
		{
			// Caller wants the empty strings
			stdStringList.push_back(string());
		}
		
		// Erase what we've parsed so far
		s.erase(0,foundPos + delimiter.length());
		
		// Search some more
		foundPos = s.find(delimiter);
	}
	
	Trim(s);
	if (!s.empty())
	{
		// Push last line onto the field list
		stdStringList.push_back(s);
	}
}

//---------------------------------------------------------------------
// JoinStdStringList
//---------------------------------------------------------------------
string JoinStdStringList (char delimiter, const StdStringList& stdStringList)
{
	string		s;
	
	for (StdStringList_const_iter x = stdStringList.begin(); x != stdStringList.end(); x++)
	{
		if (!s.empty())
			s += delimiter;
		s += *x;
	}
	
	return s;
}

//---------------------------------------------------------------------
// Trim
//---------------------------------------------------------------------
void Trim (string& s)
{
	while (!s.empty() && isspace(s[s.length()-1]))
		s.erase(s.length()-1,1);
	while (!s.empty() && isspace(s[0]))
		s.erase(0,1);
}

//---------------------------------------------------------------------
// MakeLowerCase
//---------------------------------------------------------------------
void MakeLowerCase (string& s)
{
	for (unsigned long x = 0; x < s.length(); x++)
		s[x] = tolower(s[x]);
}

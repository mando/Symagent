/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		UberAgent file - API for all Symbiot Agent plugins
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					18 Dec 2003
#		Last Modified:				26 Feb 2004
#		
#######################################################################
*/

#if !defined(SYMBIOT_PLUGIN_API)
#define SYMBIOT_PLUGIN_API

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include <map>
#include <string>
#include <vector>

//---------------------------------------------------------------------
// Namespace imports
//---------------------------------------------------------------------
using std::map;
using std::string;
using std::vector;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Begin C Environment
//---------------------------------------------------------------------
#if defined(__cplusplus)
	extern "C" {
#endif

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

string AgentName ();
	// Returns the short name of this agent.

string AgentVersion ();
	// Returns the version of this agent.  The format of this string
	// should be MM.mm.bb where:
	//		MM = Major release number
	//		mm = Minor release number
	//		bb = Bug fix/patch release number
	// It is permissible to append alpha/beta indicators (eg, "a3" or
	// "b1") to the string as well.

string AgentDescription ();
	// Returns a description of this agent's functionality.  Return
	// an empty string if you don't want to supply a description.

void AgentEnvironment (TLoginDataNode& loginEnvNode);
	// This function is called before AgentInit.  Its purpose is to
	// provide the plugin an opportunity to report environmental
	// information to the server during the login process, information
	// which may affect the preference information that will be
	// supplied to the plugin later, during the call to AgentInit.  An
	// example could be a network sniffing plugin that needs to tell
	// the server what network interfaces are available so that the
	// server can then intelligently indicate which ones need to
	// be sniffed.  If the plugin chooses to supply information then
	// it should embed that information into the loginEnvNode object
	// provide as the argument.
	//
	// Note that this function is called only once per agent/plugin
	// load.  Therefore, this is an acceptable place to do any
	// global memory initialization or whatever.

bool AgentInit (const TPreferenceNode& preferenceNode);
	// Function will be called by the controlling application if the
	// plugin needs to be initialized.  The argument represents the top
	// node of an XML block containing configuration/preference data
	// for the plugin.  Return true if initialization was successful,
	// false otherwise.

void AgentRun ();
	// Entry point for the agent's function.  Agents can assume that
	// AgentInit() has been called and that it returned true before
	// this function is called.

void AgentStop ();
	// Function will be called by the controlling application when
	// the agent should stop execution for any reason.  Agents should
	// periodically check to see if this function has been called and
	// then terminate gracefully if at all possible.  This function
	// will be called only in a threaded execution context.

//---------------------------------------------------------------------
// End C Environment
//---------------------------------------------------------------------
#if defined(__cplusplus)
	}
#endif

//---------------------------------------------------------------------
#endif // SYMBIOT_PLUGIN_API

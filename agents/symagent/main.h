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
#		Last Modified:				07 Jan 2005
#		
#######################################################################
*/

#if !defined(UBERAGENT_MAIN)
#define UBERAGENT_MAIN

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "agent-config.h"
#include "agent-defs.h"
#include "agent-utils.h"

#include "plugin-manager.h"

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

bool Initialize (TPluginMgr& pluginMgrObj);
	// Initializes the environment based on plugins found and information
	// located in the configuration file.

bool EnablePlugin (TPluginMgr& pluginMgrObj, TPreferenceNode& pluginPrefNode, bool runIfActivated = false);
	// Enables a plugin described by the pluginPrefNode argument.  If
	// runIfActivated is true then the plugin is executed if it is successfully
	// enabled.  Returns true if the plugin was actually enabled, false otherwise.

void DisablePlugin (TPluginMgr& pluginMgrObj, TPreferenceNode& pluginPrefNode);
	// Disables a plugin described by the pluginPrefNode argument.

void Run (TPluginMgr& pluginMgrObj);
	// Launches enabled plugins and enters the main event loop.

void CreateLoginMessageAddendum (TLoginDataNode& pluginDescNode, TPluginMgr& pluginMgrObj);
	// Destructively modifies the first argument to contain the extra
	// XML required to supply the server with plugin information.

void ServerCommandDispatch (TServerReply& serverCommand, TPluginMgr& pluginMgrObj);
	// Processes inbound server commands.

void ShowVersion (int argc, char** argv);
	// Displays version information via stdout.

void StopAllPlugins (TPluginMgr& pluginMgrObj, bool restartOnTimeout);
	// Stops all running plugins.  If restartOnTimeout is true then, if the plugins do
	// not stop within a reasonable amount of time, RestartAgentFromNewInstance() is called
	// to ensure that a running symagent is always available.

void RestartAgentFromNewInstance (int sigNum);
	// Relaunches a new instance the agent using the same command parameters that were used
	// to launch this instance.  The new instance will summarily kill this one and take over
	// operations.  The argument to this function is ignored.

void ShowHelp (int argc, char** argv);
	// Displays help information via stdout.

void DoCommunicationTest ();
	// If the application receives a certain command-line argument
	// (as defined by kAppArgCommTest) then perform a communication
	// test with the server and then quit.  Results from the test
	// will be piped to stdout.

//---------------------------------------------------------------------
#endif // UBERAGENT_MAIN

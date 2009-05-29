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
#		Last Modified:				14 Mar 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "main.h"

#include "agent-heartbeat.h"

#if HAVE_LIBGEN_H
	#include <libgen.h>
#endif
#include <iostream>
#include <signal.h>
#include <unistd.h>

//---------------------------------------------------------------------
// Import the std namespace for convenience
//---------------------------------------------------------------------
using namespace std;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define	kLibSymVersionMin						0x010100L

#define	kAppArgCommTest							"--comm-test"
#define	kAppArgVersionLong						"--version"
#define	kAppArgVersionShort						"-v"
#define	kAppArgHelpLong							"--help"
#define	kAppArgHelpShort						"-h"

#define	kMessageTagHeartbeat					"HEARTBEAT_INTERVAL"
#define	kMessageAttributeHeartbeatValue				"value"

#define	kMessageTagAvailPlugins					"AVAIL_PLUGINS"

#define	kMessageTagActivatePlugins				"ENABLE_PLUGINS"

#define	kMessageTagCommand						"COMMAND"
#define	kMessageTagCommandEnablePlugins				kMessageTagActivatePlugins
#define	kMessageTagCommandDisablePlugins			"DISABLE_PLUGINS"
#define	kMessageTagCommandShutdown					"SHUTDOWN"
#define	kMessageTagCommandRestart					"RESTART"

#define	kMessageTagPlugin						"PLUGIN"
#define	kMessageAttributePluginName					"name"
#define	kMessageAttributePluginVersion				"version"
#define	kMessageAttributePluginSig					"signature"
#define	kMessageTagPluginConfig						"CONFIG"

#define	kDebugModeOn							0
#define	kDebugPluginName						"symplugin-mac-lookup"

//---------------------------------------------------------------------
// Module Global Variables
//---------------------------------------------------------------------
static bool										gHeartbeatEnabled = false;

//---------------------------------------------------------------------
// main
//---------------------------------------------------------------------
int main (int argc, char** argv)
{
	int			result = 0;
	bool		libInited = false;
	
	// Make sure we have the right version of the libsymbiot library
	// Runtime check
	if (SymLibVersion() < kLibSymVersionMin)
	{
		cerr << "Error: Incompatible version of libsymbiot detected" << endl << flush;
		exit(1);
	}
	
	if (argc == 2 && (strcasecmp(argv[1],kAppArgVersionLong) == 0 || strcasecmp(argv[1],kAppArgVersionShort) == 0))
	{
		ShowVersion(argc,argv);
	}
	else if (argc == 2 && (strcasecmp(argv[1],kAppArgHelpLong) == 0 || strcasecmp(argv[1],kAppArgHelpShort) == 0))
	{
		ShowHelp(argc,argv);
	}
	else
	{
		try
		{
			// Initialize the Symbiot Agent Library
			if (SymLibInit(argc,argv,kUberAgentName))
			{
				#if defined(REQUIRE_SUPER_USER) && REQUIRE_SUPER_USER
					// Make sure we have the correct permissions
					if (getuid() != 0)
					{
						string	errString;
						
						errString = "Agent requires super-user permissions ";
						errString += "(user " + NumberToString(getuid()) + " made the attempt)";
						throw TSymLibErrorObj(kErrorRequiresSuperUserPerms,errString);
					}
				#endif
				
				// Make sure our plugin directory has the right permissions
				if (!VerifyExactFilePerms(PLUGIN_PATH,S_IRWXU,getuid()))
				{
					string		errString;
					
					errString = "Plugin directory '";
					errString += PLUGIN_PATH;
					errString += "' does not have the correct permissions";
					throw TSymLibErrorObj(kErrorPluginDirPermissionsBad,errString);
				}
				
				libInited = true;
				
				// Pump up our resource allocations
				#if HAVE_DECL_RLIMIT_CORE
					MaxSystemLimit(RLIMIT_CORE);
				#endif
				#if HAVE_DECL_RLIMIT_CPU
					MaxSystemLimit(RLIMIT_CPU);
				#endif
				#if HAVE_DECL_RLIMIT_DATA
					MaxSystemLimit(RLIMIT_DATA);
				#endif
				#if HAVE_DECL_RLIMIT_FSIZE
					MaxSystemLimit(RLIMIT_FSIZE);
				#endif
				#if HAVE_DECL_RLIMIT_MEMLOCK
					MaxSystemLimit(RLIMIT_MEMLOCK);
				#endif
				#if HAVE_DECL_RLIMIT_NOFILE
					MaxSystemLimit(RLIMIT_NOFILE);
				#endif
				#if HAVE_DECL_RLIMIT_NPROC
					MaxSystemLimit(RLIMIT_NPROC);
				#endif
				#if HAVE_DECL_RLIMIT_RSS
					MaxSystemLimit(RLIMIT_RSS);
				#endif
				#if HAVE_DECL_RLIMIT_STACK
					MaxSystemLimit(RLIMIT_STACK);
				#endif
				
				if (DoesApplicationArgExist(kAppArgCommTest))
				{
					// Perform the server communication test and bail
					DoCommunicationTest();
				}
				else
				{
					TPluginMgr		pluginMgrObj;
					PluginSigMap	pluginSigMap;
					StdStringList	validPluginList;
					
					// Locate our plugins
					pluginMgrObj.LocatePlugins(pluginSigMap);
					
					// еее Perform comparison between found plugins/signatures with information
					// еее found within the agent SSL certificate
					
					// Construct the list of valid plugins
					for (PluginSigMap_const_iter x = pluginSigMap.begin(); x != pluginSigMap.end(); x++)
					{
						string		pluginPath(x->first);
						string		pluginSig(x->second);
						
						validPluginList.push_back(pluginPath);
					}
					
					// Load the valid plugins
					pluginMgrObj.LoadPlugins(validPluginList);
					
					do
					{
						TLoginDataNode	pluginDescNode(kMessageTagAvailPlugins);
						bool			haveConnection = false;
						bool			agentInited = false;
						bool			errorOccurred = false;
						bool			okToTerminate = false;
						double			onErrorWaitInSeconds = 30;
						
						gHeartbeatEnabled = false;
						
						// Init our signal handlers
						SetSignalHandlers();
						
						// Initialize the login addendum information
						CreateLoginMessageAddendum(pluginDescNode,pluginMgrObj);
						
						try
						{
							// Connect with server
							ConnectToServer(pluginDescNode);
							
							if (IsConnectedToServer())
							{
								haveConnection = true;
								
								// Initialize
								agentInited = Initialize(pluginMgrObj);
								
								if (agentInited)
								{
									// Execute the plugins' code
									Run(pluginMgrObj);
									
									// Stop our plugins -- note that if we get
									// here then this is a "normal" shutdown
									okToTerminate = true;
									StopAllPlugins(pluginMgrObj,(CurrentRunState() != kRunStateStop && CurrentRunState() != kRunStateTerminate));
									
									switch (CurrentRunState())
									{
										case kRunStateTerminate:
											ClearTaskQueues(false,false);
											break;
										
										case kRunStateStop:
											ClearTaskQueues(true,false);
											break;
										
										case kRunStateRestart:
											ClearTaskQueues(true,true);
											break;
										
										default:
											break;
									}
								}
								
								// Disconnect from the server
								DisconnectFromServer();
							}
						}
						catch (TSymLibErrorObj& errObj)
						{
							if (!errObj.IsLogged())
							{
								WriteToErrorLog(errObj.GetDescription());
								errObj.MarkAsLogged();
							}
							
							// Send error message to cerr if we're not running as a daemon
							if (!RunningAsDaemon())
								cerr << "Error: " << errObj.GetError() << ": " << errObj.GetDescription() << endl << flush;
							
							try
							{
								// Stop our plugins
								StopAllPlugins(pluginMgrObj,true);
								// Disconnect from the server
								DisconnectFromServer();
							}
							catch (...)
							{
								// Absorb errors
							}
							
							switch (errObj.GetError())
							{
								case kErrorAgentNotProvisioned:
									{
										string	errString;
										
										errString = errObj.GetDescription() + " -- will retry connection";
										WriteToMessagesLog(errString);
										errorOccurred = true;
										onErrorWaitInSeconds = 60;
									}
									break;
								
								case kErrorDBUnavailable:
								case kErrorServerUnavailable:
								case kErrorServerCommunicationTimeout:
								case kErrorBadServerResponse:
									{
										string	errString;
										
										errString = errObj.GetDescription() + " -- will retry connection";
										WriteToMessagesLog(errString);
										errorOccurred = true;
										onErrorWaitInSeconds = 30;
									}
									break;
								
								default:
									if (!okToTerminate)
									{
										// We received a strange error and we're supposed to
										// stay running
										string	errString;
										
										errString = errObj.GetDescription() + " -- will launch new agent";
										WriteToMessagesLog(errString);
										
										try
										{
											// Stop our plugins
											StopAllPlugins(pluginMgrObj,true);
											// Disconnect from the server
											DisconnectFromServer();
										}
										catch (...)
										{
											// Absorb errors
										}
										
										// Since we can't depend on our environment, spawn
										// a new instance of the agent
										RestartAgentFromNewInstance(0);
									}
									else if (haveConnection && !agentInited)
									{
										// We connected okay but the init failed; re-throw exception
										throw;
									}
									break;
							}
						}
						
						if (errorOccurred || (DoMainEventLoop() && !IsConnectedToServer()))
						{
							// We need to just wait for a little while first ...
							if (onErrorWaitInSeconds > 0)
								PauseExecution(onErrorWaitInSeconds);
						}
						
						// Let's relaunch another instance of ourselves to make
						// sure our memory is cleaned up appropriately (damned pthreads...)
						if (CurrentRunState() != kRunStateStop && CurrentRunState() != kRunStateTerminate)
						{
							// SetRunState(kRunStateRun);
							RestartAgentFromNewInstance(0);
						}
					}
					while (DoMainEventLoop());
				}
			}
		}
		catch (TSymLibErrorObj& errObj)
		{
			if (!errObj.IsLogged())
			{
				WriteToErrorLog(errObj.GetDescription());
				errObj.MarkAsLogged();
			}
			
			if (!RunningAsDaemon())
				cerr << "Error: " << errObj.GetError() << ": " << errObj.GetDescription() << endl << flush;
			result = 1;
		}
		catch (...)
		{
			if (!RunningAsDaemon())
				cerr << "Uncaught, unknown error" << endl << flush;
			result = 1;
		}
		
		if (libInited)
		{
			// Allow the Symbiot Agent Library to take down any structures
			SymLibCleanup();
		}
	}
	
	return result;
}

//---------------------------------------------------------------------
// Initialize
//---------------------------------------------------------------------
bool Initialize (TPluginMgr& pluginMgrObj)
{
	bool				initialized = false;
	TPreferenceNode		prefRootNode(GetPreferenceNode());
	TPreferenceNode		nodeRef;
	string				logMessage;
	unsigned long		pluginsActivated = 0;
	
	if (prefRootNode.IsValid())
	{
		// Find the list of plugins we should be activating
		nodeRef = prefRootNode.FindNode(kMessageTagActivatePlugins);
		
	#if kDebugModeOn
		// Only one plugin, named by kDebugPluginName, will be initialized and enabled
		{
			TPreferenceNode		pluginConfigRef;
			TPlugin*			pluginPtr = pluginMgrObj.GetPluginPtr(kDebugPluginName);
			
			if (pluginPtr)
			{
				pluginPtr->AgentInit(pluginConfigRef);
				pluginPtr->MarkAsActivated();
				++pluginsActivated;
				
				logMessage = "DEBUGGING MODE:  Activating plugin '";
				logMessage += kDebugPluginName;
				logMessage += "'";
				WriteToMessagesLog(logMessage);
			}
			else
			{
				logMessage = "DEBUGGING MODE:  Did not find plugin '";
				logMessage += kDebugPluginName;
				logMessage += "'";
				WriteToMessagesLog(logMessage);
			}
		}
	#else
		if (nodeRef.IsValid())
		{
			for (unsigned long x = 0; x < nodeRef.SubnodeCount(); x++)
			{
				TPreferenceNode		pluginPrefNode(nodeRef.GetNthSubnode(x));
				
				if (EnablePlugin(pluginMgrObj,pluginPrefNode))
					++pluginsActivated;
			}
		}
	#endif
		
		initialized = true;
	}
	
	logMessage = "";
	logMessage += "Total of " + NumberToString(pluginsActivated) + " plugin";
	if (pluginsActivated != 1)
		logMessage += "s";
	logMessage += " activated";
	WriteToMessagesLog(logMessage);
	
	if (initialized)
	{
		nodeRef = prefRootNode.FindNode(kMessageTagHeartbeat);
		if (nodeRef.IsValid())
		{
			time_t	intervalValue = static_cast<time_t>(StringToNumber(nodeRef.GetAttributeValue(kMessageAttributeHeartbeatValue)));
			
			// Default the heartbeat interval to 60 seconds if it makes no sense
			if (intervalValue <= 0)
				intervalValue = 60;
			
			AddTaskToQueue(new THeartbeat(intervalValue),false);
			
			gHeartbeatEnabled = true;
		}
	}
	
	return initialized;
}

//---------------------------------------------------------------------
// EnablePlugin
//---------------------------------------------------------------------
bool EnablePlugin (TPluginMgr& pluginMgrObj, TPreferenceNode& pluginPrefNode, bool runIfActivated)
{
	bool		isEnabled = false;
	string		logMessage;
	
	if (pluginPrefNode.IsValid() && pluginPrefNode.GetTag() == kMessageTagPlugin)
	{
		string			pluginName(pluginPrefNode.GetAttributeValue(kMessageAttributePluginName));
		TPreferenceNode	pluginConfigRef = pluginPrefNode.FindNode(kMessageTagPluginConfig);
		TPlugin*		pluginPtr = pluginMgrObj.GetPluginPtr(pluginName);
		
		if (pluginPtr)
		{
			bool	isAgentInited = false;
			
			try
			{
				isAgentInited = pluginPtr->AgentInit(pluginConfigRef);
			}
			catch (TSymLibErrorObj& errObj)
			{
				if (!errObj.IsLogged())
				{
					logMessage = "While loading plugin '" + pluginPtr->Path() + "': ";
					logMessage += errObj.GetDescription();
					
					WriteToErrorLog(logMessage);
					errObj.MarkAsLogged();
				}
				isAgentInited = false;
			}
			catch (...)
			{
				// Ignore unknown errors
				isAgentInited = false;
			}
			
			if (isAgentInited)
			{
				pluginPtr->MarkAsActivated();
				
				logMessage = "";
				logMessage += "Plugin '" + pluginPtr->Path() + "' activated as '" + pluginName + "'";
				WriteToMessagesLog(logMessage);
				
				isEnabled = true;
				
				if (runIfActivated)
					pluginPtr->AgentSpawn();
			}
			else
			{
				logMessage = "";
				logMessage += "Plugin '" + pluginPtr->Path() + "' failed initialization";
				WriteToErrorLog(logMessage);
			}
		}
		else
		{
			logMessage = "";
			logMessage += "Server requested plugin '" + pluginName + "' activation but no plugin with that name was found";
			WriteToErrorLog(logMessage);
		}
	}
	
	return isEnabled;
}

//---------------------------------------------------------------------
// DisablePlugin
//---------------------------------------------------------------------
void DisablePlugin (TPluginMgr& pluginMgrObj, TPreferenceNode& pluginPrefNode)
{
	string		logMessage;
	
	if (pluginPrefNode.IsValid() && pluginPrefNode.GetTag() == kMessageTagPlugin)
	{
		string			pluginName(pluginPrefNode.GetAttributeValue(kMessageAttributePluginName));
		TPlugin*		pluginPtr = pluginMgrObj.GetPluginPtr(pluginName);
		
		if (pluginPtr)
		{
			pluginPtr->AgentStop();
		}
		else
		{
			logMessage = "";
			logMessage += "Server requested plugin '" + pluginName + "' deactivation but no plugin with that name was found";
			WriteToErrorLog(logMessage);
		}
	}
}

//---------------------------------------------------------------------
// Run
//---------------------------------------------------------------------
void Run (TPluginMgr& pluginMgrObj)
{
	StdStringList	pluginNameList;
	unsigned long	spawnedCount = 0;
	
	pluginMgrObj.PluginNameList(pluginNameList);
	for (StdStringList_const_iter x = pluginNameList.begin(); x != pluginNameList.end(); x++)
	{
		TPlugin*	pluginPtr = pluginMgrObj.GetPluginPtr(*x);
		
		if (pluginPtr->IsActivated())
		{
			pluginPtr->AgentSpawn();
			++spawnedCount;
		}
	}
	
	if (gHeartbeatEnabled || spawnedCount > 0)
	{
		if (spawnedCount > 0)
		{
			// Wait until we have at least one agent running
			while (pluginMgrObj.RunningCount() == 0)
				PauseExecution(.5);
		}
		
		// Now keep looping while waiting for the plugins to do their thing
		while (DoMainEventLoop() &&
			   IsConnectedToServer() &&
			   (spawnedCount == 0 || pluginMgrObj.RunningCount() > 0))
		{
			TServerReply		serverCommand;
			
			PauseExecution(.5);
			
			if (GetServerCommand(serverCommand))
				ServerCommandDispatch(serverCommand,pluginMgrObj);
		}
	}
}

//---------------------------------------------------------------------
// CreateLoginMessageAddendum
//---------------------------------------------------------------------
void CreateLoginMessageAddendum (TLoginDataNode& pluginDescNode, TPluginMgr& pluginMgrObj)
{
	if (pluginMgrObj.PluginCount() > 0)
	{
		StdStringList	pluginNameList;
		
		// Create an XML node describing our plugins
		
		pluginMgrObj.PluginNameList(pluginNameList);
		for (StdStringList_const_iter x = pluginNameList.begin(); x != pluginNameList.end(); x++)
		{
			TPlugin*			pluginPtr = pluginMgrObj.GetPluginPtr(*x);
			TMessageNode		pluginNode(pluginDescNode.Append(kMessageTagPlugin,"",""));
			TLoginDataNode		pluginLoginDataNode;
			
			pluginNode.AddAttribute(kMessageAttributePluginName,pluginPtr->AgentName());
			pluginNode.AddAttribute(kMessageAttributePluginVersion,pluginPtr->AgentVersion());
			pluginNode.AddAttribute(kMessageAttributePluginSig,pluginPtr->Signature());
			
			pluginPtr->AgentEnvironment(pluginLoginDataNode);
			if (pluginLoginDataNode.IsValid())
				pluginNode.Append(pluginLoginDataNode);
		}
	}
}

//---------------------------------------------------------------------
// ServerCommandDispatch
//---------------------------------------------------------------------
void ServerCommandDispatch (TServerReply& serverCommand, TPluginMgr& pluginMgrObj)
{
	TMessageNode		commandNode;
	bool				handled = false;
	
	if (!handled)
	{
		commandNode = serverCommand.FindNode(kMessageTagCommandShutdown);
		if (commandNode.IsValid())
		{
			// Shutdown the application
			WriteToMessagesLog("Shutting down due to server command");
			SetRunState(kRunStateTerminate);
			handled = true;
		}
	}
	
	if (!handled)
	{
		commandNode = serverCommand.FindNode(kMessageTagCommandRestart);
		if (commandNode.IsValid())
		{
			// Shutdown the application
			WriteToMessagesLog("Restarting due to server command");
			SetRunState(kRunStateRestart);
			handled = true;
		}
	}
	
	if (!handled)
	{
		commandNode = serverCommand.FindNode(kMessageTagCommandDisablePlugins);
		if (commandNode.IsValid())
		{
			// We need to enable some plugins
			WriteToMessagesLog("Disabling agents due to server command");
			for (unsigned long x = 0; x < commandNode.SubnodeCount(); x++)
			{
				TPreferenceNode		pluginPrefNode(commandNode.GetNthSubnode(x));
				
				// Disable the plugin
				DisablePlugin(pluginMgrObj,pluginPrefNode);
			}
			handled = true;
		}
		
		commandNode = serverCommand.FindNode(kMessageTagCommandEnablePlugins);
		if (commandNode.IsValid())
		{
			// We need to enable some plugins
			WriteToMessagesLog("Enabling agents due to server command");
			for (unsigned long x = 0; x < commandNode.SubnodeCount(); x++)
			{
				TPreferenceNode		pluginPrefNode(commandNode.GetNthSubnode(x));
				
				// Enable and execute the plugin
				EnablePlugin(pluginMgrObj,pluginPrefNode,true);
			}
			handled = true;
		}
	}
}

//---------------------------------------------------------------------
// StopAllPlugins
//---------------------------------------------------------------------
void StopAllPlugins (TPluginMgr& pluginMgrObj, bool restartOnTimeout)
{
	if (restartOnTimeout)
	{
		struct sigaction		mySigAction;
		
		mySigAction.sa_handler = RestartAgentFromNewInstance;
		mySigAction.sa_flags = 0;
		
		sigemptyset(&mySigAction.sa_mask);
		sigaction(SIGALRM,&mySigAction,NULL);
		
		alarm(30);
	}
	
	pluginMgrObj.StopAllPlugins();
	
	if (restartOnTimeout)
	{
		struct sigaction		mySigAction;
		
		mySigAction.sa_handler = SIG_DFL;
		mySigAction.sa_flags = 0;
		
		sigemptyset(&mySigAction.sa_mask);
		sigaction(SIGALRM,&mySigAction,NULL);
		
		alarm(0);
	}
	
	pluginMgrObj.DeactivateAllPlugins();
}

//---------------------------------------------------------------------
// RestartAgentFromNewInstance
//---------------------------------------------------------------------
void RestartAgentFromNewInstance (int /* sigNum */)
{
	StdStringList	appArgList;
	
	if (ApplicationArgList(appArgList) > 0)
	{
		string		command;
		
		for (StdStringList_const_iter x = appArgList.begin(); x != appArgList.end(); x++)
		{
			if (*x != "start" && *x != "stop" && *x != "restart")
			{
				if (!command.empty())
					command += " ";
				command += *x;
			}
		}
		
		if (!command.empty())
			command += " ";
		command += "restart";
		
		if (!command.empty())
		{
			string	logString;
			
			logString = "Restart agent instance with command '" + command + "'";
			WriteToMessagesLog(logString);
			
			ExecApplication(command,"");
		}
	}
	else
	{
		WriteToMessagesLog("Could not restart agent due to missing original startup options/commands");
	}
}

//---------------------------------------------------------------------
// ShowVersion
//---------------------------------------------------------------------
void ShowVersion (int /* argc */, char** argv)
{
	unsigned long 	versionNumber = 0;
	char*			versionPtr = reinterpret_cast<char*>(&versionNumber);
	string			libVersionStr;
	string			appVersionStr;
	const int		kBufferSize = 24;	// overkill
	char			buffer[kBufferSize];
	
	memset(buffer,0,kBufferSize);
	
	// Get the library's version number and display it
	versionNumber = SymLibVersion();
	libVersionStr.clear();
	
	#if BYTEORDER == 4321
		// Big-endian; format = 00MMmmbb
		sprintf(buffer,"%u",versionPtr[1]);
		libVersionStr += buffer;
		libVersionStr += ".";
		sprintf(buffer,"%u",versionPtr[2]);
		libVersionStr += buffer;
		libVersionStr += ".";
		sprintf(buffer,"%u",versionPtr[3]);
		libVersionStr += buffer;
	#else
		// Little-endian; format = bbmmMM00
		sprintf(buffer,"%u",versionPtr[2]);
		libVersionStr += buffer;
		libVersionStr += ".";
		sprintf(buffer,"%u",versionPtr[1]);
		libVersionStr += buffer;
		libVersionStr += ".";
		sprintf(buffer,"%u",versionPtr[0]);
		libVersionStr += buffer;
	#endif
	
	// Get the agents's version number and display it
	versionNumber = AGENT_VERSION_NUMBER;
	appVersionStr.clear();
	
	#if BYTEORDER == 4321
		// Big-endian; format = 00MMmmbb
		sprintf(buffer,"%u",versionPtr[1]);
		appVersionStr += buffer;
		appVersionStr += ".";
		sprintf(buffer,"%u",versionPtr[2]);
		appVersionStr += buffer;
		appVersionStr += ".";
		sprintf(buffer,"%u",versionPtr[3]);
		appVersionStr += buffer;
	#else
		// Little-endian; format = bbmmMM00
		sprintf(buffer,"%u",versionPtr[2]);
		appVersionStr += buffer;
		appVersionStr += ".";
		sprintf(buffer,"%u",versionPtr[1]);
		appVersionStr += buffer;
		appVersionStr += ".";
		sprintf(buffer,"%u",versionPtr[0]);
		appVersionStr += buffer;
	#endif
	
	// Display both versions on one line
	#if HAVE_LIBGEN_H
		cout << basename(argv[0]);
	#else
		cout << argv[0];
	#endif
	cout << "/library versions: " << appVersionStr << "/" << libVersionStr << endl;
}

//---------------------------------------------------------------------
// ShowHelp
//---------------------------------------------------------------------
void ShowHelp (int /* argc */, char** argv)
{
	cout << "Usage: ";
	
	#if HAVE_LIBGEN_H
		cout << basename(argv[0]);
	#else
		cout << argv[0];
	#endif
	
	cout << " start|stop|restart|status" << endl;
}

//---------------------------------------------------------------------
// DoCommunicationTest
//---------------------------------------------------------------------
void DoCommunicationTest ()
{
	TPluginMgr		pluginMgrObj;
	TLoginDataNode	pluginDescNode(kMessageTagAvailPlugins);
	
	CreateLoginMessageAddendum(pluginDescNode,pluginMgrObj);
	
	try
	{
		cout << "SERVER_CONNECT\t" << flush;
		ConnectToServer(pluginDescNode);
		cout << "OK" << endl << flush;
	}
	catch (TSymLibErrorObj& errObj)
	{
		cout << "Error\t" << errObj.GetError() << "\t" << errObj.GetDescription() << endl << flush;
	}
	catch (int errNum)
	{
		cout << "Error\t" << errNum << "\t" << "OS Error Code" << endl << flush;
	}
	catch (...)
	{
		cout << "Error\t" << "-" << "\t" << "Unknown exception" << endl << flush;
	}
	
	try
	{
		cout << "SERVER_DISCONNECT\t" << flush;
		DisconnectFromServer();
		cout << "OK" << endl << flush;
	}
	catch (TSymLibErrorObj& errObj)
	{
		cout << "Error\t" << errObj.GetError() << "\t" << errObj.GetDescription() << endl << flush;
	}
	catch (int errNum)
	{
		cout << "Error\t" << errNum << "\t" << "OS Error Code" << endl << flush;
	}
	catch (...)
	{
		cout << "Error\t" << "-" << "\t" << "Unknown exception" << endl << flush;
	}
	
}

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
#		Created:					09 Sep 2003
#		Last Modified:				11 Feb 2005
#
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-api.h"

#include "symlib-app-exec.h"
#include "symlib-communicate.h"
#include "symlib-config.h"
#include "symlib-expat.h"
#include "symlib-file-watch.h"
#include "symlib-prefs.h"
#include "symlib-ssl-encode.h"
#include "symlib-ssl-digest.h"
#include "symlib-task-queue.h"
#include "symlib-tcp.h"
#include "symlib-utils.h"
#include "symlib-xml.h"

#include <signal.h>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
static TServerObj*								gServerObjPtr = NULL;

//*********************************************************************
// Functions
//*********************************************************************

//---------------------------------------------------------------------
// SymLibVersion
//---------------------------------------------------------------------
unsigned long SymLibVersion ()
{
	return LIBSYMBIOT_VERSION_NUMBER;
}

//---------------------------------------------------------------------
// SymLibInit
//---------------------------------------------------------------------
bool SymLibInit (int argc, char** argv, const std::string& agentName)
{
	bool			successAndContinue = false;
	std::string		logString;
	
	try
	{
		std::string		tempString;
		bool			stopApp = false;
		bool			startApp = true;		// Assumption
		bool			daemonizeApp = false;
		
		// Initialize the library
		LibraryInit(argc,argv,agentName);
		
		// Load the local preference file
		GetPrefsPtr()->LoadLocalConfFile();
		
		// Log our activity
		logString = "Application launch";
		if (gEnvironObjPtr->ArgListCount() > 1)
		{
			logString += " with args: ";
			for (StdStringList_const_iter x = gEnvironObjPtr->ArgListBegin() + 1; x != gEnvironObjPtr->ArgListEnd(); x++)
			{
				if (x != gEnvironObjPtr->ArgListBegin())
					logString += " ";
				logString += *x;
			}
		}
		WriteToMessagesLog(logString);
		
		// Check some arguments to see if they want us to do anything special
		if (DoesApplicationArgExist(kAppArgKeyStatus))
		{
			unsigned long	pid = ReadPIDFile();
			
			if (pid > 0 && kill(pid,0) == 0)
			{
				std::cout << agentName << " is running as a daemon at PID " << pid << std::endl;
			}
			else
			{
				std::cout << agentName << " is not running as a daemon" << std::endl;
			}
			
			// We don't want to keep running in this case
			startApp = false;
		}
		else
		{
			if (DoesApplicationArgExist(kAppArgKeyStop))
			{
				stopApp = true;
				startApp = false;
			}
			if (DoesApplicationArgExist(kAppArgKeyStart) || DoesApplicationArgExist(kAppArgKeyDaemonize))
			{
				startApp = true;
				daemonizeApp = true;
			}
			if (DoesApplicationArgExist(kAppArgKeyRestart))
			{
				stopApp = true;
				startApp = true;
				daemonizeApp = true;
			}
			
			if (stopApp)
			{
				// Stop an already-running process.
				unsigned long	oldPID = ReadPIDFile();
				
				if (oldPID > 0)
				{
					// Make sure the process is still running
					if (kill(oldPID,0) == 0)
					{
						logString = "Sending normal termination signal to agent process " + NumToString(oldPID);
						WriteToMessagesLog(logString);
						
						if (kill(oldPID,SIGTERM) == 0)
						{
							time_t	expireTime;
							
							// Wait for 20 seconds for the process to quit
							expireTime = time(NULL) + 20;
							while (kill(oldPID,0) == 0 && time(NULL) < expireTime)
								PauseExecution(.5);
							
							if (kill(oldPID,0) == 0)
							{
								// The process didn't die; kill it hard
								logString = "Sending extreme termination signal to agent process " + NumToString(oldPID);
								WriteToMessagesLog(logString);
								
								if (kill(oldPID,SIGKILL) == 0)
								{
									// Wait for 5 seconds for the process to quit
									expireTime = time(NULL) + 5;
									while (kill(oldPID,0) == 0 && time(NULL) < expireTime)
										PauseExecution(.5);
								}
							}
							
							if (kill(oldPID,0) == 0)
							{
								logString = "Unable to stop agent process " + NumToString(oldPID);
								WriteToMessagesLog(logString);
							}
							else
							{
								// Success!
								logString = "Successfully stopped agent process " + NumToString(oldPID);
								WriteToMessagesLog(logString);
								
								// Remove PID file
								DeletePIDFile();
							}
						}
						else
						{
							logString = "Unable to stop agent process " + NumToString(oldPID);
							if (errno == ESRCH)
								logString += " -- process not found";
							else if (errno == EPERM)
								logString += " -- insufficient permissions";
							else
								logString += " -- error code " + NumToString(errno);
							WriteToMessagesLog(logString);
						}
					}
					else
					{
						logString = "";
						logString = "Unable to stop agent process " + NumToString(oldPID);
						if (errno == ESRCH)
							logString += " -- process not found";
						else if (errno == EPERM)
							logString += " -- insufficient permissions";
						else
							logString += " -- error code " + NumToString(errno);
						WriteToMessagesLog(logString);
					}
				}
				else
				{
					WriteToMessagesLog("Unable to stop existing agent process -- PID file not found");
				}
			}
			
			if (startApp && daemonizeApp)
			{
				// Make sure there isn't a daemon already running
				unsigned long	oldPID = ReadPIDFile();
				
				if (oldPID > 0 && kill(oldPID,0) == 0)
				{
					logString = "Daemon process already running at PID " + NumToString(oldPID) + "; cancelling this execution";
					WriteToErrorLog(logString);
					startApp = false;
				}
			}
			
			if (startApp)
			{
				pid_t	currentPID = getpid();
				
				if (daemonizeApp)
					gEnvironObjPtr->MarkAsDaemon(BecomeDaemon());
				
				if (gEnvironObjPtr->IsDaemon())
				{
					gEnvironObjPtr->SetAppPID(getpid());
					CreatePIDFile();
					logString = "Switch from PID " + NumToString(currentPID) + " to PID " + NumToString(getpid());
					WriteToMessagesLog(logString);
				}
				
				// Create an object to handle our persistent stuff
				gServerObjPtr = new TServerObj();
				
				InitTaskQueue();
				
				successAndContinue = true;
			}
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While initializing library: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		
		// Remove PID file
		if (gEnvironObjPtr && gEnvironObjPtr->IsDaemon())
		{
			// Remove PID file
			DeletePIDFile();
		}
		
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While initializing library: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		
		// Remove PID file
		if (gEnvironObjPtr && gEnvironObjPtr->IsDaemon())
		{
			// Remove PID file
			DeletePIDFile();
		}
		
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While initializing library: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		
		// Remove PID file
		if (gEnvironObjPtr && gEnvironObjPtr->IsDaemon())
		{
			// Remove PID file
			DeletePIDFile();
		}
		
		throw newErrObj;
	}
	
	return successAndContinue;
}

//---------------------------------------------------------------------
// SymLibCleanup
//---------------------------------------------------------------------
void SymLibCleanup ()
{
	try
	{
		WriteToMessagesLog("Begin agent shutdown");
		
		try
		{
			DeleteTaskQueue();
			
			if (gServerObjPtr)
			{
				// Gracefully disconnect, if necessary
				DisconnectFromServer();
				
				delete(gServerObjPtr);
				gServerObjPtr = NULL;
			}
			
			if (gEnvironObjPtr && gEnvironObjPtr->IsDaemon())
			{
				// Remove PID file
				DeletePIDFile();
			}
			
			WriteToMessagesLog("Agent shutdown complete");
		}
		catch (...)
		{
			// Make sure our PID file (if any) is removed before rethrowing error
			if (gEnvironObjPtr && gEnvironObjPtr->IsDaemon())
			{
				// Remove PID file
				DeletePIDFile();
			}
			throw;
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While cleaning up library: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While cleaning up library: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While cleaning up library: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// ApplicationArgList
//---------------------------------------------------------------------
unsigned long ApplicationArgList (StdStringList& argList)
{
	try
	{
		argList.clear();
		
		copy(gEnvironObjPtr->ArgListBegin(),gEnvironObjPtr->ArgListEnd(),back_inserter(argList));
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While obtaining application arguments: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While obtaining application arguments: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While obtaining application arguments: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return argList.size();
}

//---------------------------------------------------------------------
// DoesApplicationArgExist
//---------------------------------------------------------------------
bool DoesApplicationArgExist (const std::string& arg)
{
	bool		exists = false;
	
	try
	{
		if (find(gEnvironObjPtr->ArgListBegin() + 1,gEnvironObjPtr->ArgListEnd(),arg) != gEnvironObjPtr->ArgListEnd())
			exists = true;
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While checking application arguments: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While checking application arguments: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While checking application arguments: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return exists;
}

//---------------------------------------------------------------------
// GetApplicationArgValue
//---------------------------------------------------------------------
std::string GetApplicationArgValue (const std::string& arg)
{
	std::string		value;
	
	try
	{
		StdStringList_const_iter	iter = find(gEnvironObjPtr->ArgListBegin() + 1,gEnvironObjPtr->ArgListEnd(),arg);
		
		if (iter != gEnvironObjPtr->ArgListEnd())
		{
			iter++;
			if (iter != gEnvironObjPtr->ArgListEnd())
				value = *iter;
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While obtaining application argument key/value: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While obtaining application argument key/value: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While obtaining application argument key/value: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return value;
}

//---------------------------------------------------------------------
// GetDynamicDebuggingFlags
//---------------------------------------------------------------------
unsigned long long GetDynamicDebuggingFlags ()
{
	unsigned long long	flags = kDynDebugNone;
	
	if (gEnvironObjPtr)
		flags = gEnvironObjPtr->DynamicDebugFlags();
	
	return flags;
}

//---------------------------------------------------------------------
// RunningAsDaemon
//---------------------------------------------------------------------
bool RunningAsDaemon ()
{
	return gEnvironObjPtr && gEnvironObjPtr->IsDaemon();
}

//---------------------------------------------------------------------
// PauseExecution
//---------------------------------------------------------------------
void PauseExecution (double seconds)
{
	Pause(seconds);
}

//---------------------------------------------------------------------
// WriteToErrorLog
//---------------------------------------------------------------------
void WriteToErrorLog (const std::string& logEntry)
{
	WriteToErrorLogFile(logEntry);
}

//---------------------------------------------------------------------
// WriteToMessagesLog
//---------------------------------------------------------------------
void WriteToMessagesLog (const std::string& logEntry)
{
	WriteToMessagesLogFile(logEntry);
}

//---------------------------------------------------------------------
// ConnectToServer
//---------------------------------------------------------------------
void ConnectToServer (TLoginDataNode& additionalLoginNode)
{
	try
	{
		if (gServerObjPtr)
		{
			if (!gServerObjPtr->IsConnected())
			{
				TServerMessage		loginMessage;
				TServerReply		reply;
				TMessageNode		nodeRef;
				
				gServerObjPtr->Connect();
				
				// Append login information to the message
				nodeRef = loginMessage.Append(kMessageTypeValueLogin,"","");
				//nodeRef.AddAttribute(kMessageTagIPAddress,gServerObjPtr->LocalIPAddressAsString());
				nodeRef.AddAttribute(kMessageTagClientSignature,gEnvironObjPtr->AppSignature());
				
				if (additionalLoginNode.IsValid())
					nodeRef.Append(additionalLoginNode);
				
				// Perform the login protocol
				try
				{
					ResponseCode	replyCode = SendToServer(loginMessage,reply,kCompressionModeNone);
					
					switch (replyCode)
					{
						case kResponseCodeOK:
							{
								// Stuff all the <CONFIG> stuff into our prefs
								
								nodeRef = reply.FindNode(kMessageTypeValueConfig);
								if (nodeRef.IsValid())
								{
									// Stuff all the <CONFIG> stuff into our prefs
									unsigned long	itemCount = nodeRef.SubnodeCount();
									std::string		compressionText;
									
									for (unsigned long x = 0; x < itemCount; x++)
									{
										TMessageNode	childNode(nodeRef.GetNthSubnode(x));
										
										GetPrefsPtr()->AppendPrefNodePtr(reinterpret_cast<TXMLNodeObj*>(childNode.GetPtr()));
									}
									
									// Insert our host-given nonce separately into our runtime environment
									gEnvironObjPtr->SetServerNonce(nodeRef.GetAttributeValue(kMessageTagNonce));
									
									// Parse out server-supplied compression designation, if any
									compressionText = nodeRef.GetAttributeValue(kTagPrefCompression);
									if (compressionText == "gzip")
										gServerObjPtr->SetCompressionMode(kCompressionModeGZip);
								}
							}
							break;
						
						case kResponseCodeNotProvisionedErr:
							{
								// The agent is not provisioned.  We need to throw a particular
								// exception so the calling application can take steps
								gServerObjPtr->Disconnect();
								throw TSymLibErrorObj(kErrorAgentNotProvisioned);
							}
							break;
						
						case kResponseCodeDBUnavailErr:
							{
								// The database is unavailable.  Throw an exception so the calling
								// application can take steps
								gServerObjPtr->Disconnect();
								throw TSymLibErrorObj(kErrorDBUnavailable);
							}
							break;
						
						default:
							{
								// Unknown response.  Throw an exception
								gServerObjPtr->Disconnect(true);
								throw TSymLibErrorObj(kErrorServerUnavailable);
							}
							break;
					}
				}
				catch (...)
				{
					// Some error occurred.  Disconnect and rethrow
					gServerObjPtr->Disconnect(true);
					throw;
				}
			}
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While connecting to server: " + errObj.GetDescription();
			WriteToErrorLog(errString);
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While connecting to server: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While connecting to server: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// DisconnectFromServer
//---------------------------------------------------------------------
void DisconnectFromServer ()
{
	try
	{
		// Clear pending tasks, allow running tasks to terminate gracefully
		_ClearTaskQueues(true,true);
		
		if (gServerObjPtr && gServerObjPtr->IsConnected())
		{
			try
			{
				// Perform the logout protocol
				
				TServerMessage		logoutMessage;
				TServerReply		reply;
				TMessageNode		nodeRef;
				
				// Append logout information to the message
				nodeRef = logoutMessage.Append(kMessageTypeValueLogout,"","");
				
				// Send it away
				SendToServer(logoutMessage,reply,kCompressionModeNone);
				
				// Disconnect
				gServerObjPtr->Disconnect();
			}
			catch (...)
			{
				// Make sure the server is disconnected
				gServerObjPtr->Disconnect(true);
				// Re-throw error for logging
				throw;
			}
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While disconnecting from server: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While disconnecting from server: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While disconnecting from server: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// IsConnectedToServer
//---------------------------------------------------------------------
bool IsConnectedToServer ()
{
	bool	isConnected = false;
	
	if (gServerObjPtr)
		isConnected = gServerObjPtr->IsConnected();
	
	return isConnected;
}

//---------------------------------------------------------------------
// SendToServer
//---------------------------------------------------------------------
ResponseCode SendToServer (TServerMessage& xmlData,
						   TServerReply& receivedXMLData,
						   CompressionMode compressionMode)
{
	ResponseCode		responseCode = kResponseCodeUnknown;
	
	try
	{
		if (gServerObjPtr && gServerObjPtr->IsConnected())
		{
			TLockedPthreadMutexObj		lock(gServerObjPtr->IOLock());
			
			// Add the current MAC address to the outbound message
			//xmlData.AddAttribute(kMessageTagMACAddress,gServerObjPtr->MyMACAddress());
			
			if (gServerObjPtr->Send(xmlData.AsCompressedString(),compressionMode))
			{
				std::string		receivedData(gServerObjPtr->Receive());
				std::string		savedReceivedData(receivedData);
				
				if (receivedData.find("HTTP") == 0)
				{
					// We need to extract the HTTP headers
					std::string		header;
					StdStringList	headerLines;
					unsigned long	sectionPos = receivedData.find(gServerObjPtr->SectionDelimiter());
					bool			formatError = false;
					
					if (sectionPos == std::string::npos)
					{
						// We don't have content, so assume that the entire reply is just a header
						header = receivedData;
						receivedData = "";
					}
					else
					{
						// Parse out the header
						header = receivedData.substr(0,sectionPos);
						
						// Remove the headers from the received data
						receivedData.erase(0,sectionPos + gServerObjPtr->SectionDelimiter().length());
						
						// Remove the whitespace around the content
						while (!receivedData.empty() && isspace(receivedData[receivedData.length()-1]))
							receivedData.erase(receivedData.length()-1,1);
						while (!receivedData.empty() && isspace(receivedData[0]))
							receivedData.erase(0,1);
					}
					
					// Parse the response code from the first line, which
					// will be in the format "HTTP/1.1 nnn sssss"
					SplitStdString(gServerObjPtr->LineDelimiter(),header,headerLines,false);
					if (!headerLines.empty())
					{
						StdStringList	items;
						
						SplitStdString(' ',headerLines[0],items,false);
						if (items.size() >= 2)
						{
							long	code = static_cast<long>(StringToNum(items[1]));
							
							if (code == 100 || (code >= 200 && code <= 299))
							{
								if (receivedData.find("<COMMAND>") == 0)
								{
									// This is a server command; stash it on the server queue
									// and do NOT pass it back to the caller
									gServerObjPtr->SaveServerCommand(receivedData);
								}
								else
								{
									// Normal, everyday response
									receivedXMLData.Parse(receivedData);
								}
								
								if (code == 202)
									responseCode = kResponseCodeNotProvisionedErr;
								else
									responseCode = kResponseCodeOK;
							}
							else if (code == 599)
							{
								// The remote database is unavailable
								WriteToErrorLog("Server is reporting database unavailable");
								receivedXMLData.Parse(receivedData);
								responseCode = kResponseCodeDBUnavailErr;
							}
							else
							{
								std::string		errString;
								
								errString += "Error: Invalid response in HTTP header received from server ";
								errString += "(HTTP response code " + NumToString(code) + ")";
								errString += "\n==== Begin actual reply ====\n";
								errString += savedReceivedData;
								errString += "\n==== End actual reply ====";
								
								throw TSymLibErrorObj(kErrorBadServerResponse,errString);
							}
						}
						else
						{
							formatError = true;
						}
					}
					else
					{
						formatError = true;
					}
					
					if (formatError)
					{
						std::string		errString;
						
						errString += "Error: Invalid format in HTTP header received from server";
						errString += "\n==== Begin actual reply ====\n";
						errString += savedReceivedData;
						errString += "\n==== End actual reply ====";
						
						throw TSymLibErrorObj(kErrorBadServerResponse,errString);
					}
				}
				else
				{
					// We didn't receive an HTTP response; that's an error
					std::string		errString;
					
					// Disconnect, hard
					gServerObjPtr->Disconnect(true);
					
					errString += "Error: Invalid response received from server";
					errString += "\n==== Begin actual reply ====\n";
					errString += savedReceivedData;
					errString += "\n==== End actual reply ====";
					
					throw TSymLibErrorObj(kErrorBadServerResponse,errString);
				}
			}
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While talking to server: " + errObj.GetDescription();
			WriteToErrorLog(errString);
			errObj.MarkAsLogged();
		}
		
		if (gServerObjPtr)
		{
			switch (errObj.GetError())
			{
				case EPIPE:
				case kSSLConnectionTerminated:
					// Our network connection is hosed.  We need to disconnect.
					gServerObjPtr->Disconnect(true);
					break;
				
				case kErrorBadServerResponse:
					gServerObjPtr->Disconnect(true);
					break;
				
				case kErrorServerCommunicationTimeout:
					gServerObjPtr->Disconnect(true);
					break;
			}
		}
		
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While talking to server: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		newErrObj.MarkAsLogged();
		
		// Assume our connection has been hosed
		if (gServerObjPtr)
			gServerObjPtr->Disconnect(true);
		
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While talking to server: " + newErrObj.GetDescription();
		WriteToErrorLog(errString);
		newErrObj.MarkAsLogged();
		
		// Assume our connection has been hosed
		if (gServerObjPtr)
			gServerObjPtr->Disconnect(true);
		
		throw newErrObj;
	}
	
	return responseCode;
}

//---------------------------------------------------------------------
// AdviseServer
//---------------------------------------------------------------------
void AdviseServer (std::string advisoryText, unsigned long priority)
{
	try
	{
		if (!advisoryText.empty() && gServerObjPtr && gServerObjPtr->IsConnected())
		{
			TServerMessage			message;
			TServerReply			reply;
			TMessageNode			nodeRef;
			const unsigned long		kMaxTextSize = 255;
			
			// Make sure the text doesn't exceed the maximum size
			if (advisoryText.length() > kMaxTextSize)
			{
				std::string		elidedText("...");
				unsigned long	newSize = kMaxTextSize - elidedText.length();
				
				advisoryText.erase(newSize,advisoryText.length() - newSize);
				advisoryText += elidedText;
			}
			
			// Construct the message
			nodeRef = message.Append("NOTICE","","");
			nodeRef.AddAttribute("text",advisoryText);
			nodeRef.AddAttribute("priority",NumToString(priority));
			
			// Send it away, ignoring the reply
			SendToServer(message,reply);
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While sending advisory message to server: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While sending advisory message to server: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While sending advisory message to server: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// GetServerCommand
//---------------------------------------------------------------------
bool GetServerCommand (TServerReply& serverCommand)
{
	bool	success = false;
	
	if (!IsTask())
	{
		try
		{
			if (gServerObjPtr)
			{
				std::string		command(gServerObjPtr->GetServerCommand());
				
				if (!command.empty())
				{
					serverCommand.Parse(command);
					success = true;
				}
			}
		}
		catch (TSymLibErrorObj& errObj)
		{
			if (!errObj.IsLogged())
			{
				std::string		errString;
				
				errString += "While obtaining a server command from the queue: " + errObj.GetDescription();
				WriteToErrorLog(errObj.GetDescription());
				errObj.MarkAsLogged();
			}
			throw;
		}
		catch (int errNum)
		{
			std::string			errString;
			TSymLibErrorObj		newErrObj(errNum);
			
			errString = "While obtaining a server command from the queue: Generic Error: ";
			errString += NumToString(errNum);
			WriteToErrorLog(errString);
			
			newErrObj.MarkAsLogged();
			throw newErrObj;
		}
		catch (...)
		{
			std::string		errString;
			TSymLibErrorObj	newErrObj(-1,"Unknown error");
			
			errString += "While obtaining a server command from the queue: " + newErrObj.GetDescription();
			
			WriteToErrorLog(errString);
			
			newErrObj.MarkAsLogged();
			throw newErrObj;
		}
	}
	
	return success;
}

//---------------------------------------------------------------------
// NetworkInterfaceList
//---------------------------------------------------------------------
unsigned long NetworkInterfaceList (StdStringList& interfaceList)
{
	unsigned long	interfaceCount = 0;
	
	try
	{
		interfaceCount = LocalHostInterfaceList(interfaceList);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While obtaining list of local network interfaces: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While obtaining list of local network interfaces: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While obtaining list of local network interfaces: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return interfaceCount;
}

//---------------------------------------------------------------------
// LocalIPAddressAsString
//---------------------------------------------------------------------
std::string LocalIPAddressAsString ()
{
	std::string		address;
	
	try
	{
		if (gServerObjPtr && gServerObjPtr->IsConnected())
			address = gServerObjPtr->LocalIPAddressAsString();
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While obtaining our local IP address: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While obtaining our local IP address: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While obtaining our local IP address: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return address;
}

//---------------------------------------------------------------------
// LocalIPPort
//---------------------------------------------------------------------
int LocalIPPort ()
{
	int		portNum = 0;
	
	try
	{
		if (gServerObjPtr && gServerObjPtr->IsConnected())
			portNum = gServerObjPtr->LocalPortNumber();
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While obtaining our local IP address: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While obtaining our local IP address: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While obtaining our local IP address: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return portNum;
}

//---------------------------------------------------------------------
// ServerIPAddressAsString
//---------------------------------------------------------------------
std::string ServerIPAddressAsString ()
{
	std::string		address;
	
	try
	{
		if (gServerObjPtr && gServerObjPtr->IsConnected())
			address = gServerObjPtr->RemoteIPAddressAsString();
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While obtaining our local IP address: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While obtaining our local IP address: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While obtaining our local IP address: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return address;
}

//---------------------------------------------------------------------
// ServerIPPort
//---------------------------------------------------------------------
int ServerIPPort ()
{
	int		portNum = 0;
	
	try
	{
		if (gServerObjPtr && gServerObjPtr->IsConnected())
			portNum = gServerObjPtr->RemotePortNumber();
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While obtaining our local IP address: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While obtaining our local IP address: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While obtaining our local IP address: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return portNum;
}

//---------------------------------------------------------------------
// GetPreferenceNode
//---------------------------------------------------------------------
TPreferenceNode GetPreferenceNode ()
{
	TPreferenceNode		prefNode;
	
	try
	{
		TXMLNodeObj*	foundNodePtr = GetPrefsPtr()->RemotePrefsNodePtr();
		
		if (foundNodePtr)
			prefNode.SetPtr(foundNodePtr);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While obtaining preference node: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While obtaining preference node: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While obtaining preference node: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return prefNode;
}

//---------------------------------------------------------------------
// AddTaskToQueue
//---------------------------------------------------------------------
void AddTaskToQueue (TTaskBase* taskObjPtr, bool runFirst)
{
	try
	{
		_AddTaskToQueue(taskObjPtr,runFirst);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While adding a task to the queue: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While adding a task to the queue: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While adding a task to the queue: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// AddDelayedTaskToQueue
//---------------------------------------------------------------------
void AddDelayedTaskToQueue (TTaskBase* taskObjPtr, time_t delayInSeconds)
{
	try
	{
		_AddDelayedTaskToQueue(taskObjPtr,delayInSeconds);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While adding a delayed task to the queue: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While adding a delayed task to the queue: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While adding a delayed task to the queue: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// DestroyTask
//---------------------------------------------------------------------
void DestroyTask (TTaskBase* taskObjPtr)
{
	try
	{
		if (taskObjPtr)
			_DeleteTaskFromQueue(taskObjPtr);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While destroying a task: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While destroying a task: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While destroying a task: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// ClearTaskQueues
//---------------------------------------------------------------------
void ClearTaskQueues (bool gracefully, bool leaveEnabled)
{
	try
	{
		_ClearTaskQueues(gracefully,leaveEnabled);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While clearing the task queue: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While clearing the task queue: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While clearing the task queue: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// IsTaskInQueue
//---------------------------------------------------------------------
bool IsTaskInQueue (const TTaskBase* taskObjPtr)
{
	bool	inQueue = false;
	
	try
	{
		if (taskObjPtr)
			inQueue = _IsTaskInQueue(taskObjPtr);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While searching for a task in queue: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While searching for a task in queue: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While searching for a task in queue: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return inQueue;
}

//---------------------------------------------------------------------
// TasksAreRunnable
//---------------------------------------------------------------------
bool TasksAreRunnable ()
{
	return IsTaskQueueAccepting();
}

//---------------------------------------------------------------------
// TasksAreExecuting
//---------------------------------------------------------------------
bool TasksAreExecuting ()
{
	return IsTaskQueueExecuting();
}

//---------------------------------------------------------------------
// IsTask
//---------------------------------------------------------------------
bool IsTask ()
{
	bool	isTask = false;
	
	try
	{
		TPthreadObj*		threadObjPtr = MyThreadObjPtr();
		
		if (threadObjPtr)
			isTask = (threadObjPtr->InternalID() != 0);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While determining if current process is a task: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While determining if current process is a task: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While determining if current process is a task: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return isTask;
}

//---------------------------------------------------------------------
// CreateFileWatcherTask
//---------------------------------------------------------------------
FileWatcherRef CreateFileWatcherTask (const std::string& filePath,
									  time_t executionIntervalInSeconds,
									  FileWatchStyle watchStyle)
{
	TTaskFileWatch*		taskObjPtr = NULL;
	
	try
	{
		taskObjPtr = new TTaskFileWatch(executionIntervalInSeconds,watchStyle);
		
		if (taskObjPtr)
			taskObjPtr->SetupTask(filePath);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While creating a file watcher task: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While creating a file watcher task: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While creating a file watcher task: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return taskObjPtr;
}

//---------------------------------------------------------------------
// DestroyFileWatcherTask
//---------------------------------------------------------------------
void DestroyFileWatcherTask (FileWatcherRef taskRef)
{
	try
	{
		TTaskFileWatch*		taskObjPtr = reinterpret_cast<TTaskFileWatch*>(taskRef);
		
		if (taskObjPtr)
			_DeleteTaskFromQueue(taskObjPtr);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While destroying a file watcher task: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While destroying a file watcher task: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While destroying a file watcher task: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// AddFileWatcherCallback
//---------------------------------------------------------------------
void AddFileWatcherCallback (FileWatcherRef taskRef,
							 FileWatchChangeFlag triggerFlags,
							 FileWatchCallback callback,
							 void* userData)
{
	try
	{
		TTaskFileWatch*		taskObjPtr = reinterpret_cast<TTaskFileWatch*>(taskRef);
		
		if (taskObjPtr)
			taskObjPtr->AddCallback(triggerFlags,callback,userData);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While adding a file watcher task callback: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While adding a file watcher task callback: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While adding a file watcher task callback: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// QueueFileWatcherTask
//---------------------------------------------------------------------
void QueueFileWatcherTask (FileWatcherRef taskRef, bool runFirst)
{
	try
	{
		TTaskFileWatch*		taskObjPtr = reinterpret_cast<TTaskFileWatch*>(taskRef);
		
		if (taskObjPtr)
			_AddTaskToQueue(taskObjPtr,runFirst);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While adding a file watcher task to the queue: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While adding a file watcher task to the queue: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While adding a file watcher task to the queue: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// GetNewFileWatcherData
//---------------------------------------------------------------------
std::string GetNewFileWatcherData (FileWatcherRef taskRef)
{
	std::string		data;
	
	try
	{
		TTaskFileWatch*		taskObjPtr = reinterpret_cast<TTaskFileWatch*>(taskRef);
		
		if (taskObjPtr)
			data = taskObjPtr->ReadAddedFileData();
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While obtaining data from a file via file watcher: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While obtaining data from a file via file watcher: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While obtaining data from a file via file watcher: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return data;
}

//---------------------------------------------------------------------
// IsFileWatcherTaskInQueue
//---------------------------------------------------------------------
bool IsFileWatcherTaskInQueue (FileWatcherRef taskRef)
{
	bool			inQueue = false;
	TTaskFileWatch*	taskObjPtr = reinterpret_cast<TTaskFileWatch*>(taskRef);
	
	if (taskObjPtr)
		inQueue = IsTaskInQueue(taskObjPtr);
	
	return inQueue;
}

//---------------------------------------------------------------------
// CreateAppExecTask
//---------------------------------------------------------------------
AppExecRef CreateAppExecTask (const std::string& appPath,
							  const std::string& appArgs,
							  const std::string& appStdInData,
							  time_t executionIntervalInSeconds)
{
	TAppExecTask*		taskObjPtr = NULL;
	
	try
	{
		taskObjPtr = new TAppExecTask(executionIntervalInSeconds);
		
		if (taskObjPtr)
			taskObjPtr->SetupTask(appPath,appArgs,appStdInData);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While creating an application execution task: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While creating an application execution task: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While creating an application execution task: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return taskObjPtr;
}

//---------------------------------------------------------------------
// DestroyAppExecTask
//---------------------------------------------------------------------
void DestroyAppExecTask (AppExecRef taskRef)
{
	try
	{
		TAppExecTask*		taskObjPtr = reinterpret_cast<TAppExecTask*>(taskRef);
		
		if (taskObjPtr)
			_DeleteTaskFromQueue(taskObjPtr);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While destroying an application execution task: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While destroying an application execution task: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While destroying an application execution task: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// AddAppExecCallback
//---------------------------------------------------------------------
void AddAppExecCallback (AppExecRef taskRef,
						 AppExecCallback callback,
						 void* userData)
{
	try
	{
		TAppExecTask*		taskObjPtr = reinterpret_cast<TAppExecTask*>(taskRef);
		
		if (taskObjPtr)
			taskObjPtr->AddCallback(callback,userData);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While adding an application execution task callback: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While adding an application execution task callback: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While adding an application execution task callback: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// QueueAppExecTask
//---------------------------------------------------------------------
void QueueAppExecTask (AppExecRef taskRef, bool runFirst)
{
	try
	{
		TAppExecTask*		taskObjPtr = reinterpret_cast<TAppExecTask*>(taskRef);
		
		if (taskObjPtr)
			_AddTaskToQueue(taskObjPtr,runFirst);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While adding an application execution task to the queue: " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While adding an application execution task to the queue: Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While adding an application execution task to the queue: " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// IsAppExecTaskInQueue
//---------------------------------------------------------------------
bool IsAppExecTaskInQueue (AppExecRef taskRef)
{
	bool			inQueue = false;
	TAppExecTask*	taskObjPtr = reinterpret_cast<TAppExecTask*>(taskRef);
	
	if (taskObjPtr)
		inQueue = IsTaskInQueue(taskObjPtr);
	
	return inQueue;
}

//---------------------------------------------------------------------
// GetFileSignature
//---------------------------------------------------------------------
std::string GetFileSignature (const std::string& filePath)
{
	std::string		sig;
	
	try
	{
		TFileObj		fileObj(filePath);
		
		if (fileObj.Exists())
		{
			TDigest			fileSigDigestObj("SHA1");
			TDigestContext	fileSigDigestContextObj;
			TEncodeContext	encodeContext;
			
			// Compute the signature of this executable
			fileSigDigestContextObj.Initialize(fileSigDigestObj);
			fileSigDigestContextObj.Update(fileObj);
			sig = encodeContext.Encode(fileSigDigestContextObj.Final());
		}
		else
		{
			std::string		errString;
			
			errString += "File '" + filePath + "' does not exist (cannot compute signature)";
			throw TSymLibErrorObj(ENOENT,errString);
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While computing signature of file '" + filePath + "': " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While computing signature of file '" + filePath + "': Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While computing signature of file '" + filePath + "': " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return sig;
}

//---------------------------------------------------------------------
// ExecApplication
//---------------------------------------------------------------------
std::string ExecApplication (const std::string& appPath, const std::string appStdInData)
{
	std::string		data;
	
	try
	{
		if (appStdInData.empty())
			data = ExecWithIO(appPath);
		else
			data = ExecWithIO(appPath,reinterpret_cast<const unsigned char*>(appStdInData.c_str()),appStdInData.length());
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While executing application '" + appPath + "': " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While executing application '" + appPath + "': Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While executing application '" + appPath + "': " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return data;
}

//---------------------------------------------------------------------
// LocateFile
//---------------------------------------------------------------------
std::string LocateFile (const std::string& fileName, const StdStringList& directoryList)
{
	std::string		foundPath;
	
	try
	{
		foundPath = FindFile(fileName,directoryList);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			std::string		errString;
			
			errString += "While trying to find file '" + fileName + "': " + errObj.GetDescription();
			WriteToErrorLog(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "While trying to find file '" + fileName + "': Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		std::string		errString;
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		errString += "While trying to find file '" + fileName + "': " + newErrObj.GetDescription();
		
		WriteToErrorLog(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return foundPath;
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

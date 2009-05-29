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
#		Last Modified:				11 Feb 2005
#
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-communicate.h"

#include "symlib-prefs.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define		kServerCommunicationTimeout				60

#define		kCACertFileName							"cacert.pem"
#define		kAgentCertFileName						"agent.pem"

//*********************************************************************
// Class TServerObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TServerObj::TServerObj ()
	:	Inherited(),
		fHostAddress(0),
		fHostPort(0),
		fHostSSLPort(0),
		fCompressionMode(kCompressionModeNone)
{
	Inherited::SetTimeout(kServerCommunicationTimeout);
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TServerObj::~TServerObj ()
{
	Disconnect();
}

//---------------------------------------------------------------------
// TServerObj::New
//---------------------------------------------------------------------
TServerObj* TServerObj::New () const
{
	return new TServerObj();
}

//---------------------------------------------------------------------
// TServerObj::Connect
//---------------------------------------------------------------------
void TServerObj::Connect ()
{
	// Call our disconnect first
	Disconnect();
	
	_Initialize();
	
	// The following should always succeed; if it fails then an exception will be thrown
	Inherited::Connect(fHostAddress,fHostSSLPort,kIOBufferSizeSystemDefault,kServerCommunicationTimeout);
	
	// Tell the SSL objects which socket to use
	fSSLConnection.SetInputOutputSocket(GetIOSocket());
	
	// Negotiate
	fSSLConnection.Connect();
	
	// Initialize some of our other stuff
	fMACAddress = Inherited::LocalMACAddress();
	
	if (fMACAddress.empty())
	{
		// We don't have a network connection, probably because we're connecting
		// to the localhost.  Set a known bogus ID instead.
		fMACAddress = "00:00:00:00:00:00";
	}
}

//---------------------------------------------------------------------
// TServerObj::Disconnect
//---------------------------------------------------------------------
void TServerObj::Disconnect (bool hardDisconnect)
{
	try
	{
		if (!hardDisconnect)
		{
			try
			{
				fSSLConnection.ShutdownConnection();
			}
			catch (...)
			{
				// Suppress errors for disconnects
			}
		}
		
		Inherited::Disconnect();
	}
	catch (...)
	{
		// Suppress errors for disconnects
	}
}

//---------------------------------------------------------------------
// TServerObj::Send
//---------------------------------------------------------------------
bool TServerObj::Send (const std::string& stuffToSend, CompressionMode compressionMode)
{
	return _Send(stuffToSend,compressionMode);
}

//---------------------------------------------------------------------
// TServerObj::Receive
//---------------------------------------------------------------------
std::string TServerObj::Receive ()
{
	return _Receive();
}

//---------------------------------------------------------------------
// TServerObj::HaveServerCommands
//---------------------------------------------------------------------
bool TServerObj::HaveServerCommands ()
{
	TLockedPthreadMutexObj	lock(fServerCommandQueueLock);
	
	return !fServerCommandQueue.empty();
}

//---------------------------------------------------------------------
// TServerObj::GetServerCommand
//---------------------------------------------------------------------
std::string TServerObj::GetServerCommand ()
{
	std::string				command;
	TLockedPthreadMutexObj	lock(fServerCommandQueueLock);
	
	if (!fServerCommandQueue.empty())
	{
		command = fServerCommandQueue.front();
		fServerCommandQueue.pop();
	}
	
	return command;
}

//---------------------------------------------------------------------
// TServerObj::SaveServerCommand
//---------------------------------------------------------------------
void TServerObj::SaveServerCommand (const std::string& serverCommand)
{
	TLockedPthreadMutexObj	lock(fServerCommandQueueLock);
	
	fServerCommandQueue.push(serverCommand);
}

//---------------------------------------------------------------------
// TServerObj::_Initialize (protected)
//---------------------------------------------------------------------
void TServerObj::_Initialize ()
{
	const TXMLNodeObj*	serverNodePtr = GetPrefsPtr()->GetPrefNodePtr(kTagPrefServer);
	
	// First, just blast the information into the slots
	fCertDirObj.SetPath(GetPrefsPtr()->GetPrefData(kTagPrefCertDir));
	fHost = GetPrefsPtr()->GetNodePtrData(serverNodePtr,kTagPrefHost);
	fServerPath = "/";
	fHostPort = static_cast<unsigned int>(StringToNum(GetPrefsPtr()->GetNodePtrData(serverNodePtr,kTagPrefPort)));
	fHostSSLPort = static_cast<unsigned int>(StringToNum(GetPrefsPtr()->GetNodePtrData(serverNodePtr,kTagPrefSSLPort)));
	
	if (fHost.find('/') != std::string::npos)
	{
		StdStringList		tempList;
		
		SplitStdString('/',fHost,tempList,false);
		if (!tempList.empty())
		{
			fHost = tempList.front();
			tempList.erase(tempList.begin());
			fServerPath += JoinStdStringList('/',tempList);
		}
	}
	
	if (fHost.empty())
		throw TSymLibErrorObj(kErrorLocalPreferenceCorrupt,"Remote host not found");
	else
	{
		// Convert the host to an IP address
		fHostAddress = GetHostAddress(fHost);
	}
	
	// We're connecting to a remote host, so we need to validate our SSL stuff
	if (!fCertDirObj.Exists())
	{
		std::string		errString;
		
		errString = "Certificate directory '";
		errString += fCertDirObj.Path();
		errString += "' does not exist";
		
		throw TSymLibErrorObj(kErrorLocalPreferenceCorrupt,errString);
	}
	else
	{
		// Make sure the SSL environment is initialized
		SSLEnvironmentObjPtr()->LoadAllCipherAlgorithms();
		
		// The directory exists; check for the files
		fCACertFileObj.SetPath(fCertDirObj.Path() + kCACertFileName);
		fAgentCertFileObj.SetPath(fCertDirObj.Path() + kAgentCertFileName);
		
		if (!fCACertFileObj.Exists())
		{
			std::string		errString;
			
			errString = "CA certificate '";
			errString += fCACertFileObj.Path();
			errString += "' does not exist";
			
			throw TSymLibErrorObj(kErrorLocalPreferenceCorrupt,errString);
		}
		
		if (fCACertFileObj.OwnerID(true) != getuid())
		{
			std::string		errString;
			
			errString = "CA certificate '";
			errString += fCACertFileObj.Path();
			errString += "' has incorrect ownership";
			
			throw TSymLibErrorObj(kErrorCertificateFilePermissionsBad,errString);
		}
		
		if (fCACertFileObj.Permissions(true) != (S_IRUSR|S_IWUSR))
		{
			std::string		errString;
			
			errString = "CA certificate '";
			errString += fCACertFileObj.Path();
			errString += "' has incorrect permissions";
			
			throw TSymLibErrorObj(kErrorCertificateFilePermissionsBad,errString);
		}
		
		if (!fAgentCertFileObj.Exists())
		{
			std::string		errString;
			
			errString = "Agent certificate '";
			errString += fAgentCertFileObj.Path();
			errString += "' does not exist";
			
			throw TSymLibErrorObj(kErrorLocalPreferenceCorrupt,errString);
		}
		
		if (fAgentCertFileObj.OwnerID(true) != getuid())
		{
			std::string		errString;
			
			errString = "Agent certificate '";
			errString += fAgentCertFileObj.Path();
			errString += "' has incorrect ownership";
			
			throw TSymLibErrorObj(kErrorCertificateFilePermissionsBad,errString);
		}
		
		if (fAgentCertFileObj.Permissions(true) != (S_IRUSR|S_IWUSR))
		{
			std::string		errString;
			
			errString = "Agent certificate '";
			errString += fAgentCertFileObj.Path();
			errString += "' has incorrect permissions";
			
			throw TSymLibErrorObj(kErrorCertificateFilePermissionsBad,errString);
		}
	}
	
	// Initialize the SSL context
	fSSLContext.Initialize(kSSLClientMode,kSSLv23Protocol);
	fSSLContext.SetCertificateAuthorityFile(fCACertFileObj);
	fSSLContext.SetCertificate(fAgentCertFileObj,SSL_FILETYPE_PEM);
	fSSLContext.SetPrivateKey(fAgentCertFileObj,SSL_FILETYPE_PEM);
	fSSLContext.SetOptions(SSL_OP_NO_SSLv2);
	
	// Initialize the SSL connection
	fSSLConnection.Initialize(fSSLContext);
	fSSLConnection.SetVerificationParams(SSL_VERIFY_PEER);
	fSSLConnection.SetIOTimeout(kServerCommunicationTimeout);
}

//---------------------------------------------------------------------
// TServerObj::_Send (protected)
//---------------------------------------------------------------------
bool TServerObj::_Send (const std::string& stuffToSend, CompressionMode compressionMode)
{
	bool					allSent = false;
	std::string				completeDataBuffer;
	
	if (!IsConnected())
		throw TSymLibErrorObj(kErrorNotConnectedToServer);
	
	// Create a buffer complete with all data that needs to be sent, including pending data
	if (!fSendBuffer.empty())
	{
		completeDataBuffer += fSendBuffer;
		fSendBuffer = "";
	}
	completeDataBuffer.append(stuffToSend);
	
	if (!completeDataBuffer.empty())
	{
		std::string			messageBuffer;
		const std::string	kEOL("\n");
		
		// Construct the communication header
		messageBuffer += "POST " + fServerPath + " HTTP/1.1" + kEOL;
		messageBuffer += "Host: " + fHost + kEOL;
		messageBuffer += "Keep-Alive: 300" + kEOL;
		messageBuffer += "Connection: Keep-Alive" + kEOL;
		messageBuffer += "Pragma: no-cache" + kEOL;
		messageBuffer += "Cache-Control: no-cache" + kEOL;
		messageBuffer += "Content-Type: application/xml" + kEOL;
		messageBuffer += "Content-Encoding: ";
		
		if (compressionMode == kCompressionModeUnspecified)
			compressionMode = fCompressionMode;
		
		switch (compressionMode)
		{
			case kCompressionModeUnspecified:
			case kCompressionModeNone:
			case kCompressionModeZLib:				// zlib compression is not supported for server communication
				messageBuffer += "text" + kEOL;
				break;
			
			case kCompressionModeGZip:
				messageBuffer += "gzip" + kEOL;
				Compress(completeDataBuffer,compressionMode);
				break;
		}
		messageBuffer += "Content-Length: ";
		messageBuffer += NumToString(completeDataBuffer.length());
		messageBuffer += kEOL + kEOL;
		
		// Append the data buffer
		messageBuffer.append(completeDataBuffer);
		
		// Add an end-of-line to message
		messageBuffer += kEOL;
		
		if (BitTest(gEnvironObjPtr->DynamicDebugFlags(),kDynDebugLogServerCommunication))
			_LogCommunication(messageBuffer,"Client->Server Message");
		
		// Send it away
		try
		{
			fSSLConnection.Write(messageBuffer);
		}
		catch (...)
		{
			// If anything happens here we need to disconnect and bail
			Disconnect(true);
			throw;
		}
		
		allSent = true;
	}
	else
	{
		// Nothing to send, but we'll claim we sent it anyway
		allSent = true;
	}
	
	return allSent;
}

//---------------------------------------------------------------------
// TServerObj::_Receive (protected)
//---------------------------------------------------------------------
std::string TServerObj::_Receive ()
{
	std::string				reply;
	std::string				data;
	unsigned long			byteCount = 32768;
	std::string				lineDelimiter;
	std::string				sectionDelimiter;
	unsigned long			pos = 0;
	unsigned long			expectedContentLength = 0;
	
	do
	{
		if (!IsConnected())
			throw TSymLibErrorObj(kErrorLocalPreferenceNotLoaded);
		
		try
		{
			data = fSSLConnection.Read(byteCount);
		}
		catch (...)
		{
			// If anything happens here we need to disconnect and bail
			Disconnect(true);
			throw;
		}
		
		reply += data;
		
		if (fLineDelimiter.empty())
		{
			// Figure out what line delimiter we're using
			pos = data.find("\n");
			if (pos != std::string::npos)
			{
				if (pos > 0 && data[pos-1] == '\r')
					fLineDelimiter = "\r\n";
				else if (pos < data.length() && data[pos+1] == '\n')
					fLineDelimiter = "\n\n";
				else
					fLineDelimiter = "\n";
			}
			else
			{
				fLineDelimiter = "\n";
			}
			fSectionDelimiter = fLineDelimiter + fLineDelimiter;
		}
		
		if (data.find("Transfer-Encoding: chunked") != std::string::npos)
		{
			// Find the end of the headers
			pos = data.find(fSectionDelimiter);
			if (pos != std::string::npos)
			{
				unsigned long	beginChunkPos = pos + fSectionDelimiter.length();
				unsigned long	endChunkPos = data.find(fLineDelimiter,beginChunkPos);
				std::string		chunkSizeStr;
				unsigned long	chunkSize = 0;
				std::string		endOfChunkMarker;
				bool			readChunks = true;
				
				endOfChunkMarker = "0" + fSectionDelimiter;
				
				if (endChunkPos != std::string::npos)
				{
					// The chunk size is included in this message (this doesn't always happen)
					chunkSizeStr = data.substr(beginChunkPos,endChunkPos - beginChunkPos);
					
					// Capture the chunk size
					chunkSize = strtol(chunkSizeStr.c_str(),NULL,16);
					if (chunkSize == 0)
						readChunks = false;
					
					// Delete the chunk size from the data stream
					data.replace(beginChunkPos,endChunkPos + fLineDelimiter.length() - beginChunkPos,"");
				}
				
				while (readChunks)
				{
					std::string		tempData = fSSLConnection.Read(byteCount);
					
					if (BitTest(gEnvironObjPtr->DynamicDebugFlags(),kDynDebugLogServerCommunication))
						_LogCommunication(tempData,"Server->Client Chunk Response");
					
					if (!tempData.empty())
					{
						if (tempData == endOfChunkMarker)
						{
							// End of message
							readChunks = false;
						}
						else if (tempData == fLineDelimiter || tempData == fSectionDelimiter)
						{
							// Dumbass message
							data += tempData;
						}
						else
						{
							if (chunkSize == 0)
							{
								// We need to extract a chunk size; it should be at the beginning of the message,
								// followed by a fLineDelimiter
								beginChunkPos = 0;
								endChunkPos = tempData.find(fLineDelimiter,beginChunkPos);
								chunkSizeStr = tempData.substr(beginChunkPos,endChunkPos - beginChunkPos);
								
								// Capture the chunk size
								chunkSize = strtol(chunkSizeStr.c_str(),NULL,16);
								
								// Delete the chunk size and delimiters from the data stream
								tempData.replace(beginChunkPos,endChunkPos + fLineDelimiter.length() - beginChunkPos,"");
							}
							
							if (!tempData.empty())
							{
								// Append the data
								data += tempData;
								
								if (tempData.length() == chunkSize)
								{
									// We read the entire chunk; reset the size
									chunkSize = 0;
								}
							}
						}
					}
					else
					{
						readChunks = false;
					}
				}
			}
		}
		
		if (expectedContentLength == 0)
		{
			pos = data.find("Content-Length: ");
			if (pos != std::string::npos)
			{
				unsigned long	beginPos = pos;
				unsigned long	endPos = data.find(fLineDelimiter,beginPos);
				std::string		contentSizeStr(data.substr(beginPos,endPos - beginPos));
				
				expectedContentLength = strtol(contentSizeStr.c_str(),NULL,10);
			}
		}
	}
	while (reply.size() < expectedContentLength);
	
	if (BitTest(gEnvironObjPtr->DynamicDebugFlags(),kDynDebugLogServerCommunication))
		_LogCommunication(reply,"Server->Client Response");
	
	if (reply.find("Connection: close") != std::string::npos)
	{
		// The server apparently doesn't want to keep talking to us for some reason;
		// perform a disconnect
		WriteToErrorLogFile("Closing server connection at server's request");
		Disconnect();
	}
	
	return reply;
}

//---------------------------------------------------------------------
// TServerObj::_LogCommunication (protected)
//---------------------------------------------------------------------
void TServerObj::_LogCommunication (const std::string& data, const std::string prompt) const
{
	std::string		comm;
	
	comm += "Debug: " + prompt + " (" + NumToString(data.length()) + " bytes): \n";
	comm += "=======================\n";
	for (unsigned long c = 0; c < data.length(); c++)
	{
		char	ch = data[c];
		
		if (ch == '\r')
		{
			comm += "\\r";
			comm += "\n";
		}
		else if (ch == '\n')
		{
			comm += "\\n";
			comm += ch;
		}
		else if (ch < 32)
		{
			unsigned int	chValue = static_cast<unsigned char>(ch);
			comm += "{" + NumToString(chValue) + "}";
		}
		else
		{
			comm += ch;
		}
	}
	comm += "\n";
	comm += "=======================";
	
	WriteToMessagesLogFile(comm);
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

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
#		Adapted from a library authored by BTI and available
#		from http://www.bti.net
#		
#		Created:					28 Oct 2003
#		Last Modified:				15 Sep 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-tcp.h"

#include "symlib-exception.h"
#include "symlib-threads.h"

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <netdb.h>
#include <sys/param.h>
#include <unistd.h>

#include <net/if.h>
#if HAVE_NET_IF_DL_H
	#include <net/if_dl.h>
#endif
#include <sys/ioctl.h>
#if HAVE_SYS_SYSCTL_H
	#include <sys/sysctl.h>
#endif
#if HAVE_NET_ROUTE_H
	#include <net/route.h>
#endif

#if HAVE_NET_ETHERNET_H
	#include <net/ethernet.h>
#else
	#define ETHER_ADDR_LEN 6
#endif

#if HAVE_LINUX_SOCKIOS_H
	#include <linux/sockios.h>
#endif

#if HAVE_ARPA_INET_H
	#include <arpa/inet.h>
#endif

#if HAVE_SYS_POLL_H
	#include <sys/poll.h>
#endif

#if HAVE_SYS_TIME_H
	#include <sys/time.h>
#endif

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Object Static Member Initializations
//---------------------------------------------------------------------
const unsigned long		TTCPConnectionObj::kRWBufferSize = 64000;
const long 				TTCPConnectionObj::kTCPTimeoutNone = -1;
const int 				TTCPConnectionObj::kTCPSocketNone = -1;
const int 				TTCPConnectionObj::kTCPLingerNone = -1;
const int 				TTCPConnectionObj::kIOBufferSizeSystemDefault = 0;

//---------------------------------------------------------------------
// Module Global Variables
//---------------------------------------------------------------------
TPthreadMutexObj							gNameResolverMutex;

//*********************************************************************
// Class TTCPConnectionObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TTCPConnectionObj::TTCPConnectionObj ()
	:	fTimeoutValue(kTCPTimeoutNone),
		fIOSocket(kTCPSocketNone),
		fLingerTime(kTCPLingerNone),
		fProcessInboundThreaded(false),
		fIdle(false)
{
	memset(&fRemoteAddress,0,sizeof(fRemoteAddress));
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TTCPConnectionObj::~TTCPConnectionObj ()
{
	try
	{
		Disconnect();
	}
	catch (...)
	{
		// Ignore all errors
	}
}

//---------------------------------------------------------------------
// TTCPConnectionObj::Connect
//---------------------------------------------------------------------
bool TTCPConnectionObj::Connect (unsigned long networkAddress, int port, int ioBufferSize, int connectTimeout)
{
	int			tempSocket = -1;
	int			options;
	
	try
	{
		Disconnect();
		
		tempSocket = _CreateSocket();
		
		fRemoteAddress.sin_family = AF_INET;
		fRemoteAddress.sin_port = htons(port);
		fRemoteAddress.sin_addr.s_addr = networkAddress;
		
		// Set the linger time on the socket if necessary
		if (IsLingerSet())
		{
			struct linger	lingerInfo;
			
			lingerInfo.l_onoff = 1;
			lingerInfo.l_linger = fLingerTime;
			if (setsockopt(tempSocket,SOL_SOCKET,SO_LINGER,(char*)&lingerInfo,sizeof(lingerInfo)) < 0 && errno != 0)
				throw TSymLibErrorObj(errno,"While trying to set socket linger options for a connect");
		}
		
		if (_Connect(tempSocket,connectTimeout) >= 0)
		{
			// Connection succeeded.
			fIOSocket = tempSocket;
			tempSocket = -1;
			
			if (ioBufferSize != kIOBufferSizeSystemDefault)
			{
				options = ioBufferSize;
				if (setsockopt(fIOSocket,SOL_SOCKET,SO_RCVBUF,(char*)&options,sizeof(options)) < 0 && errno != 0)
					throw TSymLibErrorObj(errno,"While trying to set socket receive buffer for a connect");
				options = ioBufferSize;
				if (setsockopt(fIOSocket,SOL_SOCKET,SO_SNDBUF,(char*)&options,sizeof(options)) < 0 && errno != 0)
					throw TSymLibErrorObj(errno,"While trying to set socket send buffer for a connect");
			}
		}
		else
		{
			// Make sure sockets are closed
			CloseWithoutInterrupts(tempSocket,false);
			Disconnect();
		}
	}
	catch (...)
	{
		// Make sure sockets are closed
		if (tempSocket != -1)
		{
			CloseWithoutInterrupts(tempSocket,false);
			tempSocket = -1;
		}
		Disconnect();
		throw;
	}
	
	return IsIOSocketSet();
}

//---------------------------------------------------------------------
// TTCPConnectionObj::Connect
//---------------------------------------------------------------------
bool TTCPConnectionObj::Connect (const std::string& host, int port, int ioBufferSize, int connectTimeout)
{
	bool					isConnected = false;
	NetworkAddressList		hostAddressList;
	
	if (host.empty() || host == "localhost" || host == "127.0.0.1")
	{
		// Loopback connection
		hostAddressList.push_back(htonl(INADDR_LOOPBACK));
	}
	else
	{
		GetAllHostAddresses(host,hostAddressList);
	}
	
	if (!hostAddressList.empty())
	{
		for (NetworkAddressList_iter x = hostAddressList.begin(); !isConnected && x != hostAddressList.end(); x++)
		{
			isConnected = Connect(*x,port,ioBufferSize,connectTimeout);
		}
	}
	
	return isConnected;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::Disconnect
//---------------------------------------------------------------------
void TTCPConnectionObj::Disconnect ()
{
	CloseIOSocket();
}

//---------------------------------------------------------------------
// TTCPConnectionObj::CloseIOSocket
//---------------------------------------------------------------------
void TTCPConnectionObj::CloseIOSocket ()
{
	if (IsIOSocketSet())
	{
		CloseWithoutInterrupts(fIOSocket,false);
		fIOSocket = kTCPSocketNone;
	}
	
	fSendBuffer = "";
	memset(&fRemoteAddress,0,sizeof(fRemoteAddress));
}

//---------------------------------------------------------------------
// TTCPConnectionObj::Receive
//---------------------------------------------------------------------
std::string TTCPConnectionObj::Receive (char endOfTxChar, unsigned long maxBytes)
{
	std::string			eol;
	StdStringList		eolList;
	std::string			buffer;
	
	eol += endOfTxChar;
	eolList.push_back(eol);
	
	buffer = _ReceiveLine(eolList,maxBytes);
	if (buffer.length() > 0)
		buffer.erase(buffer.length()-1);
	
	return buffer;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::Receive
//---------------------------------------------------------------------
std::string TTCPConnectionObj::Receive (const std::string& endOfTxPattern, unsigned long maxBytes)
{
	StdStringList		eolList;
	
	eolList.push_back(endOfTxPattern);
	
	return _ReceiveLine(eolList,maxBytes);
}

//---------------------------------------------------------------------
// TTCPConnectionObj::Receive
//---------------------------------------------------------------------
std::string TTCPConnectionObj::Receive (const StdStringList& endOfTxPatternList, unsigned long maxBytes)
{
	return _ReceiveLine(endOfTxPatternList,maxBytes);
}

//---------------------------------------------------------------------
// TTCPConnectionObj::Receive
//---------------------------------------------------------------------
std::string TTCPConnectionObj::Receive (const char* endOfTxPattern, unsigned long maxBytes)
{
	return Receive(std::string(endOfTxPattern),maxBytes);
}

//---------------------------------------------------------------------
// TTCPConnectionObj::ReceiveBlock
//---------------------------------------------------------------------
std::string TTCPConnectionObj::ReceiveBlock (unsigned long byteCount)
{
	return _ReceiveBlock(byteCount);
}

//---------------------------------------------------------------------
// TTCPConnectionObj::ToSend
//---------------------------------------------------------------------
bool TTCPConnectionObj::ToSend (const std::string& stuffToSend)
{
	fSendBuffer.append(stuffToSend);
	return true;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::Send
//---------------------------------------------------------------------
bool TTCPConnectionObj::Send (const std::string& stuffToSend)
{
	bool				allSent = false;
	long				bytesRemaining = 0;
	time_t				expireTime = 0;
	const char*			bufferSegment = NULL;
	
	if (IsIOSocketSet())
	{
		fSendBuffer.append(stuffToSend);
		bufferSegment = fSendBuffer.data();
		bytesRemaining = fSendBuffer.length();
		
		if (IsTimeoutSet())
			expireTime = time(NULL) + GetTimeout();
		
		try
		{
			while (bytesRemaining > 0)
			{
				if (expireTime > 0 && time(NULL) > expireTime)
					throw TSymLibErrorObj(kTCPTimeoutErr,"Timeout while sending TCP data");
				
				// Make sure we're not going to block
				if (Poll(fIOSocket,false,true))
				{
					long	bytesSent = write(fIOSocket,bufferSegment,bytesRemaining);
					int		error = errno;
					
					if (bytesSent == 0)
					{
						if (error != EINTR)
						{
							// It wasn't a system-level interrupt.  Bail.
							throw TSymLibErrorObj(error,"Error while sending TCP data"); 
						}
					}
					else if (bytesSent < 0)
					{
						switch (error)
						{
							case EAGAIN:
								// Non-blocking I/O wasn't ready for us
								break;
							
							case EINTR:
								// System-level interrupt.  Try again.
								break;
							
							default:
								// Problem we can't handle.  Bail.
								throw TSymLibErrorObj(error,"Error while sending TCP data"); 
						}
					}
					else
					{
						bytesRemaining -= bytesSent;
						bufferSegment += bytesSent;
						
						if (IsTimeoutSet())
							expireTime = time(NULL) + GetTimeout();
					}
				}
				else
					throw TSymLibErrorObj(kTCPTimeoutErr,"While sending TCP data");
			}
		}
		catch (...)
		{
			fSendBuffer = "";
			throw;
		}
		
		allSent = (bytesRemaining == 0);
		fSendBuffer = "";
	}
	
	return allSent;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::Poll
//---------------------------------------------------------------------
bool TTCPConnectionObj::Poll (int socketNum, bool canRead, bool canWrite, bool enforceTimeout)
{
	bool	eventFound = false;
	
	#if HAVE_POLL
		short	eventMask = 0;
		short	result = 0;
		
		if (canRead)
			eventMask |= POLLIN;
		
		if (canWrite)
			eventMask |= POLLOUT;
		
		result = _Poll(socketNum,eventMask,enforceTimeout);
		
		if (result > 0)
			eventFound = true;
	#elif HAVE_SELECT
		eventFound = _Select(socketNum,canRead,canWrite,enforceTimeout);
	#endif
	
	return eventFound;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::Idle
//---------------------------------------------------------------------
bool TTCPConnectionObj::Idle ()
{
	return true;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::LocalIPAddress
//---------------------------------------------------------------------
unsigned long TTCPConnectionObj::LocalIPAddress () const
{
	unsigned long	localAddress = 0;

  if (IsConnected())
	{
		struct sockaddr_in	sockInfo;
		SOCKET_SIZE_TYPE	argSize = sizeof(sockInfo);
	
		if (getsockname(fIOSocket,reinterpret_cast<struct sockaddr*>(&sockInfo),&argSize) < 0)
			throw TSymLibErrorObj(errno,"While determining local IP address of the current connection");
		
		localAddress = sockInfo.sin_addr.s_addr;
	}
	
	return localAddress;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::LocalIPAddressAsString
//---------------------------------------------------------------------
std::string TTCPConnectionObj::LocalIPAddressAsString () const
{
	std::string		localAddress;
	
	if (IsConnected())
	{
		struct sockaddr_in	sockInfo;
		SOCKET_SIZE_TYPE	argSize = sizeof(sockInfo);
		
		if (getsockname(fIOSocket,reinterpret_cast<struct sockaddr*>(&sockInfo),&argSize) < 0)
			throw TSymLibErrorObj(errno,"While determining local IP address of the current connection");
		
		localAddress = IPAddressToString(sockInfo.sin_addr);
	}
	
	return localAddress;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::LocalPortNumber
//---------------------------------------------------------------------
int TTCPConnectionObj::LocalPortNumber () const
{
	int		portNum = 0;
	
	if (IsConnected())
	{
		struct sockaddr_in	sockInfo;
		SOCKET_SIZE_TYPE	argSize = sizeof(sockInfo);
		
		if (getsockname(fIOSocket,reinterpret_cast<struct sockaddr*>(&sockInfo),&argSize) < 0)
			throw TSymLibErrorObj(errno,"While determining local IP address of the current connection");
		
		portNum = sockInfo.sin_port;
	}
	
	return portNum;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::LocalInterfaceName
//---------------------------------------------------------------------
std::string TTCPConnectionObj::LocalInterfaceName () const
{
	std::string		interfaceName;

	if (IsConnected())
	{
		
    struct ifconf		ifc;
		struct ifreq		ifr;
		struct ifreq*		ifrPtr = NULL;
		struct ifreq*		ifrPtrEnd = NULL;
		struct ifreq*		ifrPtrNext = NULL;
		
    int             tempSocket;
    const int       kIFCBufferSize = sizeof(ifr) * 64;
    char            ifcBuffer[kIFCBufferSize];
    unsigned long   myIPAddress = LocalIPAddress();
		
		// Create a dummy socket to use for ioctl
		tempSocket = socket(AF_INET,SOCK_DGRAM,0);

		if (tempSocket < 0)
			throw TSymLibErrorObj(errno,"While creating a temporary socket");
		
		// Get the configured interfaces in a struct
		ifc.ifc_len = kIFCBufferSize;
		ifc.ifc_buf = ifcBuffer;

		if (ioctl(tempSocket,SIOCGIFCONF,&ifc) < 0)
		{
			close(tempSocket);
			throw TSymLibErrorObj(errno,"While calling ioctl");
		}
        
		ifrPtr = ifc.ifc_req;
		ifrPtrEnd = reinterpret_cast<struct ifreq*>((reinterpret_cast<char*>(ifrPtr) + ifc.ifc_len));
		
		while (ifrPtr < ifrPtrEnd)
		{
			#if HAVE_SOCKADDR_SA_LEN
				unsigned int	nSize = ifrPtr->ifr_addr.sa_len + sizeof(ifrPtr->ifr_name);
				
				if (nSize < sizeof(struct ifreq))
					ifrPtrNext = ifrPtr + 1;
				else
					ifrPtrNext = reinterpret_cast<struct ifreq*>(reinterpret_cast<char*>(ifrPtr) + nSize);
			#else
				ifrPtrNext = ifrPtr + 1;
			#endif
			
			if (ifrPtr->ifr_addr.sa_family == AF_INET)
			{
                
				strcpy(ifr.ifr_name,ifrPtr->ifr_name);
                
				if (ioctl(tempSocket,SIOCGIFFLAGS,&ifr) >= 0)
				{
					if ((ifr.ifr_flags & IFF_UP) == IFF_UP && (ifr.ifr_flags & IFF_LOOPBACK) != IFF_LOOPBACK)
					{
						if (ioctl(tempSocket,SIOCGIFADDR,&ifr) >= 0)
						{
							struct sockaddr_in*		addressPtr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
							unsigned long			foundAddress = *(reinterpret_cast<unsigned long*>(&addressPtr->sin_addr));
						
							if (foundAddress == myIPAddress)
							{
								interfaceName = ifrPtr->ifr_name;
								break;
							}
						}
					}
				}
			}
			
			ifrPtr = ifrPtrNext;
		}
		
		close(tempSocket);
	}
	
	return interfaceName;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::LocalMACAddress
//---------------------------------------------------------------------
std::string TTCPConnectionObj::LocalMACAddress () const
{
	std::string		macAddress;
	
  if (IsConnected())
	{
    std::string             interfaceName(LocalInterfaceName());
    
		if (!interfaceName.empty()) {
			macAddress = LocalHostMACAddress(interfaceName);
    }
	}
	
	return macAddress;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::LocalNetworkMask
//---------------------------------------------------------------------
unsigned long TTCPConnectionObj::LocalNetworkMask () const
{
	unsigned long	netMask = 0;
	
	if (IsConnected())
	{
		struct ifreq	ifr;
		std::string		device(LocalInterfaceName());
		
		strcpy(ifr.ifr_name,device.c_str());
		
		if (ioctl(fIOSocket,SIOCGIFNETMASK,&ifr) >= 0)
		{
			struct sockaddr_in*	addressPtr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
			
			netMask = *(reinterpret_cast<unsigned long*>(&addressPtr->sin_addr));
		}
	}
	
	return netMask;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::LocalNetworkMaskAsString
//---------------------------------------------------------------------
std::string TTCPConnectionObj::LocalNetworkMaskAsString () const
{
	std::string		netMask;
	
	if (IsConnected())
		netMask = IPAddressToString(LocalNetworkMask());
	
	return netMask;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::LocalBroadcastAddress
//---------------------------------------------------------------------
unsigned long TTCPConnectionObj::LocalBroadcastAddress () const
{
	unsigned long	broadcastAddress = 0;
	
	if (IsConnected())
	{
		struct ifreq	ifr;
		std::string		device(LocalInterfaceName());
		
		strcpy(ifr.ifr_name,device.c_str());
		
		if (ioctl(fIOSocket,SIOCGIFBRDADDR,&ifr) >= 0)
		{
			struct sockaddr_in*	addressPtr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
			
			broadcastAddress = *(reinterpret_cast<unsigned long*>(&addressPtr->sin_addr));
		}
	}
	
	return broadcastAddress;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::LocalBroadcastAddressAsString
//---------------------------------------------------------------------
std::string TTCPConnectionObj::LocalBroadcastAddressAsString () const
{
	std::string		broadcastAddress;
	
	if (IsConnected())
		broadcastAddress = IPAddressToString(LocalBroadcastAddress());
	
	return broadcastAddress;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::RemoteIPAddress
//---------------------------------------------------------------------
unsigned long TTCPConnectionObj::RemoteIPAddress () const
{
	unsigned long	address = 0;
	
	if (IsConnected())
		address = *(reinterpret_cast<const unsigned long*>(&fRemoteAddress.sin_addr));
	
	return address;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::RemoteIPAddressAsString
//---------------------------------------------------------------------
std::string TTCPConnectionObj::RemoteIPAddressAsString () const
{
	std::string		remoteAddress;
	
	if (IsConnected())
		remoteAddress = IPAddressToString(fRemoteAddress.sin_addr);
	
	return remoteAddress;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::RemotePortNumber
//---------------------------------------------------------------------
int TTCPConnectionObj::RemotePortNumber () const
{
	int		portNum = 0;
	
	if (IsConnected())
		portNum = fRemoteAddress.sin_port;
	
	return portNum;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::_CreateSocket (protected)
//---------------------------------------------------------------------
int TTCPConnectionObj::_CreateSocket (int domain, int type, int protocol)
{
	int		sockNum;
	
	do
	{
		sockNum = socket(domain,type,protocol);
	}
	while (sockNum <= 0 && errno == EINTR);
	
	if (sockNum < 0)
		throw TSymLibErrorObj(errno,"While creating a network socket");
	
	return sockNum;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::_Connect (protected)
//---------------------------------------------------------------------
int TTCPConnectionObj::_Connect (int tempSocket, int timeout)
{
	int		connectResult = 0;
	int		oldFlags = 0;
	bool	nonBlocking = (timeout > 0);
	
	if (nonBlocking)
	{
		// Temporarily put the socket into nonblocking mode
		oldFlags = fcntl(tempSocket,F_GETFL);
		fcntl(tempSocket,F_SETFL,oldFlags|O_NONBLOCK);
	}
	
	do
	{
		connectResult = connect(tempSocket,reinterpret_cast<struct sockaddr*>(&fRemoteAddress),sizeof(fRemoteAddress));
	}
	while (connectResult < 0 && errno == EINTR);
	
	if (connectResult < 0)
	{
		// This is not actually a bad thing, yet.  Since we're non-blocking,
		// see if the error code indicates that we're 'in progress'.
		if (nonBlocking && errno == EINPROGRESS)
		{
			// Fine.  Now we'll poll until our timeout, waiting for a connection
			long	oldTimeout = fTimeoutValue;
			bool	socketReady = false;
			
			try
			{
				fTimeoutValue = timeout;
				socketReady = Poll(tempSocket,false,true,true);
				fTimeoutValue = oldTimeout;
			}
			catch (...)
			{
				fTimeoutValue = oldTimeout;
				throw;
			}
			
			if (socketReady)
			{
				SOCKET_SIZE_TYPE	optionSize = sizeof(connectResult);
				
				// See if we actually succeeded
				do
				{
					if (getsockopt(tempSocket,SOL_SOCKET,SO_ERROR,(char*)&connectResult,&optionSize) < 0)
						throw TSymLibErrorObj(errno,"While polling for successful connection");
				}
				while (connectResult == -1);
				
				if (connectResult != 0)
					throw TSymLibErrorObj(connectResult);
			}
			else
			{
				// Timed out
				throw TSymLibErrorObj(kTCPTimeoutErr,"While polling for successful connection");
			}
		}
		else if (errno != 0)
		{
			// Bad stuff.  However, we'll just let our caller deal with it.
			throw TSymLibErrorObj(errno);
		}
	}
	
	if (nonBlocking)
		fcntl(tempSocket,F_SETFL,oldFlags);
	
	return connectResult;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::_ReceiveLine (protected)
//---------------------------------------------------------------------
std::string TTCPConnectionObj::_ReceiveLine (const StdStringList& endOfLinePatternList, unsigned long maxBytes)
{
	char				ioBuffer;
	std::string			buffer;
	unsigned long		bytesCollected = 0;
	time_t				expireTime = 0;
	
	if (IsIOSocketSet())
	{
		if (IsTimeoutSet())
			expireTime = time(NULL) + GetTimeout();
		
		while (true)
		{
			if (expireTime > 0 && time(NULL) > expireTime)
				throw TSymLibErrorObj(kTCPTimeoutErr,"Timeout while receiving TCP data");
			
			// Make sure we have data to read
			if (Poll(fIOSocket,true,false))
			{
				int		bytesRead = read(fIOSocket,&ioBuffer,1);
				int		error = errno;
				
				if (bytesRead == 0)
				{
					if (error != EAGAIN)
					{
						// Everything read
						break;
					}
				}
				else if (bytesRead > 0)
				{
					bool eolMatched = false;
					
					buffer += ioBuffer;
					++bytesCollected;
					
					if (IsTimeoutSet())
						expireTime = time(NULL) + GetTimeout();
					
					for (StdStringList_const_iter endOfLinePattern = endOfLinePatternList.begin(); !eolMatched && endOfLinePattern != endOfLinePatternList.end(); endOfLinePattern++)
					{
						unsigned long	eolSize = endOfLinePattern->length();
						
						if (bytesCollected >= eolSize)
						{
							// We have enough characters to check for end-of-line pattern
							bool	isEOL = true;
							
							for (unsigned long x = 1; x <= eolSize; x++)
							{
								if (buffer[bytesCollected-x] != (*endOfLinePattern)[eolSize-x])
								{
									isEOL = false;
									break;
								}
							}
							
							eolMatched = isEOL;
						}
					}
					
					if (eolMatched)
						break;
					else if (maxBytes > 0 && bytesCollected >= maxBytes)
						break;
				}
				else
				{
					if (error != EINTR && error != EAGAIN)
					{
						// Strange OS error, I think
						throw TSymLibErrorObj(error,"Error while receiving TCP data");
					}
				}
			}
			else
				throw TSymLibErrorObj(kTCPTimeoutErr,"Timeout while receiving TCP data");
		}
	}
	
	return buffer;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::_ReceiveBlock (protected)
//---------------------------------------------------------------------
std::string TTCPConnectionObj::_ReceiveBlock (unsigned long blockLength)
{
	int					bytesRead,error;
	char				ioBuffer[kRWBufferSize];
	std::string			buffer;
	
	// Initialize
	memset(ioBuffer,0,kRWBufferSize);
	
	if (IsIOSocketSet())
	{
		while (true)
		{
			// Make sure we have data to read
			if (Poll(fIOSocket,true,false))
			{
				bytesRead = read(fIOSocket,ioBuffer,std::min(kRWBufferSize,blockLength - buffer.length()));
				error = errno;
				if (bytesRead == 0)
				{
					if (error != EAGAIN)
					{
						// Everything read
						break;
					}
				}
				else if (bytesRead > 0)
				{
					buffer.append(ioBuffer,bytesRead);
					
					if (buffer.length() >= blockLength)
						break;
				}
				else
				{
					if (error != EINTR && error != EAGAIN)
					{
						// Strange OS error, I think
						throw TSymLibErrorObj(error,"Error while receiving TCP data");
					}
				}
			}
			else
				throw TSymLibErrorObj(kTCPTimeoutErr,"Timeout while receiving TCP data");
		}
	}
	
	return buffer;
}

//---------------------------------------------------------------------
// TTCPConnectionObj::_Poll (protected)
//---------------------------------------------------------------------
short TTCPConnectionObj::_Poll (int socketNum, short pollEvents, bool enforceTimeout)
{
	#if HAVE_POLL
		struct pollfd		pollInfo;
		int					pollResult = 0;
		time_t				expireTime = 0;
		
		if (enforceTimeout && IsTimeoutSet())
			expireTime = time(NULL) + GetTimeout();
		
		do
		{
			if (expireTime > 0 && time(NULL) > expireTime)
				throw TSymLibErrorObj(kTCPTimeoutErr,"While polling a socket");
			
			pollInfo.fd = socketNum;
			pollInfo.events = pollEvents;
			pollInfo.revents = 0;
			
			pollResult = poll(&pollInfo,1,1000);
			
			if (pollResult < 0)
			{
				pollInfo.revents = 0;
				if (errno == EINTR)
					pollResult = 0;
				else if (errno != 0)
					throw TSymLibErrorObj(errno);
			}
			else if (pollResult > 0)
			{
				if ((pollInfo.revents & POLLERR) != 0)
					throw TSymLibErrorObj(EIO,"Unknown error while polling TCP socket");
				else if ((pollInfo.revents & POLLHUP) != 0)
					throw TSymLibErrorObj(EPIPE,"TCP connection unexpectedly disconnected");
				else if ((pollInfo.revents & POLLNVAL) != 0)
					throw TSymLibErrorObj(EBADF,"TCP socket file descriptor not open");
			}
		}
		while (pollResult == 0 && pollInfo.revents == 0 && (fIdle ? Idle() : true));
		
		return pollInfo.revents;
	#else
		throw TSymLibErrorObj(kFunctionNotSupportedErr,"poll() is not supported on your platform");
		return 0;
	#endif
}

//---------------------------------------------------------------------
// TTCPConnectionObj::_Select (protected)
//---------------------------------------------------------------------
bool TTCPConnectionObj::_Select (int socketNum, bool canRead, bool canWrite, bool enforceTimeout)
{
	#if HAVE_SELECT
		bool				eventAvailable = false;
		fd_set				readSet;
		fd_set				writeSet;
		struct timeval		timeoutInfo;
		time_t				expireTime = 0;
		
		// Setup our sets
		FD_ZERO(&readSet);
		FD_ZERO(&writeSet);
		if (canRead)
			FD_SET(socketNum,&readSet);
		if (canWrite)
			FD_SET(socketNum,&writeSet);
		
		// Setup the timeout stuff if necessary
		if (enforceTimeout && IsTimeoutSet())
			expireTime = time(NULL) + GetTimeout();
		
		do
		{
			short	selectResult = 0;
			
			if (expireTime > 0 && time(NULL) > expireTime)
				throw TSymLibErrorObj(kTCPTimeoutErr,"While polling a socket");
			
			// Setup the timeout within the select() call
			timeoutInfo.tv_sec = 1;
			timeoutInfo.tv_usec = 1000;
			
			selectResult = select(socketNum+1,&readSet,&writeSet,NULL,&timeoutInfo);
			
			if (selectResult < 0)
			{
				if (errno == EINTR)
				{
					// We were interrupted; don't do anything, reloop
				}
				else
				{
					// Some other error occurred.
					throw TSymLibErrorObj(selectResult,"While polling TCP socket");
				}
			}
			else if (selectResult > 0)
			{
				// Something happened.  Yay!
				eventAvailable = true;
			}
		}
		while (!eventAvailable && (fIdle ? Idle() : true));
		
		return eventAvailable;
	#else
		throw TSymLibErrorObj(kFunctionNotSupportedErr,"select() is not supported on your platform");
		return false;
	#endif
}

//*********************************************************************
// Global Functions
//*********************************************************************

//---------------------------------------------------------------------
// IPAddressStringToULong
//---------------------------------------------------------------------
unsigned long IPAddressStringToULong (const std::string& addressString)
{
	return inet_addr(addressString.c_str());
}

//---------------------------------------------------------------------
// IPAddressToString
//---------------------------------------------------------------------
std::string IPAddressToString (unsigned long address)
{
	struct in_addr		addr;
	
	addr.s_addr = address;
	
	return IPAddressToString(addr);
}

//---------------------------------------------------------------------
// IPAddressToString
//---------------------------------------------------------------------
std::string IPAddressToString (const in_addr& address)
{
	return std::string(inet_ntoa(address));
}

//---------------------------------------------------------------------
// NetworkDescriptionFromSize
//---------------------------------------------------------------------
std::string NetworkDescriptionFromSize (unsigned long address, unsigned int networkSize)
{
	std::string		description;
	unsigned long	mask = static_cast<unsigned int>(-1);		// Set all bits to 1
	unsigned int	index = 2;
	unsigned int	maskNum = 32;
	
	while (index <= networkSize)
	{
		mask <<= 1;
		index <<= 1;
		--maskNum;
	}
	
	description = IPAddressToString(address & mask);
	description.append("/");
	description += NumToString(maskNum);
	
	return description;
}

//---------------------------------------------------------------------
// NetworkDescriptionFromSize
//---------------------------------------------------------------------
std::string NetworkDescriptionFromSize (const std::string& address, unsigned int networkSize)
{
	return NetworkDescriptionFromSize(IPAddressStringToULong(address),networkSize);
}

//---------------------------------------------------------------------
// IsAddressInNetwork
//---------------------------------------------------------------------
bool IsAddressInNetwork (unsigned long address, unsigned long network, unsigned int significantBits)
{
	unsigned long	mask = static_cast<unsigned int>(-1);		// Set all bits to 1
	unsigned int	index = 32;
	
	while (index > significantBits)
	{
		mask <<= 1;
		--index;
	}
	
	return ((address & mask) == (network & mask));
}

//---------------------------------------------------------------------
// IsAddressInNetwork
//---------------------------------------------------------------------
bool IsAddressInNetwork (const std::string& address, const std::string& network, unsigned int significantBits)
{
	return IsAddressInNetwork(IPAddressStringToULong(address),IPAddressStringToULong(network),significantBits);
}

//---------------------------------------------------------------------
// IsAddressInNetwork
//---------------------------------------------------------------------
bool IsAddressInNetwork (const std::string& address, const std::string& network)
{
	bool				ok = false;
	unsigned long		netAddress;
	unsigned int		significantBits;
	StdStringList		items;
	
	SplitStdString('/',network,items);
	if (!items.empty())
	{
		netAddress = IPAddressStringToULong(items[0]);
		if (items.size() > 1)
		{
			significantBits = static_cast<unsigned int>(StringToNum(items[1]));
		}
		else
		{
			significantBits = 32;
		}
		
		ok = IsAddressInNetwork(IPAddressStringToULong(address),netAddress,significantBits);
	}
	
	return ok;
}

//---------------------------------------------------------------------
// LocalHostName
//---------------------------------------------------------------------
std::string LocalHostName ()
{
	std::string		hostName;
	
	hostName.resize(128);
	while (gethostname(const_cast<char*>(hostName.data()),hostName.capacity()-1) < 0)
	{
		if (errno == EINVAL)
		{
			// Our buffer is too small
			hostName.resize(hostName.capacity() * 2);
		}
		else
			throw TSymLibErrorObj(errno,"While trying to get the local host's name");
	}
	
	// The contents of hostName are NULL-terminated, but the std::string object
	// doesn't know that.  We need to tell the object what the size really is.
	hostName.resize(strlen(hostName.c_str()));
	
	return hostName;
}

//---------------------------------------------------------------------
// LocalHostAddress
//---------------------------------------------------------------------
unsigned long LocalHostAddress ()
{
	unsigned long		address = 0;
	std::string			hostName(LocalHostName());
	
	if (!hostName.empty())
		address = GetHostAddress(hostName);
	
	return address;
}

//---------------------------------------------------------------------
// LocalHostAddressString
//---------------------------------------------------------------------
std::string LocalHostAddressString ()
{
	return IPAddressToString(LocalHostAddress());
}

//---------------------------------------------------------------------
// LocalHostInterfaceList
//---------------------------------------------------------------------
unsigned long LocalHostInterfaceList (StdStringList& interfaceList)
{
	struct ifconf		ifc;
	struct ifreq		ifr;
	struct ifreq*		ifrPtr = NULL;
	struct ifreq*		ifrPtrEnd = NULL;
	struct ifreq*		ifrPtrNext = NULL;
	int					tempSocket;
	const int			kIFCBufferSize = sizeof(ifr) * 64;
	char				ifcBuffer[kIFCBufferSize];
	
	// Clear the argument list
	interfaceList.clear();
	
	// Create a dummy socket to use for ioctl
	tempSocket = socket(AF_INET,SOCK_DGRAM,0);
	if (tempSocket < 0)
		throw TSymLibErrorObj(errno,"While creating a temporary socket");
	
	// Get the configured interfaces in a struct
	ifc.ifc_len = kIFCBufferSize;
	ifc.ifc_buf = ifcBuffer;
	if (ioctl(tempSocket,SIOCGIFCONF,&ifc) < 0)
	{
		close(tempSocket);
		throw TSymLibErrorObj(errno,"While calling ioctl");
	}
    
	ifrPtr = ifc.ifc_req;
	ifrPtrEnd = reinterpret_cast<struct ifreq*>((reinterpret_cast<char*>(ifrPtr) + ifc.ifc_len));
	
	while (ifrPtr < ifrPtrEnd)
	{
		#if HAVE_SOCKADDR_SA_LEN
			unsigned int	nSize = ifrPtr->ifr_addr.sa_len + sizeof(ifrPtr->ifr_name);
			
			if (nSize < sizeof(struct ifreq))
				ifrPtrNext = ifrPtr + 1;
			else
				ifrPtrNext = reinterpret_cast<struct ifreq*>(reinterpret_cast<char*>(ifrPtr) + nSize);
		#else
			ifrPtrNext = ifrPtr + 1;
		#endif
		
		if (ifrPtr->ifr_addr.sa_family == AF_INET)
		{
			strcpy(ifr.ifr_name,ifrPtr->ifr_name);
			if (ioctl(tempSocket,SIOCGIFFLAGS,&ifr) >= 0)
			{
				if ((ifr.ifr_flags & IFF_UP) == IFF_UP && (ifr.ifr_flags & IFF_LOOPBACK) != IFF_LOOPBACK)
				{
					interfaceList.push_back(ifrPtr->ifr_name);
				}
			}
		}
		
		ifrPtr = ifrPtrNext;
	}
	
	close(tempSocket);
	
	return interfaceList.size();
}

//---------------------------------------------------------------------
// LocalHostMACAddressList
//---------------------------------------------------------------------
unsigned long LocalHostMACAddressList (MACAddressMap& macAddressMap)
{
	struct ifconf		ifc;
	struct ifreq		ifr;
	struct ifreq*		ifrPtr = NULL;
	struct ifreq*		ifrPtrEnd = NULL;
	struct ifreq*		ifrPtrNext = NULL;
	int					tempSocket;
	const int			kIFCBufferSize = sizeof(ifr) * 64;
	char				ifcBuffer[kIFCBufferSize];

	// Clear the argument list
	macAddressMap.clear();
	
	// Create a dummy socket to use for ioctl
	tempSocket = socket(AF_INET,SOCK_DGRAM,0);
	if (tempSocket < 0)
		throw TSymLibErrorObj(errno,"While creating a temporary socket");

	// Get the configured interfaces in a struct
	ifc.ifc_len = kIFCBufferSize;
	ifc.ifc_buf = ifcBuffer;
	if (ioctl(tempSocket,SIOCGIFCONF,&ifc) < 0)
	{
		close(tempSocket);
		throw TSymLibErrorObj(errno,"While calling ioctl");
	}
    
	ifrPtr = ifc.ifc_req;
	ifrPtrEnd = reinterpret_cast<struct ifreq*>((reinterpret_cast<char*>(ifrPtr) + ifc.ifc_len));
	
	while (ifrPtr < ifrPtrEnd)
	{
		#if HAVE_SOCKADDR_SA_LEN
			unsigned int	nSize = ifrPtr->ifr_addr.sa_len + sizeof(ifrPtr->ifr_name);
			
			if (nSize < sizeof(struct ifreq))
				ifrPtrNext = ifrPtr + 1;
			else
				ifrPtrNext = reinterpret_cast<struct ifreq*>(reinterpret_cast<char*>(ifrPtr) + nSize);
		#else
			ifrPtrNext = ifrPtr + 1;
		#endif
		
		if (ifrPtr->ifr_addr.sa_family == AF_INET)
		{
			strcpy(ifr.ifr_name,ifrPtr->ifr_name);
			if (ioctl(tempSocket,SIOCGIFFLAGS,&ifr) >= 0)
			{
				if ((ifr.ifr_flags & IFF_UP) == IFF_UP && (ifr.ifr_flags & IFF_LOOPBACK) != IFF_LOOPBACK)
				{
					#if HAVE_DECL_SIOCGIFHWADDR
						strcpy(ifr.ifr_name,ifrPtr->ifr_name);
            std::string ifName(ifr.ifr_name);

						if (ioctl(tempSocket,SIOCGIFHWADDR,&ifr) >= 0)
						{
							std::string		addressBuf(ifr.ifr_hwaddr.sa_data,ETHER_ADDR_LEN);
							std::string		encodedAddress;
							const char		kEncodingTable[] = {'0','1','2','3','4','5',
																'6','7','8','9','A','B',
																'C','D','E','F'
																};
							
							encodedAddress.reserve(addressBuf.length() * 3);
							
							for (unsigned long x = 0; x < addressBuf.size(); x++)
							{
								unsigned char		charValue = addressBuf[x];
								unsigned char		msb = charValue / 16;
								unsigned char		lsb = charValue % 16;
								
								encodedAddress += kEncodingTable[msb];
								encodedAddress += kEncodingTable[lsb];
								if (x + 1 < addressBuf.size())
									encodedAddress += ':';
							}
							
							macAddressMap[ifName] = encodedAddress;
						}
					#else
						int			mib[6];
						size_t		argLength;
						
						mib[0] = CTL_NET;
						mib[1] = AF_ROUTE;
						mib[2] = 0;
						mib[3] = AF_LINK;
						mib[4] = NET_RT_IFLIST;
						mib[5] = 0;
						
						if (sysctl(mib,6,NULL,&argLength,NULL,0) >= 0)
						{
							std::string		tempBuffer;
							
							tempBuffer.resize(argLength);
							if (sysctl(mib,6,const_cast<char*>(tempBuffer.data()),&argLength,NULL,0) >= 0)
							{
								char*				begin = const_cast<char*>(tempBuffer.data());
								char*				end = begin + argLength;
								struct if_msghdr*	ifmPtr = NULL;
								
								for (char* next = begin ; next < end ; next += ifmPtr->ifm_msglen)
								{
									ifmPtr = reinterpret_cast<struct if_msghdr*>(next);
									if (ifmPtr->ifm_type == RTM_IFINFO)
									{
										struct sockaddr_dl*	sdl = reinterpret_cast<struct sockaddr_dl*>(ifmPtr + 1);
										std::string			sdlName(&sdl->sdl_data[0],sdl->sdl_nlen);
										
										if (sdlName == ifName)
										{
											std::string		addressBuf(LLADDR(sdl),ETHER_ADDR_LEN);
											std::string		encodedAddress;
											const char		kEncodingTable[] = {'0','1','2','3','4','5',
																				'6','7','8','9','A','B',
																				'C','D','E','F'
																				};
											
											encodedAddress.reserve(addressBuf.length() * 3);
											
											for (unsigned long x = 0; x < addressBuf.length(); x++)
											{
												unsigned char		charValue = addressBuf[x];
												unsigned char		msb = charValue / 16;
												unsigned char		lsb = charValue % 16;
												
												encodedAddress += kEncodingTable[msb];
												encodedAddress += kEncodingTable[lsb];
												if (x + 1 < addressBuf.length())
													encodedAddress += ':';
											}
											
											macAddressMap[ifName] = encodedAddress;
										}
									}
								}
							}
						}
					#endif
				}
			}
		}
		
		ifrPtr = ifrPtrNext;
	}
	
	close(tempSocket);
	
	return macAddressMap.size();
}

//---------------------------------------------------------------------
// LocalHostMACAddress
//---------------------------------------------------------------------
std::string LocalHostMACAddress (const std::string& interfaceName)
{
	std::string		macAddress;
	MACAddressMap	macMap;
	
	if (LocalHostMACAddressList(macMap) > 0)
		macAddress = macMap[interfaceName];
	
	return macAddress;
}

//---------------------------------------------------------------------
// GetHostAddress
//---------------------------------------------------------------------
unsigned long GetHostAddress (const std::string& hostName)
{
	unsigned long			address = 0;
	struct hostent*			hostEntryPtr = NULL;
	TLockedPthreadMutexObj	lock(gNameResolverMutex);
	
	hostEntryPtr = gethostbyname(hostName.c_str());
	
	if (hostEntryPtr)
		address = *((unsigned long*)(hostEntryPtr->h_addr));
	else
	{
		if (h_errno != 0)
			throw TSymLibErrorObj(h_errno);
		else if (errno != 0)
			throw TSymLibErrorObj(errno);
	}
	
	return address;
}

//---------------------------------------------------------------------
// GetAllHostAddresses
//---------------------------------------------------------------------
unsigned long GetAllHostAddresses (const std::string& hostName, NetworkAddressList& addressList)
{
	unsigned long			addressCount = 0;
	struct hostent*			hostEntryPtr = NULL;
	TLockedPthreadMutexObj	lock(gNameResolverMutex);
	
	addressList.clear();
	hostEntryPtr = gethostbyname(hostName.c_str());
	
	if (hostEntryPtr)
	{
		int				index = 0;
		unsigned long**	ipList = reinterpret_cast<unsigned long**>(hostEntryPtr->h_addr_list);
		
		while (true)
		{
			unsigned long	address = (*ipList)[index];
						
			if (address != 0)
			{
				addressList.push_back(address);
				++index;
			}
			else
			{
				break;
			}
		}
		
		addressCount = addressList.size();
	}
	else
	{
		if (h_errno != 0)
			throw TSymLibErrorObj(h_errno);
		else if (errno != 0)
			throw TSymLibErrorObj(errno);
	}
	
	return addressCount;
}

//---------------------------------------------------------------------
// LocalHostIPMap
//---------------------------------------------------------------------
unsigned long LocalHostIPMap(IPAddressMap& ipAddressMap)
{
    struct ifconf		ifc;
    struct ifreq		ifr;
    struct ifreq*		ifrPtr = NULL;
    struct ifreq*		ifrPtrEnd = NULL;
    struct ifreq*		ifrPtrNext = NULL;
    int					    tempSocket;
    const int			  kIFCBufferSize = sizeof(ifr) * 64;
    char				    ifcBuffer[kIFCBufferSize];

    // Clear the argument list
    ipAddressMap.clear();
	
    // Create a dummy socket to use for ioctl
	  tempSocket = socket(AF_INET,SOCK_DGRAM,0);
	  if (tempSocket < 0)
		  throw TSymLibErrorObj(errno,"While creating a temporary socket");
	
    // Get the configured interfaces in a struct
    ifc.ifc_len = kIFCBufferSize;
    ifc.ifc_buf = ifcBuffer;
    if (ioctl(tempSocket,SIOCGIFCONF,&ifc) < 0)
    {
      close(tempSocket);
      throw TSymLibErrorObj(errno,"While calling ioctl");
    }

    ifrPtr = ifc.ifc_req;
    ifrPtrEnd = reinterpret_cast<struct ifreq*>((reinterpret_cast<char*>(ifrPtr) + ifc.ifc_len));
    
    while (ifrPtr < ifrPtrEnd)
	  {
        #if HAVE_SOCKADDR_SA_LEN
        unsigned int	nSize = ifrPtr->ifr_addr.sa_len + sizeof(ifrPtr->ifr_name);
        
        if (nSize < sizeof(struct ifreq))
          ifrPtrNext = ifrPtr + 1;
        else
          ifrPtrNext = reinterpret_cast<struct ifreq*>(reinterpret_cast<char*>(ifrPtr) + nSize);
        #else
        ifrPtrNext = ifrPtr + 1;
        #endif
		
        if (ifrPtr->ifr_addr.sa_family == AF_INET)
        {
            strcpy(ifr.ifr_name,ifrPtr->ifr_name);
            
            std::string ifName(ifrPtr->ifr_name);
            
            if (ioctl(tempSocket,SIOCGIFFLAGS,&ifr) >= 0)
            {
                if ((ifr.ifr_flags & IFF_UP) == IFF_UP && (ifr.ifr_flags & IFF_LOOPBACK) != IFF_LOOPBACK)
                {
                    if (ioctl(tempSocket,SIOCGIFADDR,&ifr) >= 0)
                    {
                    
                        struct sockaddr_in*		addressPtr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
                        unsigned long			foundAddress = *(reinterpret_cast<unsigned long*>(&addressPtr->sin_addr));

                        std::string ipAddress = IPAddressToString(foundAddress); 
                        ipAddressMap[ifName] = ipAddress;
                    }
                }
            }
        }
        ifrPtr = ifrPtrNext;
    }
    close(tempSocket);

    return ipAddressMap.size();
}
//---------------------------------------------------------------------
// LocalHostIPAddress
//---------------------------------------------------------------------
std::string LocalHostIPAddress (const std::string& interfaceName)
{
	
  std::string		ipAddress;
	IPAddressMap  ipAddressMap;

  if (LocalHostIPMap(ipAddressMap) > 0) 
    ipAddress = ipAddressMap[interfaceName];

  return ipAddress;
}
//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

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
#		Last Modified:				29 Jan 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_TCP)
#define SYMLIB_TCP

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-config.h"

#include "symlib-utils.h"
#include "symlib-defs.h"

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define		kTCPTimeoutErr									-13503

typedef		std::vector<unsigned long>						NetworkAddressList;
typedef		NetworkAddressList::iterator					NetworkAddressList_iter;
typedef		NetworkAddressList::const_iterator    NetworkAddressList__const_iter;

typedef		std::map<std::string,std::string>     MACAddressMap;
typedef		MACAddressMap::iterator               MACAddressMap_iter;
typedef		MACAddressMap::const_iterator         MACAddressMap_const_iter;

typedef		std::map<std::string,std::string>     IPAddressMap;
typedef		IPAddressMap::iterator                IPAddressMap_iter;
typedef		IPAddressMap::const_iterator          IPAddressMap_const_iter;

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TTCPConnectionObj;

//---------------------------------------------------------------------
// Class TTCPConnectionObj
//---------------------------------------------------------------------
class TTCPConnectionObj
{
	public:
		
		static const unsigned long	kRWBufferSize;
	
	protected:
		
		static const long			kTCPTimeoutNone;
		static const int			kTCPSocketNone;
		static const int			kTCPLingerNone;
		static const int			kIOBufferSizeSystemDefault;
		
		typedef void* (*ThreadProcedure)(void*);
	
	public:
		
		TTCPConnectionObj ();
			// Constructor
		
		virtual ~TTCPConnectionObj ();
			// Destructor
		
		virtual bool Connect (unsigned long networkAddress,
							  int port,
							  int ioBufferSize = kIOBufferSizeSystemDefault,
							  int connectTimeout = kTCPTimeoutNone);
			// Connects to the port at the given address.  This method returns
			// a boolean indicating if the connection was made successfully.
		
		virtual bool Connect (const std::string& host,
							  int port,
							  int ioBufferSize = kIOBufferSizeSystemDefault,
							  int connectTimeout = kTCPTimeoutNone);
			// Connects to the port on the given named host.  The
			// host argument may be either an empty string, "localhost" or
			// "127.0.0.1"" to specify a loopback connection.  Otherwise,
			// the host argument may be either a named host or an IP
			// address in standard dot notation.  This method returns
			// a boolean indicating if the connection was made successfully.
		
		virtual void Disconnect ();
			// Closes all open connections (if necessary).
		
		virtual void CloseIOSocket ();
			// Closes the I/O socket, if it is open.
		
		virtual std::string Receive (char endOfTxChar, unsigned long maxBytes = 0);
			// Method reads pending data from the current connection up to
			// (but not including) an end-of-transmission character.  If
			// maxBytes is provided then a maximum of maxBytes incoming data
			// will be collected.  The collected data is returned.
		
		virtual std::string Receive (const std::string& endOfTxPattern, unsigned long maxBytes = 0);
			// Method reads pending data from the current connection up to
			// (and including) an end-of-transmission pattern.  If maxBytes
			// is provided then a maximum of maxBytes incoming data will be
			// collected.  The collected data is returned.
		
		virtual std::string Receive (const char* endOfTxPattern, unsigned long maxBytes = 0);
			// Convenience method.
		
		virtual std::string Receive (const StdStringList& endOfTxPatternList, unsigned long maxBytes = 0);
			// Method reads pending data from the current connection up to
			// (and including) one of the end-of-transmission patterns found
			// in the endOfTxPatternList list.  if maxBytes is provided then a
			// maximum of maxBytes incoming data will be collected.  The collected
			// data is returned.
		
		virtual std::string ReceiveBlock (unsigned long byteCount);
			// Method reads the indicated number of bytes from the current
			// connection and returns that data in a temporary buffer object.
		
		virtual bool ToSend (const std::string& stuffToSend);
			// Collects the contents of the argument into the internal buffer
			// for eventual send via the Send() call.
		
		virtual bool Send (const std::string& stuffToSend);
			// Sends the contents of the argument to the current
			// connection.  Returns a boolean indicating whether
			// all of the contents were successfully sent or not.
		
		virtual bool Poll (int socketNum, bool canRead, bool canWrite, bool enforceTimeout = true);
			// Method polls socketNum for the read/write events designated by the
			// arguments, and returns a boolean indicating whether any such event
			// was found Method supports the Idle() method, after blocking for a
			// short time while waiting for events.  Also supports the timeout
			// parameter, which can cause a throw kTCPTimeoutErr if a timeout occurs.
		
		virtual bool Idle ();
			// This method is called periodically when this object
			// is idle, either waiting for input or waiting for
			// an outbound stream to clear.  The return value should
			// indicate to the calling function that "everything is okay"
			// and that the caller should continue with whatever task
			// is at hand; true indicates okay, false otherwise.
			// Subclasses may override this method to handle other needs
			// during this idle time.  This instance of the method does nothing.
		
		virtual unsigned long LocalIPAddress () const;
			// Returns the local IP address being used for the current connection
			// as an unsigned long, in network-byte order.  Note that there must
			// be a connection for this to succeed; method returns zero if no
			// connection is present.
		
		virtual std::string LocalIPAddressAsString () const;
			// Returns the local IP address being used for the current connection
			// as a string.  Note that there must be a connection for this to
			// succeed; method returns an empty string if no connection is present.
		
		virtual int LocalPortNumber () const;
			// Returns the port number we're current using on the local side of a
			// connection.  Note that there must be a connection for this to
			// succeed; method returns zero if no connection is present.
		
		virtual std::string LocalInterfaceName () const;
			// Returns the logical name of the local interface we currently have
			// a connection through.  Note that there must be a connection for this
			// to succeed; method returns an empty string if no connection is present.
		
		virtual std::string LocalMACAddress () const;
			// Returns the MAC address of the local interface we currently have a
			// connection through.  Note that there must be a connection for this
			// to succeed; method returns an empty string if no connection is present.
		
		virtual unsigned long LocalNetworkMask () const;
			// Returns the network mask of the local interface we currently have a
			// connection through.  Note that there must be a connection for this to
			// succeed; method returns zero if no connection is present.
		
		virtual std::string LocalNetworkMaskAsString () const;
			// Returns the network mask of the local interface we currently have a
			// connection through.  Note that there must be a connection for this to
			// succeed; method returns an empty string if no connection is present.
		
		virtual unsigned long LocalBroadcastAddress () const;
			// Returns the broadcast address of the local interface we currently have a
			// connection through.  Note that there must be a connection for this to
			// succeed; method returns zero if no connection is present.
		
		virtual std::string LocalBroadcastAddressAsString () const;
			// Returns the broadcast address of the local interface we currently have a
			// connection through.  Note that there must be a connection for this to
			// succeed; method returns an empty string if no connection is present.
		
		virtual unsigned long RemoteIPAddress () const;
			// Returns the remote IP address being used for the current connection
			// as an unsigned long, in network-byte order.  Note that there must
			// be a connection for this to succeed; method returns zero if no
			// connection is present.
		
		virtual std::string RemoteIPAddressAsString () const;
			// Returns the remote IP address being used for the current connection
			// as a string.  Note that there must be a connection for this to
			// succeed; method returns an empty string if no connection is present.
		
		virtual int RemotePortNumber () const;
			// Returns the port number we're currently connected to on the remote
			// side.  Note that there must be a connection for this to work; method
			// returns zero if no connection is present.
		
		// Accessors
		inline long GetTimeout () const
			{ return fTimeoutValue; }
		inline void SetTimeout (long newTimeout)
			{ fTimeoutValue = newTimeout; }
		inline int GetIOSocket () const
			{ return fIOSocket; }
		inline void SetIOSocket (int socketFD)
			{ fIOSocket = socketFD; }
		inline int GetLingerTime () const
			{ return fLingerTime; }
		inline void SetLingerTime (int newLingerTime)
			{ fLingerTime = newLingerTime; }
		inline void SetThreadedHandling (bool threadsOn)
			{ fProcessInboundThreaded = threadsOn; }
		inline void SetIdling (bool idleOn)
			{ fIdle = idleOn; }
		
		// Testers
		inline bool IsTimeoutSet () const
			{ return fTimeoutValue != kTCPTimeoutNone; }
		inline bool IsIOSocketSet () const
			{ return fIOSocket != kTCPSocketNone; }
		inline bool IsLingerSet () const
			{ return fLingerTime != kTCPLingerNone; }
		inline bool IsConnected () const
			{ return fIOSocket != kTCPSocketNone; }
	
	protected:
		
		virtual int _CreateSocket (int domain = AF_INET,
								   int type = SOCK_STREAM,
								   int protocol = 0);
			// Method simply creates a socket and returns the associated
			// file descriptor (or -1 if there has been an error).
		
		virtual int _Connect (int tempSocket, int timeout = 0);
			// Issues a connection request.  Will throw an exception if
			// there is an error.
		
		virtual std::string _ReceiveLine (const StdStringList& endOfLinePatternList, unsigned long maxBytes);
			// Reads from the currently-opened connection until one of the specified
			// end-of-line patterns is received or until maxBytes number of bytes
			// is received.  The matched end-of-line pattern is included in the return value.
		
		virtual std::string _ReceiveBlock (unsigned long blockLength);
			// Reads the indicated number of bytes from the currently-opened
			// connection and returns the collected data.
		
		virtual short _Poll (int socketNum, short pollEvents, bool enforceTimeout);
			// Method polls socketNum for the events designated by the
			// pollEvents argument, and returns the events actually found.
			// Method supports the Idle() method, after blocking for a
			// short time while waiting for events.  Also supports the
			// timeout parameter, which can cause a throw kTCPTimeoutErr
			// if a timeout occurs.  This function uses the poll() system call
			// and is therefore not implemented under certain builds.
		
		virtual bool _Select (int socketNum, bool canRead, bool canWrite, bool enforceTimeout);
			// Method polls socketNum for the events indicated by the
			// canRead and canWrite booleans, returning a boolean indicating
			// whether any event was found.  Method supports the Idle()
			// method, after blocking for a short time while waiting for the
			// events.  Also supports the timeout parameter, which can cause a
			// thor kTCPTimeoutErr if a timeout occurs.  This function uses the
			// select() system call.  As the poll() call is preferred, this function
			// is implemented only when poll() is not available.
		
		struct sockaddr_in					fRemoteAddress;
		std::string							fSendBuffer;
		long								fTimeoutValue;
		int									fIOSocket;
		int									fLingerTime;
		bool								fProcessInboundThreaded;
		bool								fIdle;
};

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

unsigned long IPAddressStringToULong (const std::string& addressString);
	// Function takes an IP address in dotted-quad string form
	// and converts it to an unsigned long.  The byte-order of
	// the returned value the same as network byte ordering, which
	// is big-endian.

std::string IPAddressToString (unsigned long address);
	// Converts an IP address formatted as an unsigned long (in network
	// byte order) and converts it to a human-readable string.

std::string IPAddressToString (const in_addr& address);
	// Convert an IP address structure and converts it to a human-readable string.

std::string NetworkDescriptionFromSize (unsigned long address, unsigned int networkSize);
	// Given an IP address in a network, and the size of the network
	// (eg, 8 machines), this function returns a temporary string
	// describing the network in Cisco-style notation (eg, 198.168.113.144/29).

std::string NetworkDescriptionFromSize (const std::string& address, unsigned int networkSize);
	// Same as above, except the address is a dotted-quad-format
	// IP address.

bool IsAddressInNetwork (unsigned long address, unsigned long network, unsigned int significantBits);
	// Tests the given address against the network defined by the network
	// and significantBits to see if the address is really within the
	// network.  The address and network arguments must be in network
	// byte order.  The significantBits argument is the number that follows the
	// slash in Cisco-style network descriptions.

bool IsAddressInNetwork (const std::string& address, const std::string& network, unsigned int significantBits);
	// Same as above, except the address and network arguments can be
	// dotted-quad-formatted strings.

bool IsAddressInNetwork (const std::string& address, const std::string& network);
	// Same as above, except the network argument is a Cisco-style network
	// description (eg, 198.168.113.144/29).

std::string LocalHostName ();
	// Returns the name of the local host system.

unsigned long LocalHostAddress ();
	// Returns the IP address (in network byte order) of the local host system.

std::string LocalHostAddressString ();
	// Convenience function.  Returns the IP address (in dotted-quad
	// string form) of the local host system.

unsigned long LocalHostInterfaceList (StdStringList& interfaceList);
	// Function destructively modifies the argument to contain a list of
	// logical network interface names (eg, "eth0").  The local loopback
	// interface is discarded.  The interface must be up to be included
	// in the list.  Returns the number of such interfaces found.

unsigned long LocalHostMACAddressList (MACAddressMap& macAddressMap);
	// Function destructively modifies the argument to contain a list of
	// all hardware interfaces on the local system.  The key is the name
	// of the interface (eg, "eth0") and the value is the MAC address.
	// The MAC address is returned in XX:XX:XX:XX:XX:XX format.
	// The function returns the number of interfaces found.

std::string LocalHostMACAddress (const std::string& interfaceName);
	// Returns the MAC address of the given interface name (as if returned from
	// LocalHostInterfaceList()).  The returned MAC address is in the format
	// XX:XX:XX:XX:XX:XX; an empty string is returned if the interface is not found.

unsigned long GetHostAddress (const std::string& hostName);
	// Given a host name this function returns the IP address (in network
	// byte order) of that host.

unsigned long GetAllHostAddresses (const std::string& hostName, NetworkAddressList& addressList);
	// Given a host name this function destructively modifies the
	// addressList argument to contain a list of all associated IP
	// addresses (in network byte order) for that host.  Returns
	// the number of IP addresses in the list.

unsigned long LocalHostIPMap (IPAddressMap& ipAddressMap);
  // Function destructively modifies the argument to contain a map of
  // interfaces and ip addresses .  The local loopback interface is 
  // discarded.  The interface must be up to be includedin the list.  
  // Returns the number of ip addresses.

std::string LocalHostIPAddress (const std::string& interfaceName);
  // Returns the ip address of the given interface name.  The returned ip address 
  // is in the format XXX.XXX.XXX.XXX; an empty string is returned if the interface 
  // is not found.

unsigned long LocalNetworkMask (const std::string& interfaceName);
  // Returns the network mask of the specified interface ("eth0").
  // Note that there must be a connection for this to succeed; method returns zero 
  // if no connection is present.
		
std::string LocalNetworkMaskAsString (const std::string& interfaceName);
  // Returns the network mask of the specified interface ("eth0"). 
  // Note that there must be a connection for this to succeed; method returns an 
  // empty string if no connection is present.

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif // SYMLIB_TCP

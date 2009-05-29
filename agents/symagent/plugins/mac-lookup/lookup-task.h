/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Plugin agent to lookup remote machines' MAC addresses
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					03 Feb 2004
#		Last Modified:				24 Mar 2004
#		
#######################################################################
*/

#if !defined(LOOKUP_TASK)
#define LOOKUP_TASK

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"
#include "plugin-utils.h"

//---------------------------------------------------------------------
// Import namespace symbols
//---------------------------------------------------------------------
using symbiot::TTaskBase;
using symbiot::TServerMessage;
using symbiot::TMessageNode;

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TLookupMACAddrTask;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define	kDefaultExecutionInterval						60*10	// 10 minutes

#define		kErrorNetworkDeviceNotSpecified				-24201
#define		kErrorScanTargetNotSpecified				-24202
#define		kErrorInvalidScanTarget						-24203
#define		kErrorUnableToObtainLocalIPAddress			-24204
#define		kErrorUnableToObtainLocalNetMask			-24205
#define		kErrorUnableToObtainBPFDeviceDescriptor		-24206

typedef		vector<unsigned long>						IPAddressList;
typedef		IPAddressList::iterator						IPAddressList_iter;
typedef		IPAddressList::const_iterator				IPAddressList_const_iter;

//---------------------------------------------------------------------
// Class TLookupMACAddrTask
//---------------------------------------------------------------------
class TLookupMACAddrTask : public TTaskBase
{
	private:
		
		typedef	TTaskBase						Inherited;
	
	public:
		
		TLookupMACAddrTask ();
			// Constructor
	
	private:
		
		TLookupMACAddrTask (const TLookupMACAddrTask& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TLookupMACAddrTask ();
			// Destructor
		
		virtual void SetupTask (const string& deviceName,
								const string& scanTarget,
								time_t scanInterval = 0);
			// Sets up the object for future MAC address lookups.  The deviceName
			// argument indicates which network interface to use.  The scanTarget
			// argument tells the plugin what to scan.  Valid formats for this
			// argument are:
			//
			//		host name
			//		IPv4 dotted-quad address
			//		host name with network mask (eg, myhost.mydomain.com/28)
			//		IPv4 address with network mask (eg, 192.168.1.0/28)
		
		virtual void RunTask ();
			// Thread entry point for the task.  Really just a wrapper for Main().
		
		virtual void Main (TServerMessage& messageObj);
			// еее
	
	protected:
		
		virtual unsigned long _ParseScanTarget ();
			// Parses the string contained in fScanTarget, exploding it into
			// a list of IP addresses to scan.  Returns the number of resulting
			// addresses.
		
		virtual unsigned long _GetIPAddress (const string& deviceName) const;
			// Retrieves the IP address from the given interface and returns
			// it as an unsigned long.
		
		virtual unsigned long _GetNetworkMask (const string& deviceName) const;
			// Retrieves the network mask from the given interface and returns
			// it as an unsigned long.
	
	protected:
		
		string									fMyDeviceName;
		string									fScanTarget;
		IPAddressList							fIPAddressList;
		ModEnviron*								fParentEnvironPtr;
			
};

#if USE_NETPACKET
	//---------------------------------------------------------------------
	// Class TARPTaskNetpacket
	//---------------------------------------------------------------------
	class TARPTaskNetpacket : public TTaskBase
	{
		private:
			
			typedef	TTaskBase						Inherited;
		
		public:
			
			TARPTaskNetpacket (const string& deviceName, const IPAddressList& ipAddressList);
				// Constructor
		
		private:
			
			TARPTaskNetpacket (const TARPTaskNetpacket& obj) {}
				// Copy constructor is illegal
		
		public:
			
			virtual ~TARPTaskNetpacket ();
				// Destructor
			
			virtual void RunTask ();
				// Thread entry point for the task.
		
		protected:
			
			virtual void _GetRemoteMACAddress (unsigned long remoteIPAddress) const;
				// Given a remote IP address expressed as an unsigned long in network
				// byte order, this method uses ARP to determine the corresponding
				// MAC address.  The pair is then written to a thread-specific
				// global structure.
		
		protected:
			
			ModEnviron*								fParentEnvironPtr;
			IPAddressList							fIPAddressList;
			string									fDeviceName;
				
	};
	
	typedef TARPTaskNetpacket TARPTask;
#endif

#if USE_BPF
	//---------------------------------------------------------------------
	// Class TARPTaskBPF
	//---------------------------------------------------------------------
	class TARPTaskBPF : public TTaskBase
	{
		private:
			
			typedef	TTaskBase						Inherited;
		
		public:
			
			TARPTaskBPF (const string& deviceName, const IPAddressList& ipAddressList);
				// Constructor
		
		private:
			
			TARPTaskBPF (const TARPTaskBPF& obj) {}
				// Copy constructor is illegal
		
		public:
			
			virtual ~TARPTaskBPF ();
				// Destructor
			
			virtual void RunTask ();
				// Thread entry point for the task.
		
		protected:
			
			virtual void _GetRemoteMACAddress (unsigned long remoteIPAddress) const;
				// Given a remote IP address expressed as an unsigned long in network
				// byte order, this method uses ARP to determine the corresponding
				// MAC address.  The pair is then written to a thread-specific
				// global structure.
			
			virtual int _OpenBPFDevice (unsigned long remoteIPAddress) const;
				// Returns the file descriptor for an open BPF device.
			
			virtual string _GetMyMACAddress () const;
				// Returns the MAC address of the fDeviceName as a compacted string
				// (not human-readable).
		
		protected:
			
			ModEnviron*								fParentEnvironPtr;
			IPAddressList							fIPAddressList;
			string									fDeviceName;
				
	};
	
	typedef TARPTaskBPF TARPTask;
#endif

//---------------------------------------------------------------------
#endif // LOOKUP_TASK

/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Plugin to report network activity in realtime
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					11 Nov 2003
#		Last Modified:				10 Jan 2004
#		
#######################################################################
*/

#if !defined(PACKET_OBJS)
#define PACKET_OBJS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"
#include "pcap-interface.h"
#include "network-headers.h"

#include <algorithm>
#include <netinet/ip.h>				// struct ip

#if HAVE_NETDB_H
	#include <netdb.h>
#endif

#if HAVE_DECL_AF_INET6
	#include <netinet/ip6.h>		// struct ip6
#endif
// #include <netinet/if_ether.h>		// includes net/ethernet.h -- struct ether_header
#include <netinet/tcp.h>			// struct tcphdr
#include <netinet/udp.h>			// struct udphdr
#include <netinet/ip_icmp.h>		// struct icmp

#if HAVE_DECL_AF_INET6
	#include <netinet/icmp6.h>		// struct icmp6_hdr
#endif

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TPacket;
class TPacketIPv4;
class TPacketTCPv4;
class TPacketUDPv4;
class TPacketICMPv4;
class TPacketARP;

#if HAVE_DECL_AF_INET6
	class TPacketIPv6;
	class TPacketTCPv6;
	class TPacketUDPv6;
	class TPacketICMPv6;
#endif

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef	enum
		{
			kPacketTypeUnknown = 0,
			kPacketTypeEthernet,
			kPacketTypeIPv4,
			kPacketTypeTCPv4,
			kPacketTypeUDPv4,
			kPacketTypeICMPv4,
			kPacketTypeARP,
			kPacketTypeIPv6,
			kPacketTypeTCPv6,
			kPacketTypeUDPv6,
			kPacketTypeICMPv6
		} PacketTypeCode;

//---------------------------------------------------------------------
// Class TPacket
//
// Base class - do not instantiate directly.
//---------------------------------------------------------------------
class TPacket
{
	protected:
		
		TPacket (const TCapturedPacket* packetPtr = NULL) : fRawPacketPtr(packetPtr) {}
		TPacket (const TPacket& obj) : fRawPacketPtr(obj.fRawPacketPtr) {}
	
	public:
		
		virtual ~TPacket () {}
		
		virtual PacketTypeCode PacketType () const
			{ return kPacketTypeUnknown; }
		
		virtual string ProtocolFamilyDescription () const
			{ return string("unknown"); }
		
		virtual string PacketTypeDescription () const
			{ return string("unknown"); }
		
		virtual bool IsPacketType (PacketTypeCode code) const
			{ return (code == PacketType()); }
		
		inline unsigned long CapturedSize () const
			{ return fRawPacketPtr->CapturedSize(); }
		
		inline unsigned long ActualSize () const
			{ return fRawPacketPtr->ActualSize(); }
		
		inline struct timeval Timestamp () const
			{ return fRawPacketPtr->Timestamp(); }
		
		inline double TimestampMilliseconds () const
			{
				double			millisecondTime;
				struct timeval	timeStamp = Timestamp();
				
				millisecondTime = timeStamp.tv_usec;
				millisecondTime /= 1000000;
				millisecondTime += timeStamp.tv_sec;
				
				return millisecondTime;
			}
		
		inline string TimestampString () const
			{
				string			timeString;
				struct timeval	timeStamp = Timestamp();
				time_t			timeNow = time(NULL);
				long			gmDiff = 0;
				int				temp = 0;
				
				gmDiff = mktime(localtime(&timeNow)) - mktime(gmtime(&timeNow));
				temp = (timeStamp.tv_sec + gmDiff) % 86400;
				
				timeString.resize(32);
				sprintf(const_cast<char*>(timeString.c_str()),
						"%02d:%02d:%02d.%06u",
						temp/3600,
						(temp % 3600) / 60,
						temp % 60,
						static_cast<unsigned int>(timeStamp.tv_usec));
				timeString.resize(strlen(timeString.c_str()));
				
				return timeString;
			}
		
		virtual const u_char* PayloadPtr () const
			{ return NULL; }
		
		virtual unsigned long PayloadSize () const
			{
				unsigned long	totalHeaderSize = reinterpret_cast<unsigned long>(PayloadPtr()) - reinterpret_cast<unsigned long>(fRawPacketPtr->Data());
				
				return ActualSize() - totalHeaderSize;
			}
		
		// ------------------------------------------------
		// Ethernet object methods
		// ------------------------------------------------
		
		virtual unsigned long EthernetHeaderSize () const
			{ return 0; }
		
		virtual const struct ether_header* EthernetHeaderPtr () const
			{ return NULL; }
		
		virtual const u_char* AfterEthernetHeaderPtr () const
			{ return NULL; }
		
		virtual string SourceMACAddressAsString () const
			{ return string(); }
			// Returns the MAC address of the packet's source as a string.
		
		virtual string DestinationMACAddressAsString () const
			{ return string(); }
			// Returns the MAC address of the packet's destination as a string.
		
		// ------------------------------------------------
		// IP object methods
		// ------------------------------------------------
		
		virtual unsigned long IPHeaderSize () const
			{ return 0; }
		
		virtual const struct ip* IPHeaderPtr () const
			{ return NULL; }
		
		virtual const u_char* AfterIPHeaderPtr () const
			{ return NULL; }
		
		virtual string SourceIPAddressAsString () const
			{ return string(); }
			// Returns the IP address of the packet's source as a string.
		
		virtual string DestinationIPAddressAsString () const
			{ return string(); }
			// Returns the IP address of the packet's destination as a string.
		
		virtual unsigned long IPv6HeaderSize () const
			{ return 0; }
		
		virtual const struct ip6_hdr* IPv6HeaderPtr () const
			{ return NULL; }
		
		virtual const u_char* AfterIPv6HeaderPtr () const
			{ return NULL; }
		
		// ------------------------------------------------
		// TCP/IP object methods
		// ------------------------------------------------
		
		virtual unsigned long TCPHeaderSize () const
			{ return 0; }
		
		virtual const struct tcphdr* TCPHeaderPtr () const
			{ return NULL; }
		
		virtual const u_char* AfterTCPHeaderPtr () const
			{ return NULL; }
		
		virtual unsigned int SourcePort () const		// also used in UDP
			{ return 0; }
		
		virtual unsigned int DestinationPort () const	// also used in UDP
			{ return 0; }
		
		virtual unsigned int SequenceNumber () const	// also used in UDP
			{ return 0; }
		
		// ------------------------------------------------
		// UDP object methods
		// ------------------------------------------------
		
		virtual unsigned long UDPHeaderSize () const
			{ return 0; }
		
		virtual const struct udphdr* UDPHeaderPtr () const
			{ return NULL; }
		
		virtual const u_char* AfterUDPHeaderPtr () const
			{ return NULL; }
		
		// ------------------------------------------------
		// ICMP object methods
		// ------------------------------------------------
		
		virtual unsigned long ICMPHeaderSize () const
			{ return 0; }
		
		virtual const struct icmp* ICMPHeaderPtr () const
			{ return NULL; }
		
		virtual const u_char* AfterICMPHeaderPtr () const
			{ return NULL; }
		
		virtual unsigned long ICMPv6HeaderSize () const
			{ return 0; }
		
		virtual const struct icmp6_hdr* ICMPv6HeaderPtr () const
			{ return NULL; }
		
		virtual const u_char* AfterICMPv6HeaderPtr () const
			{ return NULL; }
		
		// ------------------------------------------------
		// ARP object methods
		// ------------------------------------------------
		
		virtual unsigned long ARPHeaderSize () const
			{ return 0; }
		
		virtual const struct arphdr* ARPHeaderPtr () const
			{ return NULL; }
		
		virtual const u_char* AfterARPHeaderPtr () const
			{ return NULL; }
	
	protected:
		
		const TCapturedPacket*							fRawPacketPtr;
};

//---------------------------------------------------------------------
// Class TPacketEthernet
//---------------------------------------------------------------------
class TPacketEthernet : public TPacket
{
	private:
		
		typedef	TPacket									Inherited;
	
	public:
		
		TPacketEthernet (const TCapturedPacket* packetPtr = NULL);
			// Constructor
		
		TPacketEthernet (const TPacketEthernet& obj);
			// Copy constructor
		
		virtual ~TPacketEthernet ();
			// Destructor
		
		virtual PacketTypeCode PacketType () const
			{ return kPacketTypeEthernet; }
		
		virtual string ProtocolFamilyDescription () const
			{ return string(""); }
		
		virtual string PacketTypeDescription () const
			{ return string("enet"); }
		
		virtual bool IsPacketType (PacketTypeCode code) const
			{ return ((code == TPacketEthernet::PacketType()) || Inherited::IsPacketType(code)); }
		
		inline unsigned long EthernetHeaderSize () const
			{ return ETHER_HDR_LEN; }
		
		inline const struct ether_header* EthernetHeaderPtr () const
			{ return fHeaderPtr; }
		
		inline const u_char* AfterEthernetHeaderPtr () const
			{ return fPayloadPtr; }
		
		virtual const u_char* PayloadPtr () const
			{ return fPayloadPtr; }
		
		virtual string SourceMACAddressAsString () const;
			// Override
		
		virtual string DestinationMACAddressAsString () const;
			// Override
	
	protected:
		
		static string _DecodeMACAddress (const u_char* encodedMACAddress);
	
	private:
		
		const struct ether_header*						fHeaderPtr;
		const u_char*									fPayloadPtr;
};

//---------------------------------------------------------------------
// Class TPacketIPv4
//---------------------------------------------------------------------
class TPacketIPv4 : public TPacketEthernet
{
	private:
		
		typedef	TPacketEthernet							Inherited;
	
	public:
		
		TPacketIPv4 (const TCapturedPacket* packetPtr = NULL);
			// Constructor
		
		TPacketIPv4 (const TPacketIPv4& obj);
			// Copy constructor
		
		virtual ~TPacketIPv4 ();
			// Destructor
		
		virtual PacketTypeCode PacketType () const
			{ return kPacketTypeIPv4; }
		
		virtual string ProtocolFamilyDescription () const
			{ return string("IPv4"); }
		
		virtual string PacketTypeDescription () const
			{ return string("ip"); }
		
		virtual bool IsPacketType (PacketTypeCode code) const
			{ return ((code == TPacketIPv4::PacketType()) || Inherited::IsPacketType(code)); }
		
		inline unsigned long IPHeaderSize () const
			{ return (IPHeaderPtr()->ip_hl * 4); }
		
		inline const struct ip* IPHeaderPtr () const
			{ return fHeaderPtr; }
		
		inline const u_char* AfterIPHeaderPtr () const
			{ return fPayloadPtr; }
		
		virtual const u_char* PayloadPtr () const
			{ return fPayloadPtr; }
		
		virtual string SourceIPAddressAsString () const;
			// Override
		
		virtual string DestinationIPAddressAsString () const;
			// Override
	
	private:
		
		const struct ip*								fHeaderPtr;
		const u_char*									fPayloadPtr;
};

//---------------------------------------------------------------------
// Class TPacketTCPv4
//---------------------------------------------------------------------
class TPacketTCPv4 : public TPacketIPv4
{
	private:
		
		typedef	TPacketIPv4								Inherited;
	
	public:
		
		TPacketTCPv4 (const TCapturedPacket* packetPtr = NULL);
			// Constructor
		
		TPacketTCPv4 (const TPacketTCPv4& obj);
			// Copy constructor
		
		virtual ~TPacketTCPv4 ();
			// Destructor
		
		virtual PacketTypeCode PacketType () const
			{ return kPacketTypeTCPv4; }
		
		virtual string PacketTypeDescription () const
			{ return string("tcp"); }
		
		virtual bool IsPacketType (PacketTypeCode code) const
			{ return ((code == TPacketTCPv4::PacketType()) || Inherited::IsPacketType(code)); }
		
		inline unsigned long TCPHeaderSize () const
			{ return (TCPHeaderPtr()->TCPHDR_DATA_OFFSET_NAME * 4); }
		
		inline const struct tcphdr* TCPHeaderPtr () const
			{ return fHeaderPtr; }
		
		inline const u_char* AfterTCPHeaderPtr () const
			{ return fPayloadPtr; }
		
		virtual const u_char* PayloadPtr () const
			{ return fPayloadPtr; }
		
		virtual unsigned int SourcePort () const
			{ return ntohs(TCPHeaderPtr()->TCPHDR_SOURCE_PORT_NAME); }
		
		virtual unsigned int DestinationPort () const
			{ return ntohs(TCPHeaderPtr()->TCPHDR_DEST_PORT_NAME); }
		
		virtual unsigned int SequenceNumber() const
			{ return ntohs(TCPHeaderPtr()->seq); }
	
	private:
		
		const struct tcphdr*							fHeaderPtr;
		const u_char*									fPayloadPtr;
};

//---------------------------------------------------------------------
// Class TPacketUDPv4
//---------------------------------------------------------------------
class TPacketUDPv4 : public TPacketIPv4
{
	private:
		
		typedef	TPacketIPv4								Inherited;
	
	public:
		
		TPacketUDPv4 (const TCapturedPacket* packetPtr = NULL);
			// Constructor
		
		TPacketUDPv4 (const TPacketUDPv4& obj);
			// Copy constructor
		
		virtual ~TPacketUDPv4 ();
			// Destructor
		
		virtual PacketTypeCode PacketType () const
			{ return kPacketTypeUDPv4; }
		
		virtual string PacketTypeDescription () const
			{ return string("udp"); }
		
		virtual bool IsPacketType (PacketTypeCode code) const
			{ return ((code == TPacketUDPv4::PacketType()) || Inherited::IsPacketType(code)); }
		
		inline unsigned long UDPHeaderSize () const
			{ return sizeof(struct udphdr); }
		
		inline const struct udphdr* UDPHeaderPtr () const
			{ return fHeaderPtr; }
		
		inline const u_char* AfterUDPHeaderPtr () const
			{ return fPayloadPtr; }
		
		virtual const u_char* PayloadPtr () const
			{ return fPayloadPtr; }
		
		virtual unsigned int SourcePort () const
			{ return ntohs(UDPHeaderPtr()->UDPHDR_SOURCE_PORT_NAME); }
		
		virtual unsigned int DestinationPort () const
			{ return ntohs(UDPHeaderPtr()->UDPHDR_DEST_PORT_NAME); }
	
	private:
		
		const struct udphdr*							fHeaderPtr;
		const u_char*									fPayloadPtr;
};

//---------------------------------------------------------------------
// Class TPacketICMPv4
//---------------------------------------------------------------------
class TPacketICMPv4 : public TPacketIPv4
{
	private:
		
		typedef	TPacketIPv4								Inherited;
	
	public:
		
		TPacketICMPv4 (const TCapturedPacket* packetPtr = NULL);
			// Constructor
		
		TPacketICMPv4 (const TPacketICMPv4& obj);
			// Copy constructor
		
		virtual ~TPacketICMPv4 ();
			// Destructor
		
		virtual PacketTypeCode PacketType () const
			{ return kPacketTypeICMPv4; }
		
		virtual string PacketTypeDescription () const
			{ return string("icmp"); }
		
		virtual bool IsPacketType (PacketTypeCode code) const
			{ return ((code == TPacketICMPv4::PacketType()) || Inherited::IsPacketType(code)); }
		
		inline unsigned long ICMPHeaderSize () const
			{ return sizeof(struct icmp); }
		
		inline const struct icmp* ICMPHeaderPtr () const
			{ return fHeaderPtr; }
		
		inline const u_char* AfterICMPHeaderPtr () const
			{ return fPayloadPtr; }
		
		virtual const u_char* PayloadPtr () const
			{ return fPayloadPtr; }
	
	private:
		
		const struct icmp*								fHeaderPtr;
		const u_char*									fPayloadPtr;
};

//---------------------------------------------------------------------
// Class TPacketARP
//---------------------------------------------------------------------
class TPacketARP : public TPacketEthernet
{
	private:
		
		typedef	TPacketEthernet							Inherited;
	
	public:
		
		TPacketARP (const TCapturedPacket* packetPtr = NULL);
			// Constructor
		
		TPacketARP (const TPacketARP& obj);
			// Copy constructor
		
		virtual ~TPacketARP ();
			// Destructor
		
		virtual PacketTypeCode PacketType () const
			{ return kPacketTypeARP; }
		
		virtual string PacketTypeDescription () const
			{ return string("arp"); }
		
		virtual bool IsPacketType (PacketTypeCode code) const
			{ return ((code == TPacketARP::PacketType()) || Inherited::IsPacketType(code)); }
		
		inline unsigned long ARPHeaderSize () const
			{ return (8 + (2 * ARPHeaderPtr()->ar_hln) + (2 * ARPHeaderPtr()->ar_pln)); }
		
		inline const struct arphdr* ARPHeaderPtr () const
			{ return fHeaderPtr; }
		
		inline const u_char* AfterARPHeaderPtr () const
			{ return fPayloadPtr; }
		
		virtual const u_char* PayloadPtr () const
			{ return fPayloadPtr; }
	
	private:
		
		const struct arphdr*							fHeaderPtr;
		const u_char*									fPayloadPtr;
};

#if HAVE_DECL_AF_INET6
	//---------------------------------------------------------------------
	// Class TPacketIPv6
	//---------------------------------------------------------------------
	class TPacketIPv6 : public TPacketEthernet
	{
		private:
			
			typedef	TPacketEthernet							Inherited;
		
		public:
			
			TPacketIPv6 (const TCapturedPacket* packetPtr = NULL);
				// Constructor
			
			TPacketIPv6 (const TPacketIPv6& obj);
				// Copy constructor
			
			virtual ~TPacketIPv6 ();
				// Destructor
			
			virtual PacketTypeCode PacketType () const
				{ return kPacketTypeIPv6; }
			
			virtual string ProtocolFamilyDescription () const
				{ return string("IPv6"); }
			
			virtual string PacketTypeDescription () const
				{ return string("ip"); }
			
			virtual bool IsPacketType (PacketTypeCode code) const
				{ return ((code == TPacketIPv6::PacketType()) || Inherited::IsPacketType(code)); }
			
			inline unsigned long IPv6HeaderSize () const
				{ return sizeof(struct ip6_hdr); }
			
			inline const struct ip6_hdr* IPv6HeaderPtr () const
				{ return fHeaderPtr; }
			
			inline const u_char* AfterIPv6HeaderPtr () const
				{ return fPayloadPtr; }
			
			virtual const u_char* PayloadPtr () const
				{ return fPayloadPtr; }
			
			virtual string SourceIPAddressAsString () const;
				// Override
			
			virtual string DestinationIPAddressAsString () const;
				// Override
		
		private:
			
			static string _IPAddressAsString (const struct in6_addr& addr);
				// Converts the given address to a printable string and
				// returns it.
		
		private:
			
			const struct ip6_hdr*							fHeaderPtr;
			const u_char*									fPayloadPtr;
	};
	
	//---------------------------------------------------------------------
	// Class TPacketTCPv6
	//---------------------------------------------------------------------
	class TPacketTCPv6 : public TPacketIPv6
	{
		private:
			
			typedef	TPacketIPv6								Inherited;
		
		public:
			
			TPacketTCPv6 (const TCapturedPacket* packetPtr = NULL);
				// Constructor
			
			TPacketTCPv6 (const TPacketTCPv6& obj);
				// Copy constructor
			
			virtual ~TPacketTCPv6 ();
				// Destructor
			
			virtual PacketTypeCode PacketType () const
				{ return kPacketTypeTCPv6; }
			
			virtual string PacketTypeDescription () const
				{ return string("tcp"); }
			
			virtual bool IsPacketType (PacketTypeCode code) const
				{ return ((code == TPacketTCPv6::PacketType()) || Inherited::IsPacketType(code)); }
			
			inline unsigned long TCPHeaderSize () const
				{ return (TCPHeaderPtr()->TCPHDR_DATA_OFFSET_NAME * 4); }
			
			inline const struct tcphdr* TCPHeaderPtr () const
				{ return fHeaderPtr; }
			
			inline const u_char* AfterTCPHeaderPtr () const
				{ return fPayloadPtr; }
			
			virtual const u_char* PayloadPtr () const
				{ return fPayloadPtr; }
			
			virtual unsigned int SourcePort () const
				{ return ntohs(TCPHeaderPtr()->TCPHDR_SOURCE_PORT_NAME); }
			
			virtual unsigned int DestinationPort () const
				{ return ntohs(TCPHeaderPtr()->TCPHDR_DEST_PORT_NAME); }
		
		private:
			
			const struct tcphdr*							fHeaderPtr;
			const u_char*									fPayloadPtr;
	};
	
	//---------------------------------------------------------------------
	// Class TPacketUDPv6
	//---------------------------------------------------------------------
	class TPacketUDPv6 : public TPacketIPv6
	{
		private:
			
			typedef	TPacketIPv6								Inherited;
		
		public:
			
			TPacketUDPv6 (const TCapturedPacket* packetPtr = NULL);
				// Constructor
			
			TPacketUDPv6 (const TPacketUDPv6& obj);
				// Copy constructor
			
			virtual ~TPacketUDPv6 ();
				// Destructor
			
			virtual PacketTypeCode PacketType () const
				{ return kPacketTypeUDPv6; }
			
			virtual string PacketTypeDescription () const
				{ return string("udp"); }
			
			virtual bool IsPacketType (PacketTypeCode code) const
				{ return ((code == TPacketUDPv6::PacketType()) || Inherited::IsPacketType(code)); }
			
			inline unsigned long UDPHeaderSize () const
				{ return sizeof(struct udphdr); }
			
			inline const struct udphdr* UDPHeaderPtr () const
				{ return fHeaderPtr; }
			
			inline const u_char* AfterUDPHeaderPtr () const
				{ return fPayloadPtr; }
			
			virtual const u_char* PayloadPtr () const
				{ return fPayloadPtr; }
			
			virtual unsigned int SourcePort () const
				{ return ntohs(UDPHeaderPtr()->UDPHDR_SOURCE_PORT_NAME); }
			
			virtual unsigned int DestinationPort () const
				{ return ntohs(UDPHeaderPtr()->UDPHDR_DEST_PORT_NAME); }
		
		private:
			
			const struct udphdr*							fHeaderPtr;
			const u_char*									fPayloadPtr;
	};
	
	//---------------------------------------------------------------------
	// Class TPacketICMPv6
	//---------------------------------------------------------------------
	class TPacketICMPv6 : public TPacketIPv6
	{
		private:
			
			typedef	TPacketIPv6								Inherited;
		
		public:
			
			TPacketICMPv6 (const TCapturedPacket* packetPtr = NULL);
				// Constructor
			
			TPacketICMPv6 (const TPacketICMPv6& obj);
				// Copy constructor
			
			virtual ~TPacketICMPv6 ();
				// Destructor
			
			virtual PacketTypeCode PacketType () const
				{ return kPacketTypeICMPv6; }
			
			virtual string PacketTypeDescription () const
				{ return string("icmp"); }
			
			virtual bool IsPacketType (PacketTypeCode code) const
				{ return ((code == TPacketICMPv6::PacketType()) || Inherited::IsPacketType(code)); }
			
			inline unsigned long ICMPv6HeaderSize () const
				{ return sizeof(struct icmp6_hdr); }
			
			inline const struct icmp6_hdr* ICMPv6HeaderPtr () const
				{ return fHeaderPtr; }
			
			inline const u_char* AfterICMPv6HeaderPtr () const
				{ return fPayloadPtr; }
			
			virtual const u_char* PayloadPtr () const
				{ return fPayloadPtr; }
		
		private:
			
			const struct icmp6_hdr*							fHeaderPtr;
			const u_char*									fPayloadPtr;
	};
#endif

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

TPacket* CreatePacketObj (const TCapturedPacket& rawPacket);
	// Analyzes the argument to determine what kind of packet it is and
	// returns a dynamically-created object to wrap the packet.  The
	// caller is responsible for calling delete() on the returned object
	// pointer.  May return NULL if the packet type cannot be determined.

//---------------------------------------------------------------------
#endif // PACKET_OBJS

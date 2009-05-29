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

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "packet-objs.h"

#include "plugin-utils.h"

#include <arpa/inet.h>

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

#if !defined(ETHERTYPE_IP)
	#define	ETHERTYPE_IP	0x0800
#endif

#if !defined(ETHERTYPE_ARP)
	#define	ETHERTYPE_ARP	0x0806
#endif

#if HAVE_DECL_AF_INET6
	#if !defined(ETHERTYPE_IPV6)
		#define	ETHERTYPE_IPV6	0x86dd
	#endif
#endif

//*********************************************************************
// Class TPacketEthernet
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketEthernet::TPacketEthernet (const TCapturedPacket* packetPtr)
	:	Inherited(packetPtr)
{
	fHeaderPtr = reinterpret_cast<const struct ether_header*>(fRawPacketPtr->Data());
	fPayloadPtr = reinterpret_cast<const u_char*>(fHeaderPtr) + EthernetHeaderSize();
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketEthernet::TPacketEthernet (const TPacketEthernet& obj)
	:	Inherited(obj),
		fHeaderPtr(obj.fHeaderPtr),
		fPayloadPtr(obj.fPayloadPtr)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPacketEthernet::~TPacketEthernet ()
{
}

//---------------------------------------------------------------------
// TPacketEthernet::SourceMACAddressAsString
//---------------------------------------------------------------------
string TPacketEthernet::SourceMACAddressAsString () const
{
	return _DecodeMACAddress(EthernetHeaderPtr()->ether_shost);
}

//---------------------------------------------------------------------
// TPacketEthernet::DestinationMACAddressAsString
//---------------------------------------------------------------------
string TPacketEthernet::DestinationMACAddressAsString () const
{
	return _DecodeMACAddress(EthernetHeaderPtr()->ether_dhost);
}

//---------------------------------------------------------------------
// TPacketEthernet::_DecodeMACAddress (static protected)
//---------------------------------------------------------------------
string TPacketEthernet::_DecodeMACAddress (const u_char* encodedMACAddress)
{
	string			macAddress;
	const char		kEncodingTable[] = {'0','1','2','3','4','5',
										'6','7','8','9','A','B',
										'C','D','E','F'
									   };
	
	for (unsigned long x = 0; x < ETHER_ADDR_LEN; x++)
	{
		unsigned char		charValue = encodedMACAddress[x];
		unsigned char		msb = charValue / 16;
		unsigned char		lsb = charValue % 16;
		
		macAddress += kEncodingTable[msb];
		macAddress += kEncodingTable[lsb];
		if (x + 1 < ETHER_ADDR_LEN)
			macAddress += ':';
	}
	
	return macAddress;
}

//*********************************************************************
// Class TPacketIPv4
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketIPv4::TPacketIPv4 (const TCapturedPacket* packetPtr)
	:	Inherited(packetPtr)
{
	fHeaderPtr = reinterpret_cast<const struct ip*>(Inherited::PayloadPtr());
	fPayloadPtr = reinterpret_cast<const u_char*>(fHeaderPtr) + IPHeaderSize();
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketIPv4::TPacketIPv4 (const TPacketIPv4& obj)
	:	Inherited(obj),
		fHeaderPtr(obj.fHeaderPtr),
		fPayloadPtr(obj.fPayloadPtr)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPacketIPv4::~TPacketIPv4 ()
{
}

//---------------------------------------------------------------------
// TPacketIPv4::SourceIPAddressAsString
//---------------------------------------------------------------------
string TPacketIPv4::SourceIPAddressAsString () const
{
	return string(inet_ntoa(IPHeaderPtr()->ip_src));
}

//---------------------------------------------------------------------
// TPacketIPv4::DestinationIPAddressAsString
//---------------------------------------------------------------------
string TPacketIPv4::DestinationIPAddressAsString () const
{
	return string(inet_ntoa(IPHeaderPtr()->ip_dst));
}

//*********************************************************************
// Class TPacketTCPv4
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketTCPv4::TPacketTCPv4 (const TCapturedPacket* packetPtr)
	:	Inherited(packetPtr)
{
	fHeaderPtr = reinterpret_cast<const struct tcphdr*>(Inherited::PayloadPtr());
	fPayloadPtr = reinterpret_cast<const u_char*>(fHeaderPtr) + TCPHeaderSize();
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketTCPv4::TPacketTCPv4 (const TPacketTCPv4& obj)
	:	Inherited(obj),
		fHeaderPtr(obj.fHeaderPtr),
		fPayloadPtr(obj.fPayloadPtr)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPacketTCPv4::~TPacketTCPv4 ()
{
}

//*********************************************************************
// Class TPacketUDPv4
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketUDPv4::TPacketUDPv4 (const TCapturedPacket* packetPtr)
	:	Inherited(packetPtr)
{
	fHeaderPtr = reinterpret_cast<const struct udphdr*>(Inherited::PayloadPtr());
	fPayloadPtr = reinterpret_cast<const u_char*>(fPayloadPtr) + UDPHeaderSize();
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketUDPv4::TPacketUDPv4 (const TPacketUDPv4& obj)
	:	Inherited(obj),
		fHeaderPtr(obj.fHeaderPtr),
		fPayloadPtr(obj.fPayloadPtr)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPacketUDPv4::~TPacketUDPv4 ()
{
}

//*********************************************************************
// Class TPacketICMPv4
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketICMPv4::TPacketICMPv4 (const TCapturedPacket* packetPtr)
	:	Inherited(packetPtr)
{
	fHeaderPtr = reinterpret_cast<const struct icmp*>(Inherited::PayloadPtr());
	fPayloadPtr = reinterpret_cast<const u_char*>(fHeaderPtr) + ICMPHeaderSize();
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketICMPv4::TPacketICMPv4 (const TPacketICMPv4& obj)
	:	Inherited(obj),
		fHeaderPtr(obj.fHeaderPtr),
		fPayloadPtr(obj.fPayloadPtr)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPacketICMPv4::~TPacketICMPv4 ()
{
}

//*********************************************************************
// Class TPacketARP
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketARP::TPacketARP (const TCapturedPacket* packetPtr)
	:	Inherited(packetPtr)
{
	fHeaderPtr = reinterpret_cast<const struct arphdr*>(Inherited::PayloadPtr());
	fPayloadPtr = reinterpret_cast<const u_char*>(fHeaderPtr) + ARPHeaderSize();
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPacketARP::TPacketARP (const TPacketARP& obj)
	:	Inherited(obj),
		fHeaderPtr(obj.fHeaderPtr),
		fPayloadPtr(obj.fPayloadPtr)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPacketARP::~TPacketARP ()
{
}

#if HAVE_DECL_AF_INET6
	//*********************************************************************
	// Class TPacketIPv6
	//*********************************************************************
	
	//---------------------------------------------------------------------
	// Constructor
	//---------------------------------------------------------------------
	TPacketIPv6::TPacketIPv6 (const TCapturedPacket* packetPtr)
		:	Inherited(packetPtr)
	{
		fHeaderPtr = reinterpret_cast<const struct ip6_hdr*>(Inherited::PayloadPtr());
		fPayloadPtr = reinterpret_cast<const u_char*>(fHeaderPtr) + IPv6HeaderSize();
	}
	
	//---------------------------------------------------------------------
	// Constructor
	//---------------------------------------------------------------------
	TPacketIPv6::TPacketIPv6 (const TPacketIPv6& obj)
		:	Inherited(obj),
			fHeaderPtr(obj.fHeaderPtr),
			fPayloadPtr(obj.fPayloadPtr)
	{
	}
	
	//---------------------------------------------------------------------
	// Destructor
	//---------------------------------------------------------------------
	TPacketIPv6::~TPacketIPv6 ()
	{
	}
	
	//---------------------------------------------------------------------
	// TPacketIPv6::SourceIPAddressAsString
	//---------------------------------------------------------------------
	string TPacketIPv6::SourceIPAddressAsString () const
	{
		return _IPAddressAsString(IPv6HeaderPtr()->ip6_src);
	}
	
	//---------------------------------------------------------------------
	// TPacketIPv6::DestinationIPAddressAsString
	//---------------------------------------------------------------------
	string TPacketIPv6::DestinationIPAddressAsString () const
	{
		return _IPAddressAsString(IPv6HeaderPtr()->ip6_dst);
	}
	
	//---------------------------------------------------------------------
	// TPacketIPv6::_IPAddressAsString (static private)
	//---------------------------------------------------------------------
	string TPacketIPv6::_IPAddressAsString (const struct in6_addr& addr)
	{
		string					addrStr;
		struct sockaddr_in6		socketInfo;
		int						niFlags = NI_NUMERICHOST;
		
		#ifdef NI_WITHSCOPEID
			niFlags |= NI_WITHSCOPEID;
		#endif
		
		addrStr.resize(NI_MAXHOST);
		memset(&socketInfo,0,sizeof(socketInfo));
		socketInfo.sin6_family = AF_INET6;
		#if defined(HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN)
			socketInfo.sin6_len = sizeof(socketInfo);
		#endif
		socketInfo.sin6_addr = addr;
		
		if (IN6_IS_ADDR_LINKLOCAL(&addr) && *(reinterpret_cast<u_int16_t*>(&socketInfo.sin6_addr.s6_addr[2])) != 0)
		{
			socketInfo.sin6_scope_id = ntohs(*(reinterpret_cast<u_int16_t*>(&socketInfo.sin6_addr.s6_addr[2])));
			socketInfo.sin6_addr.s6_addr[2] = socketInfo.sin6_addr.s6_addr[3] = 0;
		}
		
		if (getnameinfo(reinterpret_cast<struct sockaddr*>(&socketInfo),sizeof(socketInfo),const_cast<char*>(addrStr.data()),addrStr.capacity()-1,NULL,0,niFlags) == 0)
			addrStr.resize(strlen(addrStr.c_str()));
		else
			addrStr = "";
		
		return addrStr;
	}

	//*********************************************************************
	// Class TPacketTCPv6
	//*********************************************************************
	
	//---------------------------------------------------------------------
	// Constructor
	//---------------------------------------------------------------------
	TPacketTCPv6::TPacketTCPv6 (const TCapturedPacket* packetPtr)
		:	Inherited(packetPtr)
	{
		fHeaderPtr = reinterpret_cast<const struct tcphdr*>(Inherited::PayloadPtr());
		fPayloadPtr = reinterpret_cast<const u_char*>(fHeaderPtr) + TCPHeaderSize();
	}
	
	//---------------------------------------------------------------------
	// Constructor
	//---------------------------------------------------------------------
	TPacketTCPv6::TPacketTCPv6 (const TPacketTCPv6& obj)
		:	Inherited(obj),
			fHeaderPtr(obj.fHeaderPtr),
			fPayloadPtr(obj.fPayloadPtr)
	{
	}
	
	//---------------------------------------------------------------------
	// Destructor
	//---------------------------------------------------------------------
	TPacketTCPv6::~TPacketTCPv6 ()
	{
	}
	
	//*********************************************************************
	// Class TPacketUDPv6
	//*********************************************************************
	
	//---------------------------------------------------------------------
	// Constructor
	//---------------------------------------------------------------------
	TPacketUDPv6::TPacketUDPv6 (const TCapturedPacket* packetPtr)
		:	Inherited(packetPtr)
	{
		fHeaderPtr = reinterpret_cast<const struct udphdr*>(Inherited::PayloadPtr());
		fPayloadPtr = reinterpret_cast<const u_char*>(fPayloadPtr) + UDPHeaderSize();
	}
	
	//---------------------------------------------------------------------
	// Constructor
	//---------------------------------------------------------------------
	TPacketUDPv6::TPacketUDPv6 (const TPacketUDPv6& obj)
		:	Inherited(obj),
			fHeaderPtr(obj.fHeaderPtr),
			fPayloadPtr(obj.fPayloadPtr)
	{
	}
	
	//---------------------------------------------------------------------
	// Destructor
	//---------------------------------------------------------------------
	TPacketUDPv6::~TPacketUDPv6 ()
	{
	}
	
	//*********************************************************************
	// Class TPacketICMPv6
	//*********************************************************************
	
	//---------------------------------------------------------------------
	// Constructor
	//---------------------------------------------------------------------
	TPacketICMPv6::TPacketICMPv6 (const TCapturedPacket* packetPtr)
		:	Inherited(packetPtr)
	{
		fHeaderPtr = reinterpret_cast<const struct icmp6_hdr*>(Inherited::PayloadPtr());
		fPayloadPtr = reinterpret_cast<const u_char*>(fHeaderPtr) + ICMPv6HeaderSize();
	}
	
	//---------------------------------------------------------------------
	// Constructor
	//---------------------------------------------------------------------
	TPacketICMPv6::TPacketICMPv6 (const TPacketICMPv6& obj)
		:	Inherited(obj),
			fHeaderPtr(obj.fHeaderPtr),
			fPayloadPtr(obj.fPayloadPtr)
	{
	}
	
	//---------------------------------------------------------------------
	// Destructor
	//---------------------------------------------------------------------
	TPacketICMPv6::~TPacketICMPv6 ()
	{
	}
#endif

//*********************************************************************
// Global Functions
//*********************************************************************

//---------------------------------------------------------------------
// CreatePacketObj
//---------------------------------------------------------------------
TPacket* CreatePacketObj (const TCapturedPacket& rawPacket)
{
	TPacket*					packetObjPtr = NULL;
	const struct ether_header*	headerPtr = reinterpret_cast<const struct ether_header*>(rawPacket.Data());
	
	switch (ntohs(headerPtr->ether_type))
	{
		case ETHERTYPE_IP:
			{
				const struct ip*	ipPtr = reinterpret_cast<const struct ip*>(rawPacket.Data() + ETHER_HDR_LEN);
				
				if ((ntohs(ipPtr->ip_off) & 0x1fff) == 0)
				{
					switch (ipPtr->ip_p)
					{
						case IPPROTO_TCP:
							packetObjPtr = new TPacketTCPv4(&rawPacket);
							break;
						
						case IPPROTO_UDP:
							packetObjPtr = new TPacketUDPv4(&rawPacket);
							break;
						
						case IPPROTO_ICMP:
							packetObjPtr = new TPacketICMPv4(&rawPacket);
							break;
					}
				}
				else
				{
					// It's a fragment, and not the first one
					packetObjPtr = new TPacketIPv4(&rawPacket);
				}
				
				// When all else fails...
				if (!packetObjPtr)
					packetObjPtr = new TPacketEthernet(&rawPacket);
			}
			break;
		
	#if HAVE_DECL_AF_INET6
		case ETHERTYPE_IPV6:
			{
				const struct ip6_hdr*	ipPtr = reinterpret_cast<const struct ip6_hdr*>(rawPacket.Data() + ETHER_HDR_LEN);
				
				switch (ipPtr->ip6_nxt)
				{
					case IPPROTO_TCP:
						packetObjPtr = new TPacketTCPv6(&rawPacket);
						break;
					
					case IPPROTO_UDP:
						packetObjPtr = new TPacketUDPv6(&rawPacket);
						break;
					
					case IPPROTO_ICMPV6:
						packetObjPtr = new TPacketICMPv6(&rawPacket);
						break;
					
					default:
						packetObjPtr = new TPacketIPv6(&rawPacket);
						break;
				}
			}
			break;
	#endif
		
		case ETHERTYPE_ARP:
			packetObjPtr = new TPacketARP(&rawPacket);
			break;
		
		default:
			break;
	}
	
	
	return packetObjPtr;
}

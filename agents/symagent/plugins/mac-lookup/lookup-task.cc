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
#		Last Modified:				11 Feb 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "lookup-task.h"

#include <sys/types.h>
#include <sys/socket.h>

#if HAVE_NET_ETHERNET_H
	#include <net/ethernet.h>
#else
	#define	ETHER_ADDR_LEN		6
#endif

#include <net/if.h>
#include <netinet/in.h>

#if HAVE_NETINET_IF_ETHER_H
	#include <netinet/if_ether.h>
#else
	#define	ARPHRD_ETHER		1
	#define	ARPOP_REQUEST		1
	#define	ARPOP_REPLY			2
#endif

#if USE_NETPACKET
	#include <netpacket/packet.h>
#endif
#if USE_BPF
	#include <net/bpf.h>
#endif
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>

#if HAVE_SYS_FCNTL_H
	#include <sys/fcntl.h>
#endif

#if HAVE_SYS_SYSCTL_H
	#include <sys/sysctl.h>
#endif

#if HAVE_NET_ROUTE_H
	#include <net/route.h>
#endif

#if HAVE_NET_IF_DL_H
	#include <net/if_dl.h>
#endif

#if !defined(PTHREAD_THREADS_MAX)
	#define PTHREAD_THREADS_MAX 1024
#endif

#if !defined(ETH_P_IP)
	#define ETH_P_IP 0x0800
#endif

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

#if USE_NETPACKET
	struct ARPNetPacketReq
	{
		u_short		ar_hrd;							// Format of hardware address	-- ARPHRD_ETHER
		u_short		ar_pro;							// Format of protocol address	-- ETH_P_IP
		u_char		ar_hln;							// Length of hardware address	-- ETHER_ADDR_LEN
		u_char		ar_pln;							// Length of protocol address	-- 4 bytes (IPv4)
		u_short		ar_op;							// ARP opcode (command)			-- ARPOP_REQUEST on send ARPOP_REPLY on reply
		u_char		ar_sha[ETHER_ADDR_LEN];			// Sender MAC address			-- Mine on send, dest on reply
		u_char		ar_sip[4];						// Sender IP address			-- Mine on send, dest on reply
		u_char		ar_tha[ETHER_ADDR_LEN];			// Target MAC address			-- Broadcast on send, mine on reply
		u_char		ar_tip[4];						// Target IP address			-- Dest on send, mine on reply
	};
#endif

#if USE_BPF
	struct ARPBPFReq
	{
		u_char		ether_dhost[ETHER_ADDR_LEN];	// Target MAC address			-- Broadcast on send, mine on reply
		u_char		ether_shost[ETHER_ADDR_LEN];	// Sender MAC address			-- Mine on send, dest on reply
		u_short		ether_type;						// ARP Data						-- ETHERTYPE_ARP
		u_short		ar_hrd;							// Format of hardware address	-- ARPHRD_ETHER
		u_short		ar_pro;							// Format of protocol address	-- ETH_P_IP
		u_char		ar_hln;							// Length of hardware address	-- ETHER_ADDR_LEN
		u_char		ar_pln;							// Length of protocol address	-- 4 bytes (IPv4)
		u_short		ar_op;							// ARP opcode (command)			-- ARPOP_REQUEST on send ARPOP_REPLY on reply
		u_char		ar_sha[ETHER_ADDR_LEN];			// Sender MAC address			-- Mine on send, dest on reply
		u_char		ar_sip[4];						// Sender IP address			-- Mine on send, dest on reply
		u_char		ar_tha[ETHER_ADDR_LEN];			// Target MAC address			-- Broadcast on send, mine on reply
		u_char		ar_tip[4];						// Target IP address			-- Dest on send, mine on reply
	};
	
	struct ARPBPFReply
	{
		struct bpf_hdr			bpfHeader;
		struct ARPBPFReq		data;
	};
#endif

#define	kARPReplyTimeout				1	// seconds

//*********************************************************************
// Class TLookupMACAddrTask
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TLookupMACAddrTask::TLookupMACAddrTask ()
	:	Inherited(PROJECT_SHORT_NAME,0,false),
		fParentEnvironPtr(GetModEnviron())
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TLookupMACAddrTask::~TLookupMACAddrTask ()
{
}

//---------------------------------------------------------------------
// TLookupMACAddrTask::SetupTask
//---------------------------------------------------------------------
void TLookupMACAddrTask::SetupTask (const string& deviceName,
									const string& scanTarget,
									time_t scanInterval)
{
	if (!deviceName.empty())
		fMyDeviceName = deviceName;
	else
		throw TSymLibErrorObj(kErrorNetworkDeviceNotSpecified,"Network interface not defined");
	
	if (!scanTarget.empty())
		fScanTarget = scanTarget;
	else
		throw TSymLibErrorObj(kErrorScanTargetNotSpecified,"Scan target not defined");
	
	if (_ParseScanTarget() < 1)
	{
		string		errString;
		
		errString = "Scan target '" + fScanTarget + "' invalid";
		throw TSymLibErrorObj(kErrorInvalidScanTarget,errString);
	}
	
	if (scanInterval >= 0)
	{
		SetExecutionInterval(scanInterval);
		SetRerun(scanInterval > 0);
	}
}

//---------------------------------------------------------------------
// TLookupMACAddrTask::RunTask
//---------------------------------------------------------------------
void TLookupMACAddrTask::RunTask ()
{
	TServerMessage		messageObj;
	TServerReply		replyObj;
	
	// Create our thread environment
	CreateModEnviron(fParentEnvironPtr);
	
	if (DoPluginEventLoop())
	{
		Main(messageObj);
		
		// Send it to the server
		SendToServer(messageObj,replyObj);
	}
}

//---------------------------------------------------------------------
// TLookupMACAddrTask::Main
//---------------------------------------------------------------------
void TLookupMACAddrTask::Main (TServerMessage& messageObj)
{
	ModEnviron*		environPtr = GetModEnviron();
	
	if (environPtr)
	{
		TMessageNode	macListNode(messageObj.Append("MAC_LIST","",""));
		unsigned long	maxThreads = 0;
		unsigned long	addressesPerTask = 0;
		IPAddressList	ipAddressList;
		
		maxThreads = std::min(static_cast<unsigned long>(PTHREAD_THREADS_MAX),static_cast<unsigned long>(1024))/4;
		#if USE_BPF
			maxThreads = std::min(maxThreads,static_cast<unsigned long>(256));
		#else
			#if defined(SCAN_LIMIT_190) && SCAN_LIMIT_190
				maxThreads = 190;
				// PXN - debug
				//WriteToMessagesLog("configure for SCAN_LIMIT_190");
			#endif
		#endif
		addressesPerTask = (fIPAddressList.size() / maxThreads) + 1;
		
		macListNode.AddAttribute("device",fMyDeviceName);
		macListNode.AddAttribute("scan_target",fScanTarget);
		
		for (IPAddressList_const_iter oneIP = fIPAddressList.begin(); DoPluginEventLoop() && oneIP != fIPAddressList.end(); oneIP++)
		{
			ipAddressList.push_back(*oneIP);
			if (ipAddressList.size() >= addressesPerTask)
			{
				AddTaskToQueue(new TARPTask(fMyDeviceName,ipAddressList),true);
				ipAddressList.clear();
			}
		}
		
		if (!ipAddressList.empty())
		{
			AddTaskToQueue(new TARPTask(fMyDeviceName,ipAddressList),true);
			ipAddressList.clear();
		}
		
		while (DoPluginEventLoop() && environPtr->addressCount < fIPAddressList.size())
			PauseExecution(1);
		
		if (DoPluginEventLoop())
		{
			TLockedPthreadMutexObj	lock(environPtr->addressMapLock);
			
			for (AddressMap_const_iter x = environPtr->addressMap.begin(); x != environPtr->addressMap.end(); x++)
			{
				TMessageNode	macNode(macListNode.Append("ENTRY","",""));
				struct in_addr	addr;
				
				addr.s_addr = x->first;
				macNode.AddAttribute("ip",inet_ntoa(addr));
				macNode.AddAttribute("mac_id",x->second);
			}
		}
	}
}

//---------------------------------------------------------------------
// TLookupMACAddrTask::_ParseScanTarget (protected)
//---------------------------------------------------------------------
unsigned long TLookupMACAddrTask::_ParseScanTarget ()
{
	if (fScanTarget == "local_net")
	{
		unsigned long	ipAddress = _GetIPAddress(fMyDeviceName);
		unsigned long	netMask = _GetNetworkMask(fMyDeviceName);
		unsigned long	localMask = 0;
		unsigned long	baseAddress = 0;
		unsigned long	maxAddressMask = 0;
		
		if (ipAddress == 0)
		{
			string		errString;
			
			errString = "Unable to determine IP address used by device '" + fMyDeviceName + "'";
			throw TSymLibErrorObj(kErrorUnableToObtainLocalIPAddress,errString);
		}
		
		if (netMask == 0)
		{
			string		errString;
			
			errString = "Unable to determine network mask used by device '" + fMyDeviceName + "'";
			throw TSymLibErrorObj(kErrorUnableToObtainLocalNetMask,errString);
		}
		
		// Construct our various masks
		localMask = ~(netMask);
		baseAddress = (ipAddress & netMask);
		maxAddressMask = ntohl(localMask);
		
		// Construct a list of individual addresses, skipping
		// the very last (which is presumably a broadcast address)
		for (unsigned long x = 0; x < maxAddressMask; x++)
		{
			unsigned long	newIP = (baseAddress | htonl(x));
			
			fIPAddressList.push_back(newIP);
		}
		
		if (!fIPAddressList.empty())
		{
			// Rewrite the scan target into a CIDR
			struct in_addr	addr;
			unsigned long	bitCount = 0;
			
			++maxAddressMask;
			while (maxAddressMask > 0)
			{
				++bitCount;
				maxAddressMask /= 2;
			}
			
			addr.s_addr = baseAddress;
			fScanTarget = inet_ntoa(addr);
			fScanTarget += "/";
			fScanTarget += NumToString(32 - bitCount + 1);
		}
	}
	else
	{
		string				host;
		struct hostent*		hostEntryPtr = NULL;
		unsigned long		ipAddress = 0;
		unsigned long		subnetMask = 32;
		unsigned long		pos = fScanTarget.find("/");
		
		fIPAddressList.clear();
		
		if (pos != string::npos)
		{
			// We found a slash, which supposedly means that we have a subnet
			host = fScanTarget.substr(0,pos);
			subnetMask = static_cast<unsigned long>(StringToNum(fScanTarget.substr(pos+1)));
		}
		else
		{
			// We have a bare host (no subnet)
			host = fScanTarget;
		}
		
		// Attempt to convert the host to a network address
		hostEntryPtr = gethostbyname(host.c_str());
		if (hostEntryPtr)
			ipAddress = *(reinterpret_cast<unsigned long*>(hostEntryPtr->h_addr));
		
		if (ipAddress == 0 || subnetMask < 8 || subnetMask > 32)
		{
			string		errString;
			
			errString = "Scan target '" + fScanTarget + "' invalid";
			throw TSymLibErrorObj(kErrorInvalidScanTarget,errString);
		}
		
		if (subnetMask == 32)
		{
			// We have only a single host to put on the list
			fIPAddressList.push_back(ipAddress);
			
			WriteToMessagesLog(NumToString(ipAddress));
		}
		else
		{
			unsigned long	netMask = INADDR_BROADCAST;
			unsigned long	localMask = 0;
			unsigned long	baseAddress = 0;
			unsigned long	maxAddressMask = 0;
			
			// Construct our various masks
			netMask = htonl(netMask << (32 - subnetMask));
			localMask = ~(netMask);
			baseAddress = (ipAddress & netMask);
			maxAddressMask = ntohl(localMask);
			
			// Construct a list of individual addresses, skipping
			// the very last (which is presumably a broadcast address)
			for (unsigned long x = 0; x < maxAddressMask; x++)
			{
				unsigned long	newIP = (baseAddress | htonl(x));
				
				fIPAddressList.push_back(newIP);

				// PXN - debug
				//WriteToMessagesLog(NumToString(newIP));
			}
		}
	}
	
	return fIPAddressList.size();
}

//---------------------------------------------------------------------
// TLookupMACAddrTask::_GetIPAddress (protected)
//---------------------------------------------------------------------
unsigned long TLookupMACAddrTask::_GetIPAddress (const string& deviceName) const
{
	unsigned long		netMask = 0;
	int					sockNum = socket(AF_INET,SOCK_DGRAM,0);
	struct ifreq		ifr;
	struct sockaddr_in*	addressPtr = NULL;
	
	if (sockNum < 0)
		throw TSymLibErrorObj(errno,"During local IP address lookup: Failed to obtain a network socket");
	
	strcpy(ifr.ifr_name,deviceName.c_str());
	
	if (ioctl(sockNum,SIOCGIFADDR,&ifr) < 0)
	{
		close(sockNum);
		throw TSymLibErrorObj(errno,"During local IP address lookup: ioctl(SIOCGIFADDR) failed");
	}
	
	addressPtr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
	netMask = *(reinterpret_cast<unsigned long*>(&addressPtr->sin_addr));
	
	close(sockNum);
	
	return netMask;
}

//---------------------------------------------------------------------
// TLookupMACAddrTask::_GetNetworkMask (protected)
//---------------------------------------------------------------------
unsigned long TLookupMACAddrTask::_GetNetworkMask (const string& deviceName) const
{
	unsigned long		netMask = 0;
	int					sockNum = socket(AF_INET,SOCK_DGRAM,0);
	struct ifreq		ifr;
	struct sockaddr_in*	addressPtr = NULL;
	
	if (sockNum < 0)
		throw TSymLibErrorObj(errno,"During network mask lookup: Failed to obtain a network socket");
	
	strcpy(ifr.ifr_name,deviceName.c_str());
	
	if (ioctl(sockNum,SIOCGIFNETMASK,&ifr) < 0)
	{
		close(sockNum);
		throw TSymLibErrorObj(errno,"During network mask lookup: ioctl(SIOCGIFNETMASK) failed");
	}
	
	addressPtr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
	netMask = *(reinterpret_cast<unsigned long*>(&addressPtr->sin_addr));
	
	close(sockNum);
	
	return netMask;
}

#if USE_NETPACKET
	//*********************************************************************
	// Class TARPTaskNetpacket
	//*********************************************************************
	
	//---------------------------------------------------------------------
	// Constructor
	//---------------------------------------------------------------------
	TARPTaskNetpacket::TARPTaskNetpacket (const string& deviceName, const IPAddressList& ipAddressList)
		:	Inherited(PROJECT_SHORT_NAME,0,false),
			fParentEnvironPtr(GetModEnviron()),
			fIPAddressList(ipAddressList),
			fDeviceName(deviceName)
	{
	}
	
	//---------------------------------------------------------------------
	// Destructor
	//---------------------------------------------------------------------
	TARPTaskNetpacket::~TARPTaskNetpacket ()
	{
	}
	
	//---------------------------------------------------------------------
	// TARPTaskNetpacket::RunTask
	//---------------------------------------------------------------------
	void TARPTaskNetpacket::RunTask ()
	{
		// Create our thread environment
		CreateModEnviron(fParentEnvironPtr);
		
		if ((GetDynamicDebuggingFlags() & kDynDebugLogServerCommunication) == kDynDebugLogServerCommunication)
			WriteToMessagesLog("Starting ARP Lookup Task");
		
		for (IPAddressList_const_iter x = fIPAddressList.begin(); x != fIPAddressList.end() && DoPluginEventLoop(); x++)
			_GetRemoteMACAddress(*x);
		
		if ((GetDynamicDebuggingFlags() & kDynDebugLogServerCommunication) == kDynDebugLogServerCommunication)
			WriteToMessagesLog("Ending ARP Lookup Task");
	}
	
	//---------------------------------------------------------------------
	// TARPTaskNetpacket::_GetRemoteMACAddress (protected)
	//---------------------------------------------------------------------
	void TARPTaskNetpacket::_GetRemoteMACAddress (unsigned long remoteIPAddress) const
	{
		if (fParentEnvironPtr && remoteIPAddress != 0)
		{
			string					macAddress;
			int						sockNum = -1;
			struct ifreq			ifr;
			int						nicIndex;
			struct sockaddr_in		sockInfo;
			struct sockaddr_ll		bindInfo;
			struct sockaddr_ll		destInfo;
			struct sockaddr_ll		replyFrom;
			SOCKET_SIZE_TYPE		optVal;
			ARPNetPacketReq			arpPacket;
			ARPNetPacketReq			arpReply;
			string					errString;
			time_t					expireTime;
			
			memset(&ifr,0,sizeof(ifr));
			memset(&bindInfo,0,sizeof(bindInfo));
			memset(&destInfo,0,sizeof(destInfo));
			memset(&replyFrom,0,sizeof(replyFrom));
			memset(&arpPacket,0,sizeof(arpPacket));
			memset(&arpReply,0,sizeof(arpReply));
			
			try
			{
				// Create a socket
				sockNum = socket(PF_PACKET,SOCK_DGRAM,0);
				if (sockNum < 0)
					throw TSymLibErrorObj(errno,"During MAC lookup: Failed to obtain a network socket");
				
				// Get our NIC index
				strcpy(ifr.ifr_name,fDeviceName.c_str());
				if (ioctl(sockNum,SIOCGIFINDEX,&ifr) < 0)
				{
					errString = "Failed to locate interface '" + fDeviceName + "' in internal index";
					throw TSymLibErrorObj(errno,errString);
				}
				nicIndex = ifr.ifr_ifindex;
				
				// Make sure we can use the NIC
				if (ioctl(sockNum,SIOCGIFFLAGS,&ifr) < 0)
				{
					errString = "Failed to get status of interface '" + fDeviceName + "'";
					throw TSymLibErrorObj(errno,errString);
				}
				if (!(ifr.ifr_flags & IFF_UP))
				{
					errString = "During MAC lookup: Interface '" + fDeviceName + "' is not up";
					throw TSymLibErrorObj(errno,errString);
				}
				else if (ifr.ifr_flags & (IFF_NOARP|IFF_LOOPBACK))
				{
					errString = "Cannot use ARP on interface '" + fDeviceName + "'";
					throw TSymLibErrorObj(errno,errString);
				}
				
				// Get our local address
				if (ioctl(sockNum,SIOCGIFADDR,&ifr) < 0)
				{
					errString = "Failed to acquire IP address from '" + fDeviceName + "'";
					throw TSymLibErrorObj(errno,errString);
				}
				sockInfo = *(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr));
				
				// Set our bind info
				bindInfo.sll_family = AF_PACKET;
				bindInfo.sll_ifindex = nicIndex;
				bindInfo.sll_protocol = htons(ETH_P_ARP);
				
				// Try to bind the socket to the interface
				if (bind(sockNum,reinterpret_cast<struct sockaddr*>(&bindInfo),sizeof(bindInfo)) < 0)
					throw TSymLibErrorObj(errno,"During MAC lookup: bind() failed");
				
				// Get socket options
				optVal = sizeof(bindInfo);
				if (getsockname(sockNum,reinterpret_cast<struct sockaddr*>(&bindInfo),&optVal) < 0)
					throw TSymLibErrorObj(errno,"During MAC lookup: getsockname() for sll_halen failed");
				if (bindInfo.sll_halen == 0)
				{
					errString = "Cannot use ARP on interface '" + fDeviceName + "'";
					throw TSymLibErrorObj(errno,errString);
				}
				
				if (memcmp(&sockInfo.sin_addr.s_addr,&remoteIPAddress,sizeof(remoteIPAddress)) == 0)
				{
					// We're apparently trying to scan ourselves, which is mildly stupid,
					// but whatever.
					unsigned char*	ptr = bindInfo.sll_addr;
					char			macBuffer[24];
					
					sprintf(macBuffer,"%02X:%02X:%02X:%02X:%02X:%02X",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
					macAddress = macBuffer;
				}
				else
				{
					// Create a destination struct
					memcpy(&destInfo,&bindInfo,sizeof(bindInfo));
					memset(destInfo.sll_addr,0xFF,destInfo.sll_halen);
					
					// Construct the ARP packet
					arpPacket.ar_hrd = htons(ARPHRD_ETHER);
					arpPacket.ar_pro = htons(ETH_P_IP);
					arpPacket.ar_hln = ETHER_ADDR_LEN;
					arpPacket.ar_pln = 4;
					arpPacket.ar_op = htons(ARPOP_REQUEST);
					memcpy(arpPacket.ar_sha,bindInfo.sll_addr,bindInfo.sll_halen);
					memcpy(arpPacket.ar_sip,&sockInfo.sin_addr.s_addr,arpPacket.ar_pln);
					memcpy(arpPacket.ar_tha,destInfo.sll_addr,destInfo.sll_halen);
					memcpy(arpPacket.ar_tip,&remoteIPAddress,arpPacket.ar_pln);
					
					// Send the packet away
					if (sendto(sockNum,&arpPacket,sizeof(arpPacket),0,reinterpret_cast<struct sockaddr*>(&destInfo),sizeof(destInfo)) < 0)
						throw TSymLibErrorObj(errno,"Failed to send ARP request packet");
					
					// Get the reply
					expireTime = time(NULL) + kARPReplyTimeout;
					while (time(NULL) < expireTime)
					{
						struct timeval		selectTimeout;
						fd_set				selectSet;
						
						FD_ZERO(&selectSet);
						FD_SET(sockNum,&selectSet);
						selectTimeout.tv_sec = kARPReplyTimeout;
						selectTimeout.tv_usec = 0;
						
						if (select(sockNum+1,&selectSet,NULL,NULL,&selectTimeout) > 0)
						{
							optVal = sizeof(replyFrom);
							if (recvfrom(sockNum,&arpReply,sizeof(arpReply),0,reinterpret_cast<struct sockaddr*>(&replyFrom),&optVal) < 0)
								throw TSymLibErrorObj(errno,"Failed to receive ARP request packet");
							
							if (replyFrom.sll_pkttype == PACKET_HOST ||
								replyFrom.sll_pkttype == PACKET_BROADCAST ||
								replyFrom.sll_pkttype == PACKET_MULTICAST)
							{
								if (arpReply.ar_op == htons(ARPOP_REQUEST) || arpReply.ar_op == htons(ARPOP_REPLY))
								{
									if (arpReply.ar_hrd == htons(replyFrom.sll_hatype))
									{
										if (arpReply.ar_pro == htons(ETH_P_IP) &&
											arpReply.ar_pln == sizeof(remoteIPAddress) &&
											arpReply.ar_hln == bindInfo.sll_halen)
										{
											if (memcmp(arpReply.ar_sip,&remoteIPAddress,sizeof(remoteIPAddress)) == 0 &&
												memcmp(arpReply.ar_tha,bindInfo.sll_addr,arpReply.ar_hln) == 0)
											{
												unsigned char*	ptr = arpReply.ar_sha;
												char			macBuffer[24];
												
												sprintf(macBuffer,"%02X:%02X:%02X:%02X:%02X:%02X",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
												macAddress = macBuffer;
												break;
											}
										}
									}
								}
							}
						}
					}
				}
				
				if (sockNum != -1)
					close(sockNum);
			}
			catch (TSymLibErrorObj& errObj)
			{
				if (sockNum != -1)
					close(sockNum);
				if (!errObj.IsLogged())
				{
					WriteToErrorLog(errObj.GetDescription());
					errObj.MarkAsLogged();
				}
			}
			catch (...)
			{
				if (sockNum != -1)
					close(sockNum);
				WriteToErrorLog("Unknown error while looking up MAC address");
			}
			
			// Update the master map and addressCount
			{
				TLockedPthreadMutexObj	lock(fParentEnvironPtr->addressMapLock);
				
				if (macAddress.empty())
					macAddress = "{no_response}";
				fParentEnvironPtr->addressMap[remoteIPAddress] = macAddress;
				++fParentEnvironPtr->addressCount;
			}
		}
	}
#endif // USE_NETPACKET

#if USE_BPF
	//*********************************************************************
	// Class TARPTaskBPF
	//*********************************************************************
	
	//---------------------------------------------------------------------
	// Constructor
	//---------------------------------------------------------------------
	TARPTaskBPF::TARPTaskBPF (const string& deviceName, const IPAddressList& ipAddressList)
		:	Inherited(PROJECT_SHORT_NAME,0,false),
			fParentEnvironPtr(GetModEnviron()),
			fIPAddressList(ipAddressList),
			fDeviceName(deviceName)
	{
	}
	
	//---------------------------------------------------------------------
	// Destructor
	//---------------------------------------------------------------------
	TARPTaskBPF::~TARPTaskBPF ()
	{
	}
	
	//---------------------------------------------------------------------
	// TARPTaskBPF::RunTask
	//---------------------------------------------------------------------
	void TARPTaskBPF::RunTask ()
	{
		// Create our thread environment
		CreateModEnviron(fParentEnvironPtr);
		
		if ((GetDynamicDebuggingFlags() & kDynDebugLogServerCommunication) == kDynDebugLogServerCommunication)
			WriteToMessagesLog("Starting ARP Lookup Task");
		
		for (IPAddressList_const_iter x = fIPAddressList.begin(); x != fIPAddressList.end() && DoPluginEventLoop(); x++)
			_GetRemoteMACAddress(*x);
		
		if ((GetDynamicDebuggingFlags() & kDynDebugLogServerCommunication) == kDynDebugLogServerCommunication)
			WriteToMessagesLog("Ending ARP Lookup Task");
	}
	
	//---------------------------------------------------------------------
	// TARPTaskBPF::_GetRemoteMACAddress (protected)
	//---------------------------------------------------------------------
	void TARPTaskBPF::_GetRemoteMACAddress (unsigned long remoteIPAddress) const
	{
		if (fParentEnvironPtr && remoteIPAddress != 0)
		{
			string					macAddress;
			string					errString;
			string					myMACAddress;
			int						sockNum = -1;
			int						tempSocket = -1;
			struct ifreq			ifr;
			struct sockaddr_in		sockInfo;
			int						ioBufferSize = 0;
			char*					ioBufferPtr = NULL;
			ARPBPFReq				arpPacket;
			int						bytesMoved = 0;
			
			memset(&ifr,0,sizeof(ifr));
			memset(&sockInfo,0,sizeof(sockInfo));
			memset(&arpPacket,0,sizeof(arpPacket));
			
			try
			{
				// Open a temporary socket for ioctl calls
				tempSocket = socket(AF_INET,SOCK_DGRAM,0);
				if (tempSocket < 0)
					throw TSymLibErrorObj(errno,"Unable to open temporary network socket");
				
				// Make sure we can use the NIC
				strcpy(ifr.ifr_name,fDeviceName.c_str());
				if (ioctl(tempSocket,SIOCGIFFLAGS,&ifr) < 0)
				{
					errString = "Failed to get status of interface '" + fDeviceName + "'";
					throw TSymLibErrorObj(errno,errString);
				}
				if (!(ifr.ifr_flags & IFF_UP))
				{
					errString = "Interface '" + fDeviceName + "' is not up";
					throw TSymLibErrorObj(errno,errString);
				}
				else if (ifr.ifr_flags & (IFF_NOARP|IFF_LOOPBACK))
				{
					errString = "Cannot use ARP on interface '" + fDeviceName + "'";
					throw TSymLibErrorObj(errno,errString);
				}
				
				// Get our local address
				if (ioctl(tempSocket,SIOCGIFADDR,&ifr) < 0)
				{
					errString = "Failed to acquire IP address from '" + fDeviceName + "'";
					throw TSymLibErrorObj(errno,errString);
				}
				sockInfo = *(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr));
				
				// Close the temporary socket
				close(tempSocket);
				tempSocket = -1;
				
				// Get our MAC Address
				myMACAddress = _GetMyMACAddress();
				
				// Open a BPF socket
				sockNum = _OpenBPFDevice(remoteIPAddress);
				
				// Set buffer size for read/write on descriptor
				ioBufferSize = sizeof(arpPacket) + sizeof(struct bpf_hdr) + 32;
				if (ioctl(sockNum,BIOCSBLEN,&ioBufferSize) < 0)
				{
					errString = "Failed to set the size for I/O buffering for interface '" + fDeviceName + "'";
					throw TSymLibErrorObj(errno,errString);
				}
				
				// Allocate the buffer
				ioBufferPtr = new char[ioBufferSize];
				if (!ioBufferPtr)
					throw TSymLibErrorObj(errno,"Unable to allocate temporary buffer");
				
				// Bind the BPF descriptor to our device
				strcpy(ifr.ifr_name,fDeviceName.c_str());
				if (ioctl(sockNum,BIOCSETIF,&ifr) < 0)
				{
					errString = "Failed to bind BPF socket to '" + fDeviceName + "'";
					throw TSymLibErrorObj(errno,errString);
				}
				
				if (memcmp(&sockInfo.sin_addr.s_addr,&remoteIPAddress,sizeof(remoteIPAddress)) == 0)
				{
					// We're apparently trying to scan ourselves, which is mildly stupid,
					// but whatever.
					const unsigned char*	ptr = reinterpret_cast<const unsigned char*>(myMACAddress.data());
					char					macBuffer[24];
					
					sprintf(macBuffer,"%02X:%02X:%02X:%02X:%02X:%02X",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
					macAddress = macBuffer;
				}
				else
				{
					// Construct the ARP packet
					memcpy(arpPacket.ether_shost,myMACAddress.data(),ETHER_ADDR_LEN);
					memset(arpPacket.ether_dhost,0xFF,ETHER_ADDR_LEN);
					arpPacket.ether_type = htons(ETHERTYPE_ARP);
					arpPacket.ar_hrd = htons(ARPHRD_ETHER);
					arpPacket.ar_pro = htons(ETH_P_IP);
					arpPacket.ar_hln = ETHER_ADDR_LEN;
					arpPacket.ar_pln = 4;
					arpPacket.ar_op = htons(ARPOP_REQUEST);
					memcpy(arpPacket.ar_sha,myMACAddress.data(),ETHER_ADDR_LEN);
					memcpy(arpPacket.ar_sip,&sockInfo.sin_addr.s_addr,arpPacket.ar_pln);
					memset(arpPacket.ar_tha,0xFF,ETHER_ADDR_LEN);
					memcpy(arpPacket.ar_tip,&remoteIPAddress,arpPacket.ar_pln);
					
					// Send the packet away
					bytesMoved = write(sockNum,&arpPacket,sizeof(arpPacket));
					if (bytesMoved <= 0)
						throw TSymLibErrorObj(errno,"Failed to send ARP request packet");
					
					// Wait for the reply
					bytesMoved = read(sockNum,ioBufferPtr,ioBufferSize);
					if (bytesMoved < 0)
					{
						throw TSymLibErrorObj(errno,"Error while waiting for ARP reply packet");
					}
					else if (bytesMoved > 0)
					{
						struct bpf_hdr*	bpfHeaderPtr = reinterpret_cast<struct bpf_hdr*>(ioBufferPtr);
						ARPBPFReq*		arpReplyPtr = reinterpret_cast<ARPBPFReq*>(ioBufferPtr + bpfHeaderPtr->bh_hdrlen);
						unsigned char*	ptr = arpReplyPtr->ar_sha;
						char			macBuffer[24];
						
						sprintf(macBuffer,"%02X:%02X:%02X:%02X:%02X:%02X",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
						macAddress = macBuffer;
					}
				}
				
				if (sockNum != -1)
					close(sockNum);
				
				if (ioBufferPtr)
				{
					delete(ioBufferPtr);
					ioBufferPtr = NULL;
				}
			}
			catch (TSymLibErrorObj& errObj)
			{
				if (tempSocket != -1)
					close(tempSocket);
				if (sockNum != -1)
					close(sockNum);
				if (ioBufferPtr)
				{
					delete(ioBufferPtr);
					ioBufferPtr = NULL;
				}
				if (!errObj.IsLogged())
				{
					WriteToErrorLog(errObj.GetDescription());
					errObj.MarkAsLogged();
				}
			}
			catch (...)
			{
				if (tempSocket != -1)
					close(tempSocket);
				if (sockNum != -1)
					close(sockNum);
				if (ioBufferPtr)
				{
					delete(ioBufferPtr);
					ioBufferPtr = NULL;
				}
				WriteToErrorLog("Unknown error while looking up MAC address");
			}
			
			// Update the master map and addressCount
			{
				TLockedPthreadMutexObj	lock(fParentEnvironPtr->addressMapLock);
				
				if (macAddress.empty())
					macAddress = "{no_response}";
				fParentEnvironPtr->addressMap[remoteIPAddress] = macAddress;
				++fParentEnvironPtr->addressCount;
			}
		}
	}
	
	//---------------------------------------------------------------------
	// TARPTaskBPF::_OpenBPFDevice (protected)
	//---------------------------------------------------------------------
	int TARPTaskBPF::_OpenBPFDevice (unsigned long remoteIPAddress) const
	{
		int					bpfFD = -1;
		int					ioctlArg = 0;
		struct timeval		timeout;
		struct bpf_insn		arpReplyFilterCode[] =
									{
										BPF_STMT(BPF_LD|BPF_H|BPF_ABS,ETHER_ADDR_LEN*2),			// Extract Ethertype
										BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,ETHERTYPE_ARP,0,5),			// ARP Data?
										BPF_STMT(BPF_LD|BPF_H|BPF_ABS,20),							// Extract ARP opcode
										BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,ARPOP_REPLY,0,3),			// ARPOP_REPLY?
										BPF_STMT(BPF_LD|BPF_W|BPF_ABS,28),							// Extract source IP address
										BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,ntohl(remoteIPAddress),0,1),	// Our remote IP address?
										BPF_STMT(BPF_RET|BPF_K,sizeof(ARPBPFReq)),					// Good return
										BPF_STMT(BPF_RET|BPF_K,0)									// Failed return
									};
		struct bpf_program	arpReplyFilter;
		
		arpReplyFilter.bf_len = sizeof(arpReplyFilterCode)/sizeof(struct bpf_insn);
		arpReplyFilter.bf_insns = arpReplyFilterCode;
		
		for (int x = 0; x < 256; x++)
		{
			char	dev[32];
			
			sprintf(dev,"/dev/bpf%d",x);
			bpfFD = open(dev,O_RDWR);
			
			if (bpfFD >= 0)
				break;
		}
		
		try
		{
			if (bpfFD < 0)
				throw TSymLibErrorObj(kErrorUnableToObtainBPFDeviceDescriptor,"Unable to acquire BPF device descriptor");
			
			// Set descriptor to immediate mode
			ioctlArg = 1;
			if (ioctl(bpfFD,BIOCIMMEDIATE,&ioctlArg) < 0)
				throw TSymLibErrorObj(errno,"Unable to put BPF device into immediate mode");
			
			// Accept only incoming packets
			ioctlArg = 0;
			if (ioctl(bpfFD,BIOCGSEESENT,&ioctlArg) < 0)
				throw TSymLibErrorObj(errno,"Unable to put BPF device into scan-incoming-only mode");
			
			// Don't let the interface add headers
			ioctlArg = 0;
			if (ioctl(bpfFD,BIOCGHDRCMPLT,&ioctlArg) < 0)
				throw TSymLibErrorObj(errno,"Unable to strip header inclusion in BPF device");
			
			// Set the timeout
			timeout.tv_sec = kARPReplyTimeout;
			timeout.tv_usec = 0;
			if (ioctl(bpfFD,BIOCSRTIMEOUT,&timeout) < 0)
				throw TSymLibErrorObj(errno,"Unable to install I/O timeout on BPF device");
			
			// Set the filter
			if (ioctl(bpfFD,BIOCSETF,&arpReplyFilter) < 0)
				throw TSymLibErrorObj(errno,"Unable to install BPF filter on device");
		}
		catch (...)
		{
			if (bpfFD != -1)
				close(bpfFD);
			throw;
		}
		
		return bpfFD;
	}
	
	//---------------------------------------------------------------------
	// TARPTaskBPF::_GetMyMACAddress (protected)
	//---------------------------------------------------------------------
	string TARPTaskBPF::_GetMyMACAddress () const
	{
		string		myMACAddress;
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
			string		tempBuffer;
			
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
						string				sdlName(&sdl->sdl_data[0],sdl->sdl_nlen);
						
						if (sdlName == fDeviceName)
						{
							myMACAddress = string(LLADDR(sdl),ETHER_ADDR_LEN);
							break;
						}
					}
				}
			}
		}
		
		if (myMACAddress.empty())
		{
			string		errString;
			
			errString = "Unable to obtain MAC address of interface '" + fDeviceName + "'";
			throw TSymLibErrorObj(errno,errString);
		}
		
		return myMACAddress;
	}
	
#endif // USE_BPF

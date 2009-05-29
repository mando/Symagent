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
#		Created:					05 Nov 2003
#		Last Modified:				18 Mar 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "pcap-interface.h"

#include "plugin-utils.h"

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//*********************************************************************
// Class TCapturedPacket
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TCapturedPacket::TCapturedPacket ()
	:	fData(NULL)
{
	memset(&fHeader,0,sizeof(fHeader));
}

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
TCapturedPacket::TCapturedPacket (const TCapturedPacket& obj)
	:	fHeader(obj.fHeader)
{
	if (fHeader.caplen > 0)
	{
		fData = static_cast<u_char*>(malloc(fHeader.caplen));
		if (!fData)
			throw ENOMEM;
		
		memcpy(fData,obj.fData,fHeader.caplen);
	}
	else
	{
		fData = NULL;
	}
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TCapturedPacket::~TCapturedPacket ()
{
	if (fData)
		free(fData);
}

//---------------------------------------------------------------------
// TCapturedPacket::Set
//---------------------------------------------------------------------
void TCapturedPacket::Set (const struct pcap_pkthdr* headerPtr, const u_char* dataPtr)
{
	if (fData)
	{
		// We already have memory allocated
		if (fHeader.caplen < headerPtr->caplen)
		{
			// We don't have enough already allocated; deallocate so we
			// can allocate later
			free(fData);
			fData = NULL;
		}
	}
	
	memcpy(&fHeader,headerPtr,sizeof(fHeader));
	
	if (fHeader.caplen > 0)
	{
		if (fData == NULL)
		{
			fData = static_cast<u_char*>(malloc(fHeader.caplen));
			if (!fData)
				throw ENOMEM;
		}
		
		memcpy(fData,dataPtr,fHeader.caplen);
	}
}

//---------------------------------------------------------------------
// TCapturedPacket::Clear
//---------------------------------------------------------------------
void TCapturedPacket::Clear ()
{
	memset(&fHeader,0,sizeof(fHeader));
	if (fData)
	{
		free(fData);
		fData = NULL;
	}
}

//*********************************************************************
// Class TPCAPObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPCAPObj::TPCAPObj ()
	:	fPCAPHandle(NULL),
		fCaptureSize(BUFSIZ),
		fRawPacketRing(kPacketBufferRingSize),
		fRawPacketRingNextPos(0),
		fPacketsCapturedCount(0),
		fExternalPacketRing(NULL),
		fFileDescriptor(-1),
		fIsCapturing(false)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPCAPObj::~TPCAPObj ()
{
	CloseInterface();
	
	fDevice = "";
}

//---------------------------------------------------------------------
// TPCAPObj::OpenInterface
//---------------------------------------------------------------------
void TPCAPObj::OpenInterface (const string& device, bool promiscuous)
{
	PCAPErrBuffer	errorBuffer;
	
	errorBuffer[0] = '\0';
	
	// Close any existing interface
	CloseInterface();
	
	// Get an interface from PCAP
	fPCAPHandle = pcap_open_live(const_cast<char*>(device.c_str()),fCaptureSize,(promiscuous ? 1 : 0),1000,errorBuffer);
	
	if (!fPCAPHandle)
		throw TSymLibErrorObj(kErrorPCAPLibraryError,errorBuffer);
	
	fDevice = device;
	fFileDescriptor = pcap_fileno(fPCAPHandle);
}

//---------------------------------------------------------------------
// TPCAPObj::CloseInterface
//---------------------------------------------------------------------
void TPCAPObj::CloseInterface ()
{
	if (fPCAPHandle)
	{
		pcap_close(fPCAPHandle);
		fPCAPHandle = NULL;
		fFileDescriptor = -1;
	}
}

//---------------------------------------------------------------------
// TPCAPObj::SetFilter
//---------------------------------------------------------------------
void TPCAPObj::SetFilter (const string& filterCommand, bool optimize)
{
	struct bpf_program		filterProgram;
	PCAPNetworkInfo			netInfo;
	
	if (!fPCAPHandle)
		throw TSymLibErrorObj(kErrorPCAPInterfaceNotOpen,"A PCAP interface has not been opened");
	
	netInfo = LookupNetworkInfo(fDevice);
	
	if (pcap_compile(fPCAPHandle,&filterProgram,const_cast<char*>(filterCommand.c_str()),(optimize ? 1 : 0),netInfo.netMask) < 0)
		throw TSymLibErrorObj(kErrorPCAPLibraryError,pcap_geterr(fPCAPHandle));
	
	// We now need to be careful to always dispose of the compiled filter program
	try
	{
		// Set the compiled filter program
		if (pcap_setfilter(fPCAPHandle,&filterProgram) < 0)
		{
			string	errString;
			
			errString += "While trying to compile filter: '" + filterCommand + "'; received: ";
			errString += pcap_geterr(fPCAPHandle);
			throw TSymLibErrorObj(kErrorPCAPLibraryError,errString);
		}
	}
	catch (...)
	{
		pcap_freecode(&filterProgram);
		throw;
	}
	
	// Normal termination of method
	pcap_freecode(&filterProgram);
}

//---------------------------------------------------------------------
// TPCAPObj::CaptureNPackets
//---------------------------------------------------------------------
unsigned long TPCAPObj::CaptureNPackets (unsigned long packetCount)
{
	int				result = 0;
	
	if (!fPCAPHandle)
		throw TSymLibErrorObj(kErrorPCAPInterfaceNotOpen,"A PCAP interface has not been opened");
	
	// Initialize the raw packet ring
	ClearPacketRing();
	
	fIsCapturing = true;
	while (fPacketsCapturedCount < packetCount && DoPluginEventLoop())
	{
		result = pcap_loop(fPCAPHandle,packetCount-fPacketsCapturedCount,_DispatchCallback,reinterpret_cast<u_char*>(this));
		
		if (result < 0)
		{
			fIsCapturing = false;
			throw TSymLibErrorObj(kErrorPCAPLibraryError,pcap_geterr(fPCAPHandle));
		}
	}
	fIsCapturing = false;
	
	return fPacketsCapturedCount;
}

//---------------------------------------------------------------------
// TPCAPObj::CapturePackets
//---------------------------------------------------------------------
unsigned long TPCAPObj::CapturePackets (unsigned long durationInSeconds,
										bool allowRingOverfill)
{
	int				result = 0;
	time_t			expireTime = time(NULL) + durationInSeconds;
	
	if (!fPCAPHandle)
		throw TSymLibErrorObj(kErrorPCAPInterfaceNotOpen,"A PCAP interface has not been opened");
	
	// Initialize the raw packet ring
	fRawPacketRingNextPos = 0;
	fPacketsCapturedCount = 0;
	
	fIsCapturing = true;
	while (time(NULL) < expireTime && DoPluginEventLoop())
	{
		result = pcap_dispatch(fPCAPHandle,1,_DispatchCallback,reinterpret_cast<u_char*>(this));
		
		if (result < 0)
		{
			fIsCapturing = false;
			throw TSymLibErrorObj(kErrorPCAPLibraryError,pcap_geterr(fPCAPHandle));
		}
		
		if (!allowRingOverfill && fPacketsCapturedCount >= kPacketBufferRingSize)
			break;
	}
	fIsCapturing = false;
	
	return fPacketsCapturedCount;
}

//---------------------------------------------------------------------
// TPCAPObj::CapturePackets
//---------------------------------------------------------------------
unsigned long TPCAPObj::CapturePackets (unsigned long durationInSeconds,
										RawPacketList* externalPacketList)
{
	int				result = 0;
	time_t			expireTime = 0;
	unsigned long	packetsCapturedCount = 0;
	
	if (!fPCAPHandle)
		throw TSymLibErrorObj(kErrorPCAPInterfaceNotOpen,"A PCAP interface has not been opened");
	
	if (!externalPacketList)
		throw TSymLibErrorObj(kErrorExternalPacketListNotProvided,"External packet list not provided");
	
	try
	{
		// Remember the pointer to the external list
		fExternalPacketRing = externalPacketList;
		
		// Determine the expiration time
		expireTime = time(NULL) + durationInSeconds;
		
		fIsCapturing = true;
		while (time(NULL) <= expireTime && DoPluginEventLoop())
		{
			result = pcap_dispatch(fPCAPHandle,1,_DispatchCallback,reinterpret_cast<u_char*>(this));
			if (result < 0)
			{
				fIsCapturing = false;
				throw TSymLibErrorObj(kErrorPCAPLibraryError,pcap_geterr(fPCAPHandle));
			}
			
			if (fExternalPacketRing->size() >= kPacketBufferRingSize)
				break;
		}
		fIsCapturing = false;
		packetsCapturedCount = fExternalPacketRing->size();
		fExternalPacketRing = NULL;
	}
	catch (...)
	{
		fExternalPacketRing = NULL;
		throw;
	}
	
	return packetsCapturedCount;
}

//---------------------------------------------------------------------
// TPCAPObj::GetCapturedPackets
//---------------------------------------------------------------------
unsigned long TPCAPObj::GetCapturedPackets (RawPacketList& packetList, bool clearPacketRing)
{
	packetList.clear();
	
	if (fPacketsCapturedCount > 0)
	{
		if (fPacketsCapturedCount > kPacketBufferRingSize)
		{
			RawPacketList_iter	startPos = fRawPacketRing.begin() + (fPacketsCapturedCount % kPacketBufferRingSize) + 1;
			
			packetList.reserve(kPacketBufferRingSize);
			
			packetList.insert(packetList.begin(),startPos,fRawPacketRing.end());
			packetList.insert(packetList.begin(),fRawPacketRing.begin(),startPos - 1);
		}
		else
		{
			// Captured fewer packets than our ring size -- copy them all in order
			packetList.reserve(fPacketsCapturedCount);
			packetList.insert(packetList.begin(),fRawPacketRing.begin(),fRawPacketRing.begin() + fPacketsCapturedCount);
		}
	}
	
	if (clearPacketRing)
		ClearPacketRing();
	
	return packetList.size();
}

//---------------------------------------------------------------------
// TPCAPObj::ClearPacketRing
//---------------------------------------------------------------------
void TPCAPObj::ClearPacketRing ()
{
	fRawPacketRingNextPos = 0;
	fPacketsCapturedCount = 0;
	
	for (RawPacketList_iter x = fRawPacketRing.begin(); x != fRawPacketRing.end(); x++)
		x->Clear();
}

//---------------------------------------------------------------------
// TPCAPObj::FileDescriptor
//---------------------------------------------------------------------
int TPCAPObj::FileDescriptor () const
{
	if (!fPCAPHandle)
		throw TSymLibErrorObj(kErrorPCAPInterfaceNotOpen,"A PCAP interface has not been opened");
	
	return fFileDescriptor;
}

//---------------------------------------------------------------------
// TPCAPObj::DataLinkType
//---------------------------------------------------------------------
int TPCAPObj::DataLinkType () const
{
	if (!fPCAPHandle)
		throw TSymLibErrorObj(kErrorPCAPInterfaceNotOpen,"A PCAP interface has not been opened");
	
	return pcap_datalink(fPCAPHandle);
}

//---------------------------------------------------------------------
// TPCAPObj::CurrentStats
//---------------------------------------------------------------------
struct pcap_stat TPCAPObj::CurrentStats () const
{
	struct pcap_stat		stats;
	
	if (!fPCAPHandle)
		throw TSymLibErrorObj(kErrorPCAPInterfaceNotOpen,"A PCAP interface has not been opened");
	
	if (pcap_stats(fPCAPHandle,&stats) < 0)
		throw TSymLibErrorObj(kErrorPCAPLibraryError,pcap_geterr(fPCAPHandle));
	
	return stats;
}

//---------------------------------------------------------------------
// TPCAPObj::GetInterfaceList (static)
//---------------------------------------------------------------------
unsigned long TPCAPObj::GetInterfaceList (StdStringList& interfaceList)
{
	#if defined(HAVE_PCAP_FINDALLDEVS) && HAVE_PCAP_FINDALLDEVS
		pcap_if_t*		devList = NULL;
		PCAPErrBuffer	errorBuffer;
		
		try
		{
			if (pcap_findalldevs(&devList,errorBuffer) == -1)
				throw TSymLibErrorObj(kErrorPCAPLibraryError,errorBuffer);
			
			if (devList)
			{
				pcap_if_t*	oneDevice = devList;
				while (oneDevice)
				{
					interfaceList.push_back(oneDevice->name);
					oneDevice = oneDevice->next;
				}
				
				pcap_freealldevs(devList);
			}
		}
		catch (...)
		{
			if (devList)
				pcap_freealldevs(devList);
			throw;
		}
	#else
		NetworkInterfaceList(interfaceList);
	#endif
	
	return interfaceList.size();
}

//---------------------------------------------------------------------
// TPCAPObj::LookupDevice (static)
//---------------------------------------------------------------------
string TPCAPObj::LookupDevice ()
{
	string			device;
	PCAPErrBuffer	errorBuffer;
	
	errorBuffer[0] = '\0';
	device = pcap_lookupdev(errorBuffer);
	
	if (device.empty())
		throw TSymLibErrorObj(kErrorPCAPLibraryError,errorBuffer);
	
	return device;
}

//---------------------------------------------------------------------
// TPCAPObj::LookupNetworkInfo (static)
//---------------------------------------------------------------------
PCAPNetworkInfo TPCAPObj::LookupNetworkInfo (const string& device)
{
	PCAPNetworkInfo		info;
	PCAPErrBuffer		errorBuffer;
	
	errorBuffer[0] = '\0';
	
	if (pcap_lookupnet(const_cast<char*>(device.c_str()),&info.netNumber,&info.netMask,errorBuffer) < 0)
		throw TSymLibErrorObj(kErrorPCAPLibraryError,errorBuffer);
	
	return info;
}

//---------------------------------------------------------------------
// TPCAPObj::DataLinkDescription (static)
//---------------------------------------------------------------------
string TPCAPObj::DataLinkDescription (int dataLinkType)
{
	string		description;
	
	switch (dataLinkType)
	{
		case DLT_NULL:		description = "No link-layer encapsulation";	break;
		case DLT_EN10MB:	description = "Ethernet (10Mb)";				break;
		case DLT_EN3MB:		description = "Experimental Ethernet (3Mb)";	break;
		case DLT_AX25:		description = "Amateur Radio AX.25";			break;
		case DLT_PRONET:	description = "Proteon ProNET Token Ring";		break;
		case DLT_CHAOS:		description = "Chaos";							break;
		case DLT_IEEE802:	description = "IEEE 802 Networks";				break;
		case DLT_ARCNET:	description = "ARCNET";							break;
		case DLT_SLIP:		description = "Serial Line IP";					break;
		case DLT_PPP:		description = "Point-to-point Protocol";		break;
		case DLT_FDDI:		description = "FDDI";							break;
		default:			description = "Unknown link type";				break;
	}
	
	return description;
}

//---------------------------------------------------------------------
// TPCAPObj::_HandlePacket (protected)
//---------------------------------------------------------------------
void TPCAPObj::_HandlePacket (const struct pcap_pkthdr* header, const u_char* packet)
{
	unsigned long	pos = 0;
	
	if (fExternalPacketRing == NULL)
	{
		pos = fRawPacketRingNextPos++;
		fRawPacketRing[pos].Set(header,packet);
		
		fRawPacketRingNextPos = fRawPacketRingNextPos % kPacketBufferRingSize;
		++fPacketsCapturedCount;
	}
	else
	{
		fExternalPacketRing->push_back(TCapturedPacket());
		fExternalPacketRing->back().Set(header,packet);
	}
}

//---------------------------------------------------------------------
// TPCAPObj::_DispatchCallback (protected static)
//---------------------------------------------------------------------
void TPCAPObj::_DispatchCallback (u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
	TPCAPObj*	pcapObjPtr = reinterpret_cast<TPCAPObj*>(args);
	
	if (pcapObjPtr)
		pcapObjPtr->_HandlePacket(header,packet);
}

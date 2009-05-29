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
#		Created:					10 Nov 2003
#		Last Modified:				23 Mar 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "sniff-task.h"


#include <memory>

//---------------------------------------------------------------------
// Namespace stuff
//---------------------------------------------------------------------
using namespace std;

//---------------------------------------------------------------------
// Module Definitions
//---------------------------------------------------------------------
#define	kXMLTagNetworkTraffice						"NET_TRAFFIC"
#define	kXMLTagPacket								"PACKET"
#define	kXMLTagPacketSource							"SRC"
#define	kXMLTagPacketDestination					"DST"

#define	kXMLAttributeDeviceName						"device"
#define	kXMLAttributePacketTimestamp				"ptime"
#define	kXMLAttributePacketProtocol					"proto"
#define	kXMLAttributePacketProtocolFamily			"family"
#define	kXMLAttributePacketSize						"size"
#define	kXMLAttributeSequenceNumber					"sequence_number"
#define	kXMLAttributeMACAddress						"mac_id"
#define	kXMLAttributeIPAddress						"ip"
#define	kXMLAttributePort							"port"
#define	kXMLAttributeService						"service"
#define	kXMLAttributePacketCount					"packet_count"
#define	kXMLAttributeUnknownCount					"unknown_count"

#define	kXMLAttributeTimestampStart					"ptime_start"
#define	kXMLAttributeTimestampEnd					"ptime_end"
#define	kXMLAttributeByteCount						"byte_count"

//---------------------------------------------------------------------
// Module Definitions for summarized packet reporting
//---------------------------------------------------------------------
typedef struct
	{
		char				protocol[20];
		char				protoFamily[20];
		char				sourceMACAddr[20];
		char				destMACAddr[20];
		char				sourceIPAddr[20];
		char				destIPAddr[20];
		unsigned int		sourcePort;
		unsigned int		destPort;
		unsigned int		size;
		unsigned int		sequenceNumber;
	} SummarizedPacket;

class SPLess
{
	public:
		
		inline bool operator() (const SummarizedPacket& x, const SummarizedPacket& y) const
			{ return (memcmp(&x,&y,sizeof(x)) < 0); }
};

typedef	map<SummarizedPacket,unsigned long,SPLess>		SummarizedPacketMap;
typedef SummarizedPacketMap::iterator					SummarizedPacketMap_iter;
typedef SummarizedPacketMap::const_iterator				SummarizedPacketMap_const_iter;

struct ServiceMapGlobals
	{
		ServiceMap			serviceMap;
	};

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
static	ServiceMapGlobals*								gServiceMapGlobalsPtr = NULL;
static	TPthreadMutexObj								gServiceMapLock;

//*********************************************************************
// Class TSniffTask
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSniffTask::TSniffTask (time_t intervalInSeconds, bool rerun)
	:	Inherited(PROJECT_SHORT_NAME,intervalInSeconds,rerun),
		fCaptureDuration(0),
		fPacketsCaptured(0),
		fReportingMode(kReportingModeNormal),
		fParentEnvironPtr(GetModEnviron()),
		fSendInfoTaskCount(0)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSniffTask::~TSniffTask ()
{
}

//---------------------------------------------------------------------
// TSniffTask::SetupTask
//---------------------------------------------------------------------
void TSniffTask::SetupTask (std::string deviceName,
							bool promiscuous,
							time_t captureDuration,
							const std::string& programFilter,
							unsigned long packetCaptureSize)
{
	// Setup the internal PCAP object
	if (deviceName.empty())
		deviceName = fPCAPObj.LookupDevice();
	fPCAPObj.OpenInterface(deviceName,promiscuous);
	fPCAPObj.SetMaxCaptureSize(packetCaptureSize);
	fPCAPObj.SetFilter(programFilter,true);
	
	// Set the duration for each packet sniff
	SetCaptureDuration(captureDuration);
	
	// Initialize the global variables if necessary
	if (!gServiceMapGlobalsPtr)
	{
		TLockedPthreadMutexObj		lock(gServiceMapLock);
		
		if (!gServiceMapGlobalsPtr)
		{
			struct servent*		serviceEntryPtr;
			
			gServiceMapGlobalsPtr = new ServiceMapGlobals;
			
			serviceEntryPtr = getservent();
			
			while (serviceEntryPtr)
			{
				gServiceMapGlobalsPtr->serviceMap[make_pair(static_cast<unsigned int>(ntohs(serviceEntryPtr->s_port)),string(serviceEntryPtr->s_proto))] = serviceEntryPtr->s_name;
				serviceEntryPtr = getservent();
			}
			endservent();
		}
	}
}

//---------------------------------------------------------------------
// TSniffTask::RunTask
//---------------------------------------------------------------------
void TSniffTask::RunTask ()
{
	// Create our thread environment
	CreateModEnviron(fParentEnvironPtr);
	
	while (DoPluginEventLoop())
		Main();
	
	while (fSendInfoTaskCount > 0)
		PauseExecution(.5);
}

//---------------------------------------------------------------------
// TSniffTask::Main
//---------------------------------------------------------------------
void TSniffTask::Main ()
{
	TSendInfoTask*		sendTaskObjPtr = new TSendInfoTask(fReportingMode,fPCAPObj.CurrentDevice(),this);
	
	if (sendTaskObjPtr)
	{
		try
		{
			fPacketsCaptured = fPCAPObj.CapturePackets(fCaptureDuration,&(sendTaskObjPtr->fRawPacketList));
			if (fPacketsCaptured > 0 && DoPluginEventLoop())
				AddTaskToQueue(sendTaskObjPtr,true);
			else
				delete(sendTaskObjPtr);
		}
		catch (...)
		{
			delete(sendTaskObjPtr);
		}
	}
}

//*********************************************************************
// Class TSendInfoTask
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSendInfoTask::TSendInfoTask (ReportingMode reportingMode,
							  const string& deviceName,
							  TSniffTask* parentSniffTaskPtr)
	:	Inherited(PROJECT_SHORT_NAME,0,false),
		fReportingMode(reportingMode),
		fDeviceName(deviceName),
		fParentEnvironPtr(GetModEnviron()),
		fParentSniffTaskPtr(parentSniffTaskPtr)
{
	fRawPacketList.reserve(kPacketBufferRingSize);
	
	if (fParentSniffTaskPtr)
		fParentSniffTaskPtr->IncrementTaskCount();
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSendInfoTask::~TSendInfoTask ()
{
	if (fParentSniffTaskPtr)
		fParentSniffTaskPtr->DecrementTaskCount();
}

//---------------------------------------------------------------------
// TSendInfoTask::RunTask
//---------------------------------------------------------------------
void TSendInfoTask::RunTask ()
{
	TServerMessage		messageObj;
	TServerReply		replyObj;
	
	// Create our thread environment
	CreateModEnviron(fParentEnvironPtr);
	
	if (IsConnectedToServer() && DoPluginEventLoop())
	{
		// Create the outbound message
		CreateTrafficeMessage(messageObj);
	}
	
	if (IsConnectedToServer() && DoPluginEventLoop())
	{
		// Send it to the server
		SendToServer(messageObj,replyObj);
	}
}

//---------------------------------------------------------------------
// TSendInfoTask::CreateTrafficeMessage
//---------------------------------------------------------------------
unsigned long TSendInfoTask::CreateTrafficeMessage (TServerMessage& parentMessage)
{
	unsigned long	packetCount = 0;
	
	switch (fReportingMode)
	{
		case kReportingModeNormal:
			packetCount = _NormalTrafficeMessage(parentMessage);
			break;
		
		case kReportingModeSummary:
			packetCount = _SummaryTrafficeMessage(parentMessage);
			break;
	}
	
	return packetCount;
}

//---------------------------------------------------------------------
// TSendInfoTask::_NormalTrafficeMessage (protected)
//---------------------------------------------------------------------
unsigned long TSendInfoTask::_NormalTrafficeMessage (TServerMessage& parentMessage)
{
	unsigned long		packetsProcessed = 0;
	unsigned long		packetListSize = 0;
	unsigned long		packetByteCount = 0;
	TMessageNode		netTrafficNode;
	
	packetListSize = fRawPacketList.size();
	
	netTrafficNode = parentMessage.Append(kXMLTagNetworkTraffice,kXMLAttributeDeviceName,fDeviceName);
	
	for (RawPacketList_const_iter x = fRawPacketList.begin(); x != fRawPacketList.end(); x++)
	{
		auto_ptr<TPacket>		packetObjPtr(CreatePacketObj(*x));
		
		if (packetObjPtr.get())
		{
			TMessageNode		packetNode(netTrafficNode.Append(kXMLTagPacket,"",""));
			unsigned long long	timestampNum = static_cast<unsigned long long>(packetObjPtr->TimestampMilliseconds() * 1000);
			
			packetNode.AddAttribute(kXMLAttributePacketTimestamp,NumToString(timestampNum));
			packetNode.AddAttribute(kXMLAttributePacketProtocol,packetObjPtr->PacketTypeDescription());
			packetNode.AddAttribute(kXMLAttributePacketProtocolFamily,packetObjPtr->ProtocolFamilyDescription());
			packetNode.AddAttribute(kXMLAttributePacketSize,NumToString(packetObjPtr->PayloadSize()));
			
			packetByteCount += x->ActualSize();
			
			if (packetObjPtr->IsPacketType(kPacketTypeEthernet))
			{
				TMessageNode	sourceNode;
				TMessageNode	destNode;
				string			serviceName;
				
				sourceNode = packetNode.Append(kXMLTagPacketSource,"","");
				sourceNode.AddAttribute(kXMLAttributeMACAddress,packetObjPtr->SourceMACAddressAsString());
				
				destNode = packetNode.Append(kXMLTagPacketDestination,"","");
				destNode.AddAttribute(kXMLAttributeMACAddress,packetObjPtr->DestinationMACAddressAsString());
				
				if (packetObjPtr->IsPacketType(kPacketTypeIPv4) || packetObjPtr->IsPacketType(kPacketTypeIPv6))
				{
					bool	hasPorts = packetObjPtr->IsPacketType(kPacketTypeTCPv4) ||
									   packetObjPtr->IsPacketType(kPacketTypeUDPv4) ||
									   packetObjPtr->IsPacketType(kPacketTypeTCPv6) ||
									   packetObjPtr->IsPacketType(kPacketTypeUDPv6);
					
					sourceNode.AddAttribute(kXMLAttributeIPAddress,packetObjPtr->SourceIPAddressAsString());
					destNode.AddAttribute(kXMLAttributeIPAddress,packetObjPtr->DestinationIPAddressAsString());
					
					if (hasPorts)
					{
						sourceNode.AddAttribute(kXMLAttributePort,NumToString(packetObjPtr->SourcePort()));
						destNode.AddAttribute(kXMLAttributePort,NumToString(packetObjPtr->DestinationPort()));
						serviceName = _LookupServiceName(packetObjPtr->PacketTypeDescription(),packetObjPtr->SourcePort(),packetObjPtr->DestinationPort());
					}
				}
				
				packetNode.AddAttribute(kXMLAttributeService,serviceName);
			    packetNode.AddAttribute(kXMLAttributeSequenceNumber,NumToString(packetObjPtr->SequenceNumber()));
			}
			
			++packetsProcessed;
		}
	}
	
	// Add the number of packets in the list
	netTrafficNode.AddAttribute(kXMLAttributePacketCount,NumToString(packetsProcessed));
	
	// Add the number of unknown packets
	netTrafficNode.AddAttribute(kXMLAttributeUnknownCount,NumToString(packetListSize - packetsProcessed));
	
	// Add the total number of bytes passing over the wire
	netTrafficNode.AddAttribute(kXMLAttributeByteCount,NumToString(packetByteCount));
	
	return packetsProcessed;
}

//---------------------------------------------------------------------
// TSendInfoTask::_SummaryTrafficeMessage (protected)
//---------------------------------------------------------------------
unsigned long TSendInfoTask::_SummaryTrafficeMessage (TServerMessage& parentMessage)
{
	unsigned long		packetsProcessed = 0;
	unsigned long		packetListSize = 0;
	unsigned long		packetByteCount = 0;
	TMessageNode		netTrafficNode;
	
	packetListSize = fRawPacketList.size();
	
	netTrafficNode = parentMessage.Append(kXMLTagNetworkTraffice,kXMLAttributeDeviceName,fDeviceName);
	
	// Summaries the collected packets, if any
	if (packetListSize > 0)
	{
		SummarizedPacketMap		packetMap;
		unsigned long long		beginTimestamp = 0;
		unsigned long long		endTimestamp = 0;
		string					tempString;
		
		for (RawPacketList_const_iter x = fRawPacketList.begin(); x != fRawPacketList.end(); x++)
		{
			auto_ptr<TPacket>		packetObjPtr(CreatePacketObj(*x));
			
			if (packetObjPtr.get())
			{
				SummarizedPacket	summary;
				
				memset(&summary,0,sizeof(summary));
				
				packetByteCount += x->ActualSize();
				
				endTimestamp = static_cast<unsigned long long>(packetObjPtr->TimestampMilliseconds() * 1000);
				if (beginTimestamp == 0)
					beginTimestamp = endTimestamp;
				
				// Build the packet key
				tempString = packetObjPtr->PacketTypeDescription();
				memcpy(summary.protocol,tempString.c_str(),tempString.length());
				tempString = packetObjPtr->ProtocolFamilyDescription();
				memcpy(summary.protoFamily,tempString.c_str(),tempString.length());
				
				if (packetObjPtr->IsPacketType(kPacketTypeEthernet))
				{
					tempString = packetObjPtr->SourceMACAddressAsString();
					memcpy(summary.sourceMACAddr,tempString.c_str(),tempString.length());
					
					tempString = packetObjPtr->DestinationMACAddressAsString();
					memcpy(summary.destMACAddr,tempString.c_str(),tempString.length());
					
					if (packetObjPtr->IsPacketType(kPacketTypeIPv4) || packetObjPtr->IsPacketType(kPacketTypeIPv6))
					{
						tempString = packetObjPtr->SourceIPAddressAsString();
						memcpy(summary.sourceIPAddr,tempString.c_str(),tempString.length());
						
						tempString = packetObjPtr->DestinationIPAddressAsString();
						memcpy(summary.destIPAddr,tempString.c_str(),tempString.length());
						
						if (packetObjPtr->IsPacketType(kPacketTypeTCPv4) ||
							packetObjPtr->IsPacketType(kPacketTypeUDPv4) ||
							packetObjPtr->IsPacketType(kPacketTypeTCPv6) ||
							packetObjPtr->IsPacketType(kPacketTypeUDPv6))
						{
							summary.sourcePort = packetObjPtr->SourcePort();
							summary.destPort = packetObjPtr->DestinationPort();
                            summary.size = x->ActualSize();
							summary.sequenceNumber = packetObjPtr->SequenceNumber();
						}
					}
				}
				
				packetMap[summary]++;
				++packetsProcessed;
			}
		}
		
		// Now walk the summary, creating the message
		for (SummarizedPacketMap_const_iter x = packetMap.begin(); x != packetMap.end(); x++)
		{
			TMessageNode	packetNode(netTrafficNode.Append(kXMLTagPacket,"",""));
			string			serviceName;
			
			packetNode.AddAttribute(kXMLAttributePacketProtocol,x->first.protocol);
			packetNode.AddAttribute(kXMLAttributePacketProtocolFamily,x->first.protoFamily);
			packetNode.AddAttribute(kXMLAttributePacketCount,NumToString(x->second));
			packetNode.AddAttribute(kXMLAttributePacketSize,NumToString(x->first.size));
			packetNode.AddAttribute(kXMLAttributeSequenceNumber,NumToString(x->first.sequenceNumber));
			
			if (x->first.sourceMACAddr[0])
			{
				TMessageNode	sourceNode;
				TMessageNode	destNode;
				
				sourceNode = packetNode.Append(kXMLTagPacketSource,"","");
				sourceNode.AddAttribute(kXMLAttributeMACAddress,x->first.sourceMACAddr);
				
				destNode = packetNode.Append(kXMLTagPacketDestination,"","");
				destNode.AddAttribute(kXMLAttributeMACAddress,x->first.destMACAddr);
				
				if (x->first.sourceIPAddr[0])
				{
					sourceNode.AddAttribute(kXMLAttributeIPAddress,x->first.sourceIPAddr);
					destNode.AddAttribute(kXMLAttributeIPAddress,x->first.destIPAddr);
					
					if (x->first.sourcePort > 0 || x->first.destPort > 0)
					{
						sourceNode.AddAttribute(kXMLAttributePort,NumToString(x->first.sourcePort));
						destNode.AddAttribute(kXMLAttributePort,NumToString(x->first.destPort));
						serviceName = _LookupServiceName(x->first.protocol,x->first.sourcePort,x->first.destPort);
					}
				}
			}
			
			packetNode.AddAttribute(kXMLAttributeService,serviceName);
		}
		
		// Add the begin/end timestamps
		netTrafficNode.AddAttribute(kXMLAttributeTimestampStart,NumToString(beginTimestamp));
		netTrafficNode.AddAttribute(kXMLAttributeTimestampEnd,NumToString(endTimestamp));
		
		// Add the total number of bytes passing over the wire
		netTrafficNode.AddAttribute(kXMLAttributeByteCount,NumToString(packetByteCount));
	}
	
	// Add the number of packets in the list
	netTrafficNode.AddAttribute(kXMLAttributePacketCount,NumToString(packetsProcessed));
	
	// Add the number of unknown packets
	netTrafficNode.AddAttribute(kXMLAttributeUnknownCount,NumToString(packetListSize - packetsProcessed));
	
	return packetsProcessed;
}

//---------------------------------------------------------------------
// TSendInfoTask::_LookupServiceName (static protected)
//---------------------------------------------------------------------
string TSendInfoTask::_LookupServiceName (const string& protocol, unsigned int srcPort, unsigned int destPort)
{
	string					serviceName;
	ServiceMap_const_iter	foundIter;
	
	if (gServiceMapGlobalsPtr)
	{
		foundIter = gServiceMapGlobalsPtr->serviceMap.find(make_pair(srcPort,protocol));
		
		if (foundIter == gServiceMapGlobalsPtr->serviceMap.end() || foundIter->second.empty())
			foundIter = gServiceMapGlobalsPtr->serviceMap.find(make_pair(destPort,protocol));
		
		if (foundIter != gServiceMapGlobalsPtr->serviceMap.end())
			serviceName = foundIter->second;
	}
	
	return serviceName;
}

//*********************************************************************
// Sample XML Output
//
// <AGENT agent_id="symagent-network" instance="3" timestamp="1071178845158">
// 	<NET_TRAFFIC device="en0" packet_count="17" ptime_end="1071178844216" ptime_start="1071178838953" unknown_count="0">
// 		<PACKET family="IPv4" packet_count="6" proto="tcp" service="ssh">
// 			<SRC ip="205.238.131.194" mac_id="00:0A:95:6C:2C:6E" port="57843">
// 			</SRC>
// 			<DST ip="205.238.131.195" mac_id="00:A0:CC:D1:D6:4F" port="22">
// 			</DST>
// 		</PACKET>
// 		<PACKET family="IPv4" packet_count="11" proto="tcp" service="ssh">
// 			<SRC ip="205.238.131.195" mac_id="00:A0:CC:D1:D6:4F" port="22">
// 			</SRC>
// 			<DST ip="205.238.131.194" mac_id="00:0A:95:6C:2C:6E" port="57843">
// 			</DST>
// 		</PACKET>
// 	</NET_TRAFFIC>
// </AGENT>
//*********************************************************************

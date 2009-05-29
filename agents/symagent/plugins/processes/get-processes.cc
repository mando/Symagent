/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Agent to obtain system information
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					26 Nov 2003
#		Last Modified:				23 Feb 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "get-processes.h"

#include "plugin-utils.h"

#if defined(USE_PROC_FS) && USE_PROC_FS
	#include "linux-proc.h"
#else
	#if defined(USE_KVM_PROC) && USE_KVM_PROC
		#include "kvm-proc.h"
	#else
		#if defined(USE_WINDOWS) && USE_WINDOWS
			#include "windows-proc.h"
		#endif
	#endif
#endif

#include <sys/types.h>

#if HAVE_DIRENT_H
	#include <dirent.h>
	#define NAMLEN(dirent) strlen((dirent)->d_name)
#else
	#define dirent direct
	#define NAMLEN(dirent) (dirent)->d_namlen
	#if HAVE_SYS_NDIR_H
		#include <sys/ndir.h>
	#endif
	#if HAVE_SYS_DIR_H
		#include <sys/dir.h>
	#endif
	#if HAVE_NDIR_H
		#include <ndir.h>
	#endif
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define	kXMLTagProcessList							"PROCESS_LIST"
#define	kXMLTagProcess								"PROCESS"
#define	kXMLTagConnectionList						"CONNECTION_LIST"
#define	kXMLTagConnection							"CONNECTION"
#define	kXMLTagConnectionSource						"SRC"
#define	kXMLTagConnectionDestination				"DST"

#define	kXMLAttributeCount							"count"
#define	kXMLAttributeConnectionCount				"connections"
#define	kXMLAttributeProcID							"proc_id"
#define	kXMLAttributeProcPath						"path"
#define	kXMLAttributeProcSignature					"sig"
#define	kXMLAttributeProcOwnerID					"owner_id"
#define	kXMLAttributeProcGroupID					"group_id"
#define	kXMLAttributeConnectionProtocol				"proto"
#define	kXMLAttributeConnectionProtocolFamily		"family"
#define	kXMLAttributeIPAddress						"ip"
#define	kXMLAttributePort							"port"
#define	kXMLAttributeService						"service"

static const unsigned long							kReadWriteBlockSize = 4096;

//*********************************************************************
// Class TCollectProcessInfo
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TCollectProcessInfo::TCollectProcessInfo (time_t intervalInSeconds, bool rerun)
	:	Inherited(PROJECT_SHORT_NAME,intervalInSeconds,rerun)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TCollectProcessInfo::~TCollectProcessInfo ()
{
}

//---------------------------------------------------------------------
// TCollectProcessInfo::RunTask
//---------------------------------------------------------------------
void TCollectProcessInfo::RunTask ()
{
	TServerMessage		messageObj;
	TServerReply		replyObj;
	
	// Call the main method for gathering the info
	Main();
	
	// Create the XML message for the server
	_CreateXMLMessage(messageObj);
	
	#if kDebugWithoutServer
		std::cout << messageObj.AsString() << std::endl;
	#else
		// Send it to the server
		SendToServer(messageObj,replyObj);
	#endif
}

//---------------------------------------------------------------------
// TCollectProcessInfo::Main
//---------------------------------------------------------------------
void TCollectProcessInfo::Main ()
{
	TInfoCollector		collectorObj;
	
	if (fProtocolMap.empty())
		_InitProtocolList();
	
	if (fProtoFamilyMap.empty())
		_InitProtocolFamilyList();
	
	if (fServiceMap.empty())
		_InitServiceList();
	
	collectorObj.Collect(fProcessInfoMap,fNetworkConnectionMap);
}

//---------------------------------------------------------------------
// TCollectProcessInfo::_InitProtocolList (protected)
//---------------------------------------------------------------------
void TCollectProcessInfo::_InitProtocolList ()
{
	struct protoent*	protoEntryPtr = getprotoent();
	
	// Clear our internal list
	fProtocolMap.clear();
	
	while (protoEntryPtr)
	{
		fProtocolMap[protoEntryPtr->p_proto] = protoEntryPtr->p_name;
		protoEntryPtr = getprotoent();
	}
	
	endprotoent();
}

//---------------------------------------------------------------------
// TCollectProcessInfo::_InitProtocolFamilyList (protected)
//---------------------------------------------------------------------
void TCollectProcessInfo::_InitProtocolFamilyList ()
{
	// Clear our internal list
	fProtoFamilyMap.clear();
	
	// We're initializing only what we're looking for
	fProtoFamilyMap[AF_INET] = "ipv4";
	
	#if HAVE_DECL_AF_INET6
		fProtoFamilyMap[AF_INET6] = "ipv6";
	#endif
}

//---------------------------------------------------------------------
// TCollectProcessInfo::_InitServiceList (protected)
//---------------------------------------------------------------------
void TCollectProcessInfo::_InitServiceList ()
{
	struct servent*		serviceEntryPtr = getservent();
	
	// Clear our internal list
	fServiceMap.clear();
	
	while (serviceEntryPtr)
	{
		fServiceMap[make_pair(ntohs(serviceEntryPtr->s_port),string(serviceEntryPtr->s_proto))] = serviceEntryPtr->s_name;
		serviceEntryPtr = getservent();
	}
	
	endservent();
}

//---------------------------------------------------------------------
// TCollectProcessInfo::_CreateXMLMessage (protected)
//---------------------------------------------------------------------
void TCollectProcessInfo::_CreateXMLMessage (TServerMessage& parentMessage)
{
	TMessageNode		processListNode = parentMessage.Append(kXMLTagProcessList,kXMLAttributeCount,NumToString(fProcessInfoMap.size()));
	
	for (ProcessInfoMap_const_iter aProcess = fProcessInfoMap.begin(); aProcess != fProcessInfoMap.end(); aProcess++)
	{
		TMessageNode	processNode(processListNode.Append(kXMLTagProcess,"",""));
		unsigned long	netConnectCount = aProcess->second.inodeList.size();
		
		processNode.AddAttribute(kXMLAttributeProcID,NumToString(aProcess->first));
		processNode.AddAttribute(kXMLAttributeProcPath,aProcess->second.path);
		processNode.AddAttribute(kXMLAttributeProcSignature,aProcess->second.appSig);
		processNode.AddAttribute(kXMLAttributeProcOwnerID,NumToString(aProcess->second.ownerID));
	//	processNode.AddAttribute(kXMLAttributeProcGroupID,NumToString(aProcess->second.groupID));
		processNode.AddAttribute(kXMLAttributeConnectionCount,NumToString(netConnectCount));
		
		for (InodeList_const_iter aInode = aProcess->second.inodeList.begin(); aInode != aProcess->second.inodeList.end(); aInode++)
		{
			NetworkConnection	connectInfo(fNetworkConnectionMap[*aInode]);
			TMessageNode		netConnectNode(processNode.Append(kXMLTagConnection,"",""));
			TMessageNode		sourceNode(netConnectNode.Append(kXMLTagConnectionSource,"",""));
			TMessageNode		destNode(netConnectNode.Append(kXMLTagConnectionDestination,"",""));
			string				serviceName;
			
			netConnectNode.AddAttribute(kXMLAttributeConnectionProtocol,fProtocolMap[connectInfo.protoID]);
			netConnectNode.AddAttribute(kXMLAttributeConnectionProtocolFamily,fProtoFamilyMap[connectInfo.protoFamily]);
			
			sourceNode.AddAttribute(kXMLAttributeIPAddress,connectInfo.sourceAddr);
			sourceNode.AddAttribute(kXMLAttributePort,NumToString(connectInfo.sourcePort));
			
			destNode.AddAttribute(kXMLAttributeIPAddress,connectInfo.destAddr);
			destNode.AddAttribute(kXMLAttributePort,NumToString(connectInfo.destPort));
			
			serviceName = _LookupServiceName(fProtocolMap[connectInfo.protoID],connectInfo.sourcePort,connectInfo.destPort);
			
			netConnectNode.AddAttribute(kXMLAttributeService,serviceName);
		}
	}
}

//---------------------------------------------------------------------
// TCollectProcessInfo::_LookupServiceName (protected)
//---------------------------------------------------------------------
string TCollectProcessInfo::_LookupServiceName (const string& protocol, int srcPort, int destPort)
{
	string					serviceName;
	ServiceMap_const_iter	foundIter;
	
	foundIter = fServiceMap.find(make_pair(srcPort,protocol));
	if (foundIter == fServiceMap.end() || foundIter->second.empty())
		foundIter = fServiceMap.find(make_pair(destPort,protocol));
	if (foundIter != fServiceMap.end())
		serviceName = foundIter->second;
	
	return serviceName;
}

//*********************************************************************
// Sample XML Output
//
// <AGENT agent_id="symagent-processes" instance="0" timestamp="1070461945777">
//		<PROCESS_LIST count="2">
//			<PROCESS connections="0" owner_id="0" path="[keventd]" proc_id="2" sig=""></PROCESS>
//			<PROCESS connections="3" owner_id="0" path="/usr/local/sbin/sshd" proc_id="446" sig="TxmF3Uh7Za7qhS+RR5+AVklVdzo=">
//				<CONNECTION family="ipv4" proto="tcp" service="ssh">
//					<SRC ip="0.0.0.0" port="22"></SRC>
//					<DST ip="0.0.0.0" port="0"></DST>
//				</CONNECTION>
//				<CONNECTION family="ipv4" proto="tcp" service="ssh">
//					<SRC ip="0.0.0.0" port="22"></SRC>
//					<DST ip="0.0.0.0" port="0"></DST>
//				</CONNECTION>
//				<CONNECTION family="ipv6" proto="tcp" service="ssh">
//					<SRC ip="::ffff:216.141.86.18" port="22"></SRC>
//					<DST ip="::ffff:65.104.232.62" port="40463"></DST>
//				</CONNECTION>
//			</PROCESS>
//		</PROCESS_LIST>
// </AGENT>
//*********************************************************************

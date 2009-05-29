/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Agent to examine TCP network data
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					11 Jan 2004
#		Last Modified:				11 Feb 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "parser-attack-log.h"

#include "plugin-utils.h"

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define	kXMLTagNIDS									"NIDS"
#define	kXMLTagNIDSLogEntry							"ENTRY"
#define	kXMLTagLogEntryType							"TYPE"
#define	kXMLTagPacketInfo							"PACKET"
#define	kXMLTagNetworkSource						"SRC"
#define	kXMLTagNetworkDestination					"DST"

#define	kXMLAttributeFile							"file"
#define	kXMLAttributePlatform						"platform"
#define	kXMLAttributeLogEntryCount					"count"
#define	kXMLAttributeSnortTimestamp					"time"
#define	kXMLAttributePriority						"priority"
#define	kXMLAttributeSnortID						"id"
#define	kXMLAttributeSnortDescription				"desc"
#define	kXMLAttributeSnortClassification			"class"
#define	kXMLAttributeNetworkProtocol				"proto"
#define	kXMLAttributeDevice							"device"
#define	kXMLAttributeIPAddress						"ip"
#define	kXMLAttributePort							"port"
#define	kXMLAttributeValueSnort						"snort"

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
static TNotices										gNoticesObj;

//*********************************************************************
// Class TParserAttackLog
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TParserAttackLog::TParserAttackLog (const string& logFilePath,
									const string& dataToParse,
									const string& outputFormat)
	:	Inherited(PROJECT_SHORT_NAME,0,false),
		fLogFilePath(logFilePath),
		fDataToParse(dataToParse),
		fOutputFormat(outputFormat)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TParserAttackLog::~TParserAttackLog ()
{
}

//---------------------------------------------------------------------
// TParserAttackLog::RunTask
//---------------------------------------------------------------------
void TParserAttackLog::RunTask ()
{
	if (IsConnectedToServer())
	{
		TServerMessage		messageObj;
		TServerReply		replyObj;
		NoticeCode			noticeCodes = kNoticeNone;
		
		if ((GetDynamicDebuggingFlags() & kDynDebugLogServerCommunication) == kDynDebugLogServerCommunication)
			WriteToMessagesLog("Starting Snort Attack Log (parse and send) Task");
		
		Main(messageObj,noticeCodes);
		
		if (noticeCodes != kNoticeNone)
			gNoticesObj.AddNotice(fLogFilePath,noticeCodes);
		
		// Send it to the server
		SendToServer(messageObj,replyObj);
		
		if ((GetDynamicDebuggingFlags() & kDynDebugLogServerCommunication) == kDynDebugLogServerCommunication)
			WriteToMessagesLog("Ending Snort Attack Log (parse and send) Task");
	}
}

//---------------------------------------------------------------------
// TParserAttackLog::Main
//---------------------------------------------------------------------
void TParserAttackLog::Main (TServerMessage& messageObj, NoticeCode& noticeCodes)
{
	StdStringList	entryList;
	TMessageNode	snortNode;
	
	SplitStdString('\n',fDataToParse,entryList,false);
	
	snortNode = messageObj.Append(kXMLTagNIDS,kXMLAttributeLogEntryCount,NumToString(entryList.size()));
	snortNode.AddAttribute(kXMLAttributeFile,fLogFilePath);
	snortNode.AddAttribute(kXMLAttributePlatform,kXMLAttributeValueSnort);
	
	for (StdStringList_const_iter oneLine = entryList.begin(); oneLine != entryList.end(); oneLine++)
	{
		SnortIncidentFieldMap	fieldMap;
		
		// Convert the log line into a snort field map
		_ParseOneLine(*oneLine,fieldMap,noticeCodes);
		
		// Convert the gathered information into an XML entry
		_PopulateXMLMessage(fieldMap,snortNode,fOutputFormat);
	}
}

//---------------------------------------------------------------------
// TParserAttackLog::_ParseOneLine (static protected)
//---------------------------------------------------------------------
void TParserAttackLog::_ParseOneLine (const string& logLine, SnortIncidentFieldMap& fieldMap, NoticeCode& noticeCodes)
{
	StdStringList		fieldList;
	StdStringList		tempStringList;
	
	// Clear the argument we'll be modifying
	fieldMap.clear();
	
	// Split the log line into fields, ignoring empties
	SplitStdString("[**]",logLine,fieldList,false);
	
	// Insert common entries into the field map
	if (fieldList.size() > 0)
	{
		// Snort timestamp
		// Store this as converted to our normal timestamp format
		fieldMap[kSnortIncidentTimestamp] = NumToString(static_cast<unsigned long long>(_SnortTimestampToNum(fieldList[0],noticeCodes) * 1000));
		
		if (fieldList.size() > 1)
		{
			if (fieldList[1].find("snort_decoder") == string::npos)
			{
				// Field format:  "[<IncidentID>] <<Interface>> <IncidentDescription>"
				// IncididentID format:  "[x:x:x]
				// Interface format:  <Name> -- optional
				// IncidentDescription format:  remainder of fields, spaces included
				SplitStdString(' ',fieldList[1],tempStringList,false);
				if (tempStringList.size() >= 2)
				{
					_RemoveEnclosingChars(tempStringList[0],'[',']');
					fieldMap[kSnortIncidentID] = tempStringList[0];
					tempStringList.erase(tempStringList.begin());
					if (tempStringList.front()[0] == '<')
					{
						// Extract network interface
						_RemoveEnclosingChars(tempStringList[0],'<','>');
						fieldMap[kSnortIncidentInterface] = tempStringList[0];
						tempStringList.erase(tempStringList.begin());
					}
					else
					{
						// We don't have device information
						noticeCodes = static_cast<NoticeCode>(static_cast<int>(noticeCodes) | kNoticeMissingDevice);
					}
					fieldMap[kSnortIncidentDescription] = JoinStdStringList(' ',tempStringList);
				}
				else
				{
					// Stuff it all into the description
					fieldMap[kSnortIncidentDescription] = fieldList[1];
				}
				
				if (fieldList.size() > 2)
				{
					// Field format:  "[<Classification>] [<Priority>] {<Protocol>} <Source> -> <Destination>"
					// Classification format:	"Classification: <Description>" -- optional
					// Priority format:	"Priority: <value>" -- optional
					// Source format: "<IPAddress>:<Port>" -- port can be optional
					// Destination format: "<IPAddress>:<Port>" -- port can be optional
					
					// First, let's break the string on the protocol.  Items before the
					// protocol are optional and need to be handled differently.
					string			descriptions;
					string			packetInfo;
					unsigned long	pos = 0;
					
					SplitStdString('{',fieldList[2],tempStringList,false);
					
					if (!tempStringList.empty())
					{
						if (tempStringList.size() == 1)
						{
							packetInfo += "{" + tempStringList[0];
						}
						else
						{
							descriptions = tempStringList[0];
							tempStringList.erase(tempStringList.begin());
							packetInfo += "{" + JoinStdStringList(' ',tempStringList);
						}
					}
					
					// Walk through the description string, finding bracketed items
					pos = descriptions.find('[');
					while (pos != string::npos)
					{
						unsigned long	endPos = descriptions.find(']',pos);
						string			parameter;
						const string	kClassificationTag("Classification: ");
						const string	kPriorityTag("Priority: ");
						
						if (endPos != string::npos)
						{
							++endPos;
							parameter = descriptions.substr(pos,endPos-pos);
						}
						else
							parameter = descriptions.substr(pos,descriptions.length() - pos);
						
						_RemoveEnclosingChars(parameter,'[',']');
						Trim(parameter);
						
						// Now look for our possible values
						if (parameter.find(kClassificationTag) == 0)
						{
							unsigned long	valuePos = kClassificationTag.length();
							string			value(parameter.substr(valuePos,parameter.length()-valuePos));
							
							Trim(value);
							if (!value.empty())
								fieldMap[kSnortIncidentClassification] = value;
						}
						else if (parameter.find(kPriorityTag) == 0)
						{
							unsigned long	valuePos = kPriorityTag.length();
							string			value(parameter.substr(valuePos,parameter.length()-valuePos));
							
							Trim(value);
							if (!value.empty())
								fieldMap[kSnortIncidentPriority] = value;
						}
						
						if (endPos < descriptions.length())
							pos = descriptions.find('[',endPos);
						else
							break;
					}
					
					// Now break up the packet info stuff -- should be four items
					SplitStdString(' ',packetInfo,tempStringList,false);
					if (tempStringList.size() == 4)
					{
						string	protocol(tempStringList[0]);
						string	sourceIP(tempStringList[1]);
						string	sourcePort;
						string	destinationIP(tempStringList[3]);
						string	destinationPort;
						
						// See if the source and destination need their ports parsed out
						SplitStdString(':',sourceIP,tempStringList,false);
						if (tempStringList.size() > 1)
						{
							sourceIP = tempStringList[0];
							sourcePort = tempStringList[1];
						}
						SplitStdString(':',destinationIP,tempStringList,false);
						if (tempStringList.size() > 1)
						{
							destinationIP = tempStringList[0];
							destinationPort = tempStringList[1];
						}
						
						_RemoveEnclosingChars(protocol,'{','}');
						Trim(protocol);
						if (!protocol.empty())
						{
							MakeLowerCase(protocol);
							fieldMap[kSnortIncidentProtocol] = protocol;
						}
						
						Trim(sourceIP);
						if (!sourceIP.empty())
							fieldMap[kSnortIncidentSourceIPAddress] = sourceIP;
						
						Trim(sourcePort);
						if (!sourcePort.empty())
							fieldMap[kSnortIncidentSourcePort] = sourcePort;
						
						Trim(destinationIP);
						if (!destinationIP.empty())
							fieldMap[kSnortIncidentDestinationIPAddress] = destinationIP;
						
						Trim(destinationPort);
						if (!destinationPort.empty())
							fieldMap[kSnortIncidentDestinationPort] = destinationPort;
					}
				}
			}
		}
	}
}

//---------------------------------------------------------------------
// TParserAttackLog::_RemoveEnclosingChars (static protected)
//---------------------------------------------------------------------
void TParserAttackLog::_RemoveEnclosingChars (string& s, char beginningChar, char endingChar)
{
	while (!s.empty() && s[s.length()-1] == endingChar)
		s.erase(s.length()-1,1);
	while (!s.empty() && s[0] == beginningChar)
		s.erase(0,1);
}

//---------------------------------------------------------------------
// TParserAttackLog::_WithRemovedChars (static protected)
//---------------------------------------------------------------------
string TParserAttackLog::_WithRemovedChars (const string& s, const string& charBag)
{
	string	tempString;
	
	for (unsigned long x = 0; x < s.length(); x++)
	{
		if (charBag.find(s[x]) == string::npos)
			tempString.push_back(s[x]);
	}
	
	return tempString;
}

//---------------------------------------------------------------------
// TParserAttackLog::_SnortTimestampToNum (static protected)
//---------------------------------------------------------------------
double TParserAttackLog::_SnortTimestampToNum (const string& snortTimestamp, NoticeCode& noticeCode)
{
	double		timestampNum = 0.0;
	time_t		timeInSec = time(NULL);
	struct tm	timeInfo;
	
	// First, get the current time in order to get the timezone stuff correct
	#if HAVE_LOCALTIME_R
		localtime_r(&timeInSec,&timeInfo);
	#else
		memcpy(&timeInfo,localtime(&timeInSec),sizeof(timeInfo));
	#endif
	
	// Stuff the timeInfo struct with data pulled from the snort timestamp
	// Note that the timestamp can be in one of two formats:
	// 		MM/DD-HH:MM:SS.SSSSSS
	// 		0  0  0  0  1 1
	// 		0  3  6  9  2 4
	// or:
	// 		MM/DD/YY-HH:MM:SS.SSSSSS
	// 		0  0  0  0  1  1 1
	// 		0  3  6  9  2  5 7
	// Also, note that snort can report the timestamp in UTC time rather than
	// local time.  Unfortunately, there is no external indication of this while
	// examining the logfiles.  Here, we assume that the timestamp is in local time.
	
	if (snortTimestamp[5] == '-')
	{
		// First format for the timestamp (missing the year)
		
		// Month, 0-11
		timeInfo.tm_mon = static_cast<int>(StringToNum(snortTimestamp.substr(0,2)) - 1);
		
		// Day, 1-31
		timeInfo.tm_mday = static_cast<int>(StringToNum(snortTimestamp.substr(3,2)));
		
		// Hour, 0-23
		timeInfo.tm_hour = static_cast<int>(StringToNum(snortTimestamp.substr(6,2)));
		
		// Minute, 0-59
		timeInfo.tm_min = static_cast<int>(StringToNum(snortTimestamp.substr(9,2)));
		
		// Seconds, 0-59 (integer portion only)
		timeInfo.tm_sec = static_cast<int>(StringToNum(snortTimestamp.substr(12,2)));
		
		// Convert this struct back to a time_t value
		timeInSec = mktime(&timeInfo);
		
		// Tack on the fractional seconds
		timestampNum = timeInSec + StringToNum(snortTimestamp.substr(14));
		
		// Tell our caller that we didn't have the year
		noticeCode = static_cast<NoticeCode>(static_cast<int>(noticeCode) | kNoticeMissingYear);
	}
	else
	{
		// Second format for the timestamp
		
		// Month, 0-11
		timeInfo.tm_mon = static_cast<int>(StringToNum(snortTimestamp.substr(0,2)) - 1);
		
		// Day, 1-31
		timeInfo.tm_mday = static_cast<int>(StringToNum(snortTimestamp.substr(3,2)));
		
		// Year - 1900
		timeInfo.tm_year = static_cast<int>(StringToNum(snortTimestamp.substr(6,2)));
		if (timeInfo.tm_year < 50)
		{
			// Assume it's later than 2000
			timeInfo.tm_year += 100;
		}
		
		// Hour, 0-23
		timeInfo.tm_hour = static_cast<int>(StringToNum(snortTimestamp.substr(9,2)));
		
		// Minute, 0-59
		timeInfo.tm_min = static_cast<int>(StringToNum(snortTimestamp.substr(12,2)));
		
		// Seconds, 0-59 (integer portion only)
		timeInfo.tm_sec = static_cast<int>(StringToNum(snortTimestamp.substr(15,2)));
		
		// Convert this struct back to a time_t value
		timeInSec = mktime(&timeInfo);
		
		// Tack on the fractional seconds
		timestampNum = timeInSec + StringToNum(snortTimestamp.substr(17));
	}
	
	return timestampNum;
}

//---------------------------------------------------------------------
// TParserAttackLog::_PopulateXMLMessage (static protected)
//---------------------------------------------------------------------
void TParserAttackLog::_PopulateXMLMessage (SnortIncidentFieldMap& fieldMap,
											TMessageNode& parentNode,
											const string& outputFormat)
{
	TMessageNode		entryNode(parentNode.Append(kXMLTagNIDSLogEntry,"",""));
	TMessageNode		typeNode(entryNode.Append(kXMLTagLogEntryType,"",""));
	TMessageNode		netNode(entryNode.Append(kXMLTagPacketInfo,"",""));
	TMessageNode		sourceNode(netNode.Append(kXMLTagNetworkSource,"",""));
	TMessageNode		destNode(netNode.Append(kXMLTagNetworkDestination,"",""));
	
	entryNode.AddAttribute(kXMLAttributeSnortTimestamp,fieldMap[kSnortIncidentTimestamp]);
	entryNode.AddAttribute(kXMLAttributePriority,fieldMap[kSnortIncidentPriority]);
	
	typeNode.AddAttribute(kXMLAttributeSnortID,fieldMap[kSnortIncidentID]);
	
	netNode.AddAttribute(kXMLAttributeNetworkProtocol,fieldMap[kSnortIncidentProtocol]);
	netNode.AddAttribute(kXMLAttributeDevice,fieldMap[kSnortIncidentInterface]);
	
	sourceNode.AddAttribute(kXMLAttributeIPAddress,fieldMap[kSnortIncidentSourceIPAddress]);
	sourceNode.AddAttribute(kXMLAttributePort,fieldMap[kSnortIncidentSourcePort]);
	
	destNode.AddAttribute(kXMLAttributeIPAddress,fieldMap[kSnortIncidentDestinationIPAddress]);
	destNode.AddAttribute(kXMLAttributePort,fieldMap[kSnortIncidentDestinationPort]);
	
	if (outputFormat != kMessageAttributeValueCompact)
	{
		typeNode.AddAttribute(kXMLAttributeSnortDescription,fieldMap[kSnortIncidentDescription]);
		typeNode.AddAttribute(kXMLAttributeSnortClassification,fieldMap[kSnortIncidentClassification]);
	}
}

//*********************************************************************
// Global Functions
//*********************************************************************

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
#		Last Modified:				22 Apr 2004
#		
#######################################################################
*/

#if !defined(PARSER_ATTACK_LOG)
#define PARSER_ATTACK_LOG

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"

//---------------------------------------------------------------------
// Import namespace symbols
//---------------------------------------------------------------------
using symbiot::TTaskBase;
using symbiot::TServerMessage;
using symbiot::TMessageNode;

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TNotices;
class TParserAttackLog;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef	enum
			{
				kSnortIncidentTimestamp,
				kSnortIncidentID,
				kSnortIncidentInterface,
				kSnortIncidentDescription,
				kSnortIncidentClassification,
				kSnortIncidentPriority,
				kSnortIncidentProtocol,
				kSnortIncidentSourceIPAddress,
				kSnortIncidentSourcePort,
				kSnortIncidentDestinationIPAddress,
				kSnortIncidentDestinationPort
			}	SnortIncidentFieldCode;

typedef	map<SnortIncidentFieldCode,string>				SnortIncidentFieldMap;
typedef	SnortIncidentFieldMap::iterator					SnortIncidentFieldMap_iter;
typedef	SnortIncidentFieldMap::const_iterator			SnortIncidentFieldMap_const_iter;

typedef	enum
		{
			kNoticeNone = 0,
			kNoticeMissingYear = 1,
			kNoticeMissingDevice = 2
		}	NoticeCode;

//---------------------------------------------------------------------
// Class TNotices
//---------------------------------------------------------------------
class TNotices
{
	private:
		
		typedef	map<string,NoticeCode>					NoticeMap;
		typedef NoticeMap::iterator						NoticeMap_iter;
		typedef	NoticeMap::const_iterator				NoticeMap_const_iter;
	
	public:
		
		TNotices () {}
		~TNotices () {}
		
		void AddNotice (const string& logPath, NoticeCode code)
			{
				if (code != kNoticeNone)
				{
					TLockedPthreadMutexObj		lock(fMutex);
					NoticeCode					existingCode = fNoticeMap[logPath];
					
					if ((code & kNoticeMissingYear) == kNoticeMissingYear &&
						(existingCode & kNoticeMissingYear) != kNoticeMissingYear)
					{
						// Tell the server we're missing the year from the snort log entries
						string		advisory;
						
						existingCode = static_cast<NoticeCode>(static_cast<int>(existingCode) | kNoticeMissingYear);
						
						advisory += "Warning: Snort log '" + logPath + "' missing year in timestamps";
						WriteToErrorLog(advisory);
						AdviseServer(advisory,0);
					}
					
					if ((code & kNoticeMissingDevice) == kNoticeMissingDevice &&
						(existingCode & kNoticeMissingDevice) != kNoticeMissingDevice)
					{
						// Tell the server we're missing the device from the snort log entries
						string		advisory;
						
						existingCode = static_cast<NoticeCode>(static_cast<int>(existingCode) | kNoticeMissingDevice);
						
						advisory += "Warning: Snort log '" + logPath + "' missing network device names";
						WriteToErrorLog(advisory);
						AdviseServer(advisory,0);
					}
					
					fNoticeMap[logPath] = existingCode;
				}
			}
	
	private:
		
		NoticeMap										fNoticeMap;
		TPthreadMutexObj								fMutex;
		
};

//---------------------------------------------------------------------
// Class TParserAttackLog
//---------------------------------------------------------------------
class TParserAttackLog : public TTaskBase
{
	private:
		
		typedef	TTaskBase						Inherited;
	
	public:
		
		TParserAttackLog (const string& logFilePath,
						  const string& dataToParse,
						  const string& outputFormat);
			// Constructor
	
	private:
		
		TParserAttackLog (const TParserAttackLog& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TParserAttackLog ();
			// Destructor
		
		virtual void RunTask ();
			// Thread entry point for the task.  Really just a wrapper for Main().
		
		virtual void Main (TServerMessage& messageObj, NoticeCode& noticeCodes);
			// Parses data from a snort attack file and convert it into an XML
			// message for the server.
	
	protected:
		
		static void _ParseOneLine (const string& logLine, SnortIncidentFieldMap& fieldMap, NoticeCode& noticeCodes);
			// Parses the given logLine into fields and then into
			// a snort field map.  fieldMap is destructively modified
			// to contain the results.
		
		static void _RemoveEnclosingChars (string& s, char beginningChar, char endingChar);
			// Removes characters from beginning and end of the given
			// string, destructively modifying it.
		
		static string _WithRemovedChars (const string& s, const string& charBag);
			// Removes characters found in charBag from the string s, returning
			// the results.
		
		static double _SnortTimestampToNum (const string& snortTimestamp, NoticeCode& noticeCode);
			// Converts a snort timestamp in the form MM/DD-HH:MM:SS.SSSSSS
			// to a double, like CurrentMilliseconds().
		
		static void _PopulateXMLMessage (SnortIncidentFieldMap& fieldMap,
										 TMessageNode& parentNode,
										 const string& outputFormat);
			// Creates a message suitable for the server out of the given
			// fieldMap data, destructively modifying messageObj to contain
			// that message.
	
	protected:
		
		string											fLogFilePath;
		string											fDataToParse;
		string											fOutputFormat;
};

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

//---------------------------------------------------------------------
#endif // PARSER_ATTACK_LOG

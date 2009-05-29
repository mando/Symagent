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
#		Last Modified:				04 Jan 2004
#		
#######################################################################
*/

#if !defined(GET_PROCESSES)
#define GET_PROCESSES

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"
#include "common-info.h"

//---------------------------------------------------------------------
// Import namespace symbols
//---------------------------------------------------------------------
using symbiot::TTaskBase;
using symbiot::TServerMessage;
using symbiot::TMessageNode;

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TCollectProcessInfo;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Class TCollectProcessInfo
//---------------------------------------------------------------------
class TCollectProcessInfo : public TTaskBase
{
	private:
		
		typedef	TTaskBase							Inherited;
	
	public:
		
		TCollectProcessInfo (time_t intervalInSeconds, bool rerun);
			// Constructor
	
	private:
		
		TCollectProcessInfo (const TCollectProcessInfo& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TCollectProcessInfo ();
			// Destructor
		
		virtual void RunTask ();
			// Thread entry point for the task.  Really just a wrapper for Main().
		
		virtual void Main ();
			// Parses data from a snort attack file and convert it into an XML
			// message for the server.
	
	protected:
		
		virtual void _InitProtocolList ();
			// Initializes the fProtocolMap internal slot.
		
		virtual void _InitProtocolFamilyList ();
			// Initializes the fProtoFamilyMap internal slot.
		
		virtual void _InitServiceList ();
			// Initialize the fServiceMap internal slot.
		
		virtual void _CreateXMLMessage (TServerMessage& parentMessage);
			// Creates the outbound server message using the information found
			// in the internal slots.  The message is inserted into the argument,
			// modifying it.
		
		virtual string _LookupServiceName (const string& protocol, int srcPort, int destPort);
			// Given the source and destination ports of a communication,
			// this method returns the well-known service name for that
			// type of connection.
	
	protected:
		
		ProtocolMap									fProtocolMap;
		ProtoFamilyMap								fProtoFamilyMap;
		ServiceMap									fServiceMap;
		NetworkConnectionMap						fNetworkConnectionMap;
		ProcessInfoMap								fProcessInfoMap;
};

//---------------------------------------------------------------------
#endif // GET_PROCESSES

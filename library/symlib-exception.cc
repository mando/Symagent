/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Symbiot Master Library
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					24 Oct 2003
#		Last Modified:				11 Feb 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-exception.h"

#include "symlib-config.h"
#include "symlib-utils.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TSymLibErrorObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSymLibErrorObj::TSymLibErrorObj (long errNum)
	:	fError(errNum),
		fIsLogged(false),
		fCodeAdded(false)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSymLibErrorObj::TSymLibErrorObj (long errNum, const std::string& description)
	:	fError(errNum),
		fDescription(description),
		fIsLogged(false),
		fCodeAdded(false)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSymLibErrorObj::TSymLibErrorObj (const TSymLibErrorObj& obj)
	:	fError(obj.fError),
		fDescription(obj.fDescription),
		fIsLogged(obj.fIsLogged),
		fCodeAdded(obj.fCodeAdded)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSymLibErrorObj::~TSymLibErrorObj ()
{
}

//---------------------------------------------------------------------
// TSymLibErrorObj::GetDescription
//---------------------------------------------------------------------
std::string TSymLibErrorObj::GetDescription ()
{
	if (fDescription.empty())
		MakeDescription();
	
	if (!fCodeAdded)
	{
		fDescription += " - code " + NumToString(fError);
		fCodeAdded = true;
	}
	
	return fDescription;
}

//---------------------------------------------------------------------
// TSymLibErrorObj::MakeDescription (protected)
//---------------------------------------------------------------------
void TSymLibErrorObj::MakeDescription ()
{
	switch (fError)
	{
		case kErrorLocalPreferenceNotFound:
			fDescription = "libsymbiot: Local preferences file not found.";
			break;
		
		case kErrorLocalPreferenceCorrupt:
			fDescription = "libsymbiot: Local preferences file corrupt.";
			break;
		
		case kErrorLocalPreferenceVersionMismatch:
			fDescription = "libsymbiot: Local preference version mismatch.";
			break;
		
		case kErrorLocalPreferenceNotLoaded:
			fDescription = "libsymbiot: Local preferences not loaded.";
			break;
		
		case kErrorLocalPreferencesPermissionsBad:
			fDescription = "libsymbiot: Permissions on local preferences file incorrect.";
			break;
		
		case kErrorCertificateFilePermissionsBad:
			fDescription = "libsymbiot: Permissions on certificate file incorrect.";
			break;
		
		case kErrorNotConnectedToServer:
			fDescription = "libsymbiot: Not connected to server.";
			break;
		
		case kErrorBadServerResponse:
			fDescription = "libsymbiot: The server replied with an inappropriate HTTP response code.";
			break;
		
		case kErrorAgentNotProvisioned:
			fDescription = "Agent is not provisioned to operate.";
			break;
		
		case kErrorDBUnavailable:
			fDescription = "Server appliance database is unavailable.";
			break;
		
		case kErrorServerUnavailable:
			fDescription = "Server appliance is unavailable.";
			break;
		
		case kErrorServerCommunicationTimeout:
			fDescription = "Timeout while communicating with server.";
			break;
		
		default:
			fDescription = "libsymbiot: Unknown error.";
			break;
	}
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

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

#if !defined(SYMLIB_EXCEPTION)
#define SYMLIB_EXCEPTION

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include <string>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TSymLibErrorObj;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define		kErrorLocalPreferenceNotFound				-23101
#define		kErrorLocalPreferenceCorrupt				-23102
#define		kErrorLocalPreferenceVersionMismatch		-23103
#define		kErrorLocalPreferenceNotLoaded				-23104
#define		kErrorLocalPreferencesPermissionsBad		-23105

#define		kErrorCertificateFilePermissionsBad			-23151

#define		kErrorNotConnectedToServer					-23201
#define		kErrorBadServerResponse						-23202
#define		kErrorAgentNotProvisioned					-23203
#define		kErrorDBUnavailable							-23204
#define		kErrorServerUnavailable						-23205
#define		kErrorServerCommunicationTimeout			-23206

//---------------------------------------------------------------------
// Class TSymLibErrorObj
//---------------------------------------------------------------------
class TSymLibErrorObj
{
	public:
		
		TSymLibErrorObj (long errNum);
			// Constructor
		
		TSymLibErrorObj (long errNum, const std::string& description);
			// Constructor
		
		TSymLibErrorObj (const TSymLibErrorObj& obj);
			// Constructor
		
		virtual ~TSymLibErrorObj ();
			// Constructor
		
		virtual std::string GetDescription ();
			// Returns a description of the error.  If no
			// description was supplied with the instantiation of
			// the object then this method will call MakeDescription()
			// in the hopes that that method can supply some kind
			// of generic description.
		
		// Simple Accessors
		
		inline long GetError () const
			{ return fError; }
		
		inline void MarkAsLogged ()
			{ fIsLogged = true; }
		
		inline bool IsLogged () const
			{ return fIsLogged; }
	
	protected:
		
		virtual void MakeDescription ();
	
	protected:
		
		long					fError;
		std::string				fDescription;
		bool					fIsLogged;
		bool					fCodeAdded;
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

#endif // SYMLIB_EXCEPTION

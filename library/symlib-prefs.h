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
#		Created:					28 Aug 2003
#		Last Modified:				16 Feb 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_PREFS)
#define SYMLIB_PREFS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-utils.h"

#include "symlib-xml.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TLibSymPrefs;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define	kTagPrefCertDir								"certificates_dir"
#define	kTagPrefLogging								"logging"
#define	kTagPrefLogDir									"directory"
#define	kTagPrefLogUser									"user"
#define	kTagPrefLogGroup								"group"

#define	kTagPrefServer								"server"
#define	kTagPrefHost									"host"
#define	kTagPrefPort									"port"
#define	kTagPrefSSLPort									"ssl_port"

#define	kTagPrefCompression							"compression"

//---------------------------------------------------------------------
// Class TLibSymPrefs
//---------------------------------------------------------------------
class TLibSymPrefs
{
	public:
		
		TLibSymPrefs ();
			// Constructor
	
	private:
		
		TLibSymPrefs (const TLibSymPrefs& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TLibSymPrefs ();
			// Destructor
		
		virtual void LoadLocalConfFile ();
			// Loads and parses the local XML-formatted configuration file.
		
		virtual const TXMLNodeObj* AppendPrefNodePtr (const std::string& tag,
													  const std::string& data = "");
			// еее
		
		virtual const TXMLNodeObj* AppendPrefNodePtr (const TXMLNodeObj* nodeObjPtr);
			// еее
		
		virtual const TXMLNodeObj* GetPrefNodePtr (const std::string& tag,
												   const std::string& attribute = "",
												   const std::string& attributeValue = "") const;
			// еее
		
		virtual std::string GetPrefData (const std::string& tag,
										 const std::string& attribute = "",
										 const std::string& attributeValue = "") const;
			// еее
		
		virtual const TXMLNodeObj* GetNodePtr (const TXMLNodeObj* parentNodePtr,
											   const std::string& tag,
											   const std::string& attribute = "",
											   const std::string& attributeValue = "") const;
			// еее
		
		virtual std::string GetNodePtrData (const TXMLNodeObj* parentNodePtr,
											const std::string& tag,
											const std::string& attribute = "",
											const std::string& attributeValue = "") const;
		
		// ----------------------------------
		// Accessors
		// ----------------------------------
		
		inline bool LocalPrefsLoaded () const
			{ return (fPrefLocalHomeNodePtr != NULL); }
		
		inline TXMLNodeObj* RemotePrefsNodePtr () const
			{ return fPrefRemoteHomeNodePtr; }
	
	protected:
		
		virtual std::string _FindLocalConfFile () const;
			// Returns a full path to the local configuration file.
		
		virtual void _ValidateLocalConf ();
			// Scans the parsed local configuration and determines
			// whether it appears valid or not.  An exception is thrown
			// if an error is found.
	
	protected:
		
		TXMLNodeObj								fPrefRootNode;
		const TXMLNodeObj*						fPrefLocalHomeNodePtr;
		TXMLNodeObj*							fPrefRemoteHomeNodePtr;
};

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

TLibSymPrefs* GetPrefsPtr ();
	// Returns a pointer to the global preferences object.

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

#endif // SYMLIB_PREFS

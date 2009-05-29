/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Agent to obtain system information from Windows via Cygwin
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					02 Jan 2004
#		Last Modified:				04 Jan 2004
#		
#######################################################################
*/

#if !defined(WINDOWS_PROC)
#define WINDOWS_PROC

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "common-info.h"

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TInfoCollector;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Class TInfoCollector
//---------------------------------------------------------------------
class TInfoCollector
{
	public:
		
		TInfoCollector ();
			// Constructor
		
		TInfoCollector (const TInfoCollector& obj);
			// Copy constructor
		
		virtual ~TInfoCollector ();
			// Destructor
		
		virtual void Collect (ProcessInfoMap& procInfoMap, NetworkConnectionMap& netConnMap);
			// Collects the information and destructively modifies the arguments
			// to contain it.
};

//---------------------------------------------------------------------
#endif // WINDOWS_PROC

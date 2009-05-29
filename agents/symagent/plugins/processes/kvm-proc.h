/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Agent to obtain system information from BSD
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					08 Dec 2003
#		Last Modified:				25 Feb 2004
#		
#######################################################################
*/

#if !defined(KINFO_PROC)
#define KINFO_PROC

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"
#include "common-info.h"

#include <sys/types.h>
#if HAVE_SYS_PARAM_H
	#include <sys/param.h>
#endif
#if HAVE_SYS_UCRED_H
	#ifndef _WANT_UCRED
		#define _WANT_UCRED
		#include <sys/ucred.h>
		#undef _WANT_UCRED
	#else
		#include <sys/ucred.h>
	#endif
#endif
#if HAVE_SYS_USER_H
	#include <sys/user.h>
#endif
#include <kvm.h>

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
	
	protected:
		
		template <class T>
		ssize_t _KVMRead (kvm_t* handle, T address, void* buffer, size_t bufferSize)
			{
				ssize_t		bytesRead = kvm_read(handle,reinterpret_cast<unsigned long>(address),buffer,bufferSize);
				
				if (bytesRead == 0)
					throw TSymLibErrorObj(kErrorKVMReadFailed,kvm_geterr(handle));
				
				return bytesRead;
			}
		
		template <class T1, class T2>
		ssize_t _KVMRead (kvm_t* handle, T1 address, T2& buffer)
			{
				ssize_t		bytesRead = 0;
				
				memset(&buffer,0,sizeof(buffer));
				bytesRead = kvm_read(handle,reinterpret_cast<unsigned long>(address),&buffer,sizeof(buffer));
				if (bytesRead == 0)
					throw TSymLibErrorObj(kErrorKVMReadFailed,kvm_geterr(handle));
				
				return bytesRead;
			}
		
		static string _IPAddressAsString (const struct in_addr& addr);
			// Converts the given IPv4 address structure to a string and returns it.
		
		#if HAVE_DECL_AF_INET6
			static string _IPAddressAsString (const struct in6_addr& addr);
				// Converts the given IPv6 address structure to a string and returns it.
		#endif
};

//---------------------------------------------------------------------
#endif // KINFO_PROC

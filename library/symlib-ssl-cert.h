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
#		Adapted from a library authored by BTI and available
#		from http://www.bti.net
#		
#		Created:					29 Oct 2003
#		Last Modified:				29 Oct 2003
#		
#######################################################################
*/

#if !defined(SYMLIB_SSL_CERT)
#define SYMLIB_SSL_CERT

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-ssl-util.h"

#include "symlib-ssl-digest.h"
#include "symlib-ssl-pkey.h"

#include "symlib-time.h"

#include "openssl/x509v3.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TX509Obj;

//---------------------------------------------------------------------
// Class TX509Obj
//---------------------------------------------------------------------
class TX509Obj
{
	public:
		
		TX509Obj ();
			// Constructor
		
		TX509Obj (X509* x509Ptr);
			// Constructor
		
		TX509Obj (const TX509Obj& obj);
			// Copy constructor
			// OpenSSL functions:  X509_dup
		
		virtual ~TX509Obj ();
			// Destructor
		
		virtual void Initialize ();
			// Initializes our internal structures.  Destroys any existing
			// certificate information in the process.
			// OpenSSL functions:  X509_new
		
		virtual unsigned long Version () const;
			// Returns the version number within the current certificate.
			// OpenSSL functions:  X509_get_version
		
		virtual void SetVersion (unsigned long version);
			// Sets the version number within the certificate.
			// OpenSSL functions:  X509_set_version
		
		virtual TPKeyObj PublicKey ();
			// Returns a copy of the public key associated with the
			// current certificate.
			// OpenSSL functions:  X509_get_pubkey
		
		virtual void SetPublicKey (TPKeyObj& publicKeyObj);
			// Associates the given public key object with the certificate.
			// OpenSSL functions:  X509_set_pubkey
		
		inline std::string PublicKeyAlgorithmName ()
			{ return PublicKeyAlgorithmLongName(); }
		
		virtual std::string PublicKeyAlgorithmShortName ();
			// Returns the short name of the public key algorithm associated
			// with the current certificate.
			// OpenSSL functions:  OBJ_nid2sn, OBJ_obj2nid
		
		virtual std::string PublicKeyAlgorithmLongName ();
			// Returns the long name of the public key algorithm associated
			// with the current certificate.
			// OpenSSL functions:  OBJ_nid2ln, OBJ_obj2nid
		
		inline std::string SignatureAlgorithmName ()
			{ return SignatureAlgorithmLongName(); }
		
		virtual std::string SignatureAlgorithmShortName ();
			// Returns the short name of the signing algorithm associated
			// with the current certificate.
			// OpenSSL functions:  OBJ_nid2sn, OBJ_obj2nid
		
		virtual std::string SignatureAlgorithmLongName ();
			// Returns the long name of the signing algorithm associated
			// with the current certificate.
			// OpenSSL functions:  OBJ_nid2ln, OBJ_obj2nid
		
		virtual int SignatureType () const;
			// Returns the signature type.
			// OpenSSL functions:  X509_get_signature_type
		
		virtual TBigNumBuffer SerialNumber () const;
			// Returns the serial number within the current certificate.
			// OpenSSL functions:  X509_get_serialNumber, ASN1_INTEGER_to_BN
		
		virtual void SetSerialNumber (TBigNumBuffer serialNumber);
			// Sets the serial number within the certificate.
			// OpenSSL functions:  X509_set_serialNumber, X509_get_serialNumber,
			// BN_to_ASN1_INTEGER
		
		virtual TTimeObj ValidNotBeforeDate ();
			// Returns the starting validity date for the certificate.
			// OpenSSL functions:  X509_get_notBefore
		
		virtual void SetValidNotBeforeDate (TTimeObj& beginValidDateObj);
			// Sets the starting validity date for the certificate to
			// the argument.  The TTimeObj should be set with local time
			// values.  If possible, it will be stored in the certificate
			// in GMT format.
			// OpenSSL functions:  X509_get_notBefore
		
		virtual TTimeObj ValidNotAfterDate ();
			// Returns the ending validity date for the certificate.
			// OpenSSL functions:  X509_get_notAfter
		
		virtual void SetValidNotAfterDate (TTimeObj& beginValidDateObj);
			// Sets the starting validity date for the certificate to
			// the argument.  The TTimeObj should be set with local time
			// values.  If possible, it will be stored in the certificate
			// in GMT format.
			// OpenSSL functions:  X509_get_notAfter
		
		virtual void SetValidDates (TTimeObj& beginValidDateObj, TTimeObj& endValidDateObj);
			// Sets the valid dates for the current certificate.  Both
			// TTimeObj arguments should be set with localtime values.  If
			// possible, they will be stored in GMT format.
			// OpenSSL functions:  X509_get_notBefore, X509_get_notAfter
		
		virtual void SetValidDates (TTimeObj& beginValidDateObj, unsigned int days);
			// Sets the valid dates for the current certificate, starting with the
			// beginValidDateObj value and continuing for 'days' days.
			// beginValidDateObj should be set with localtime values.  If possible,
			// it will be stored in GMT format.
		
		virtual int IssuerEntryCount ();
			// Returns the number of issuer entries in the current certificate.
			// OpenSSL functions:  X509_NAME_entry_count, X509_get_issuer_name
		
		virtual size_t GetIssuerEntries (StdStringList& issuerList);
			// Destructively modifies the argument to contain the issuers from
			// the current certificate.  Returns the number of issuers put
			// on the list.
			// OpenSSL functions:  X509_NAME_oneline, X509_get_issuer_name
		
		virtual void AddIssuerEntry (const std::string& field, const std::string& entry);
			// Adds the given field/entry combination to the issuer portion of the
			// current certificate.
			// OpenSSL functions:  X509_get_issuer_name, X509_NAME_add_entry_by_txt
		
		virtual void AddIssuerEntry (int nid, const std::string& entry);
			// Adds the given NID, which is translated to a field name, and entry
			// combination to the issuer portion of the current certificate.
			// OpenSSL functions:  X509_get_issuer_name, X509_NAME_add_entry_by_NID
		
		virtual int SubjectEntryCount ();
			// Returns the number of subject entries in the current certificate.
			// OpenSSL functions:  X509_NAME_entry_count, X509_get_subject_name
		
		virtual size_t GetSubjectEntries (StdStringList& subjectList);
			// Destructively modifies the argument to contain the subjects from
			// the current certificate.  Returns the number of subjects put
			// on the list.
			// OpenSSL functions:  X509_NAME_oneline, X509_get_subject_name
		
		virtual void AddSubjectEntry (const std::string& field, const std::string& entry);
			// Adds the given field/entry combination to the subject portion of the
			// current certificate.
			// OpenSSL functions:  X509_get_subject_name, X509_NAME_add_entry_by_txt
		
		virtual int ExtensionCount () const;
			// Returns the number of extensions loaded into the current certificate.
			// OpenSSL functions:  X509_get_ext_count
		
		virtual void AddSubjectEntry (int nid, const std::string& entry);
			// Adds the given NID, which is translated to a field name, and entry
			// combination to the subject portion of the current certificate.
			// OpenSSL functions:  X509_get_subject_name, X509_NAME_add_entry_by_NID
		
		virtual void AddV3Extension (int nid, const std::string& entry);
			// Adds the given information as an extension to the current certificate.
			// OpenSSL functions:  X509V3_EXT_conf_nid, X509_add_ext, X509_EXTENSION_free
		
		virtual void AddV3Extension (const std::string& name, const std::string& entry);
			// Adds the given information as an extension to the current certificate.
			// OpenSSL functions:  X509V3_EXT_conf, X509_add_ext, X509_EXTENSION_free
		
		virtual void Sign (const TDigest& digestObj, TPKeyObj& publicKeyObj);
			// Signs the certificate with the given digest algorithm and public key.
			// OpenSSL functions:  X509_sign
		
		virtual bool Verify (TPKeyObj& publicKeyObj) const;
			// Returns a boolean indicating whether the current certificate was
			// actually signed by the given key or not.
			// OpenSSL functions:  X509_verify
		
		virtual void WriteToFile (TFileObj& fileObj) const;
			// Writes the current certificate to the file indicated by the argument.
			// OpenSSL functions:  i2d_X509_fp
		
		virtual void ReadFromFile (TFileObj& fileObj);
			// Reads a certificate from the file indicated by the argument, destroying
			// any information currently contained within this object.
			// OpenSSL functions:  d2i_X509_fp
		
		virtual int CertificateType (EVP_PKEY* publicKeyPtr = NULL);
			// Returns the certificate type.
			// OpenSSL functions:  X509_certificate_type
	
	public:
		
		// Accessors
		
		inline bool IsSet () const
			{ return (fX509Ptr != NULL); }
		
		inline operator const X509* () const
			{ return fX509Ptr; }
		
		inline operator X509* ()
			{ return fX509Ptr; }
	
	protected:
		
		virtual void Cleanup ();
			// Initializes our internal structures.
			// OpenSSL functions:  X509_free
		
		virtual TTimeObj ConvertToTimeObj (ASN1_TIME* asn1TimePtr);
			// Converts a pointer to an ASN1_TIME structure to a TTimeObj.
			// Returned time will be in the local time zone.
		
		virtual void ConvertFromTimeObj (TTimeObj& timeObj, ASN1_TIME* asn1TimePtr);
			// Converts from a TTimeObj to an ASN1_TIME structure.  The
			// given time must be in the local time zone; it will be
			// converted to GMT if possible.
			// OpenSSL functions:  ASN1_UTCTIME_set, ASN1_GENERALIZEDTIME_set
	
	protected:
		
		X509*									fX509Ptr;
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif

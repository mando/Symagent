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

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-ssl-cert.h"

#include "symlib-utils.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TX509Obj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TX509Obj::TX509Obj ()
	:	fX509Ptr(NULL)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TX509Obj::TX509Obj (X509* x509Ptr)
	:	fX509Ptr(NULL)
{
	if (x509Ptr)
	{
		fX509Ptr = X509_dup(x509Ptr);
		if (!fX509Ptr)
			throw TSSLErrorObj(kSSLX509CopyFailure);
	}
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TX509Obj::TX509Obj (const TX509Obj& obj)
	:	fX509Ptr(NULL)
{
	if (obj.fX509Ptr)
	{
		fX509Ptr = X509_dup(obj.fX509Ptr);
		if (!fX509Ptr)
			throw TSSLErrorObj(kSSLX509CopyFailure);
	}
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TX509Obj::~TX509Obj ()
{
	Cleanup();
}

//---------------------------------------------------------------------
// TX509Obj::Initialize
//---------------------------------------------------------------------
void TX509Obj::Initialize ()
{
	Cleanup();
	
	fX509Ptr = X509_new();
	
	if (!fX509Ptr)
		throw TSSLErrorObj(kSSLX509InitFailure);
}

//---------------------------------------------------------------------
// TX509Obj::Version
//---------------------------------------------------------------------
unsigned long TX509Obj::Version () const
{
	unsigned long		version = 0;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	version = X509_get_version(fX509Ptr);
	
	return version;
}

//---------------------------------------------------------------------
// TX509Obj::SetVersion
//---------------------------------------------------------------------
void TX509Obj::SetVersion (unsigned long version)
{
	if (!IsSet())
		Initialize();
	
	if (X509_set_version(fX509Ptr,version) != 1)
		throw TSSLErrorObj(kSSLX509UnableToSetVersion);
}

//---------------------------------------------------------------------
// TX509Obj::PublicKey
//---------------------------------------------------------------------
TPKeyObj TX509Obj::PublicKey ()
{
	TPKeyObj		publicKeyObj;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	publicKeyObj = X509_get_pubkey(fX509Ptr);
	
	return publicKeyObj;
}

//---------------------------------------------------------------------
// TX509Obj::SetPublicKey
//---------------------------------------------------------------------
void TX509Obj::SetPublicKey (TPKeyObj& publicKeyObj)
{
	if (!IsSet())
		Initialize();
	
	X509_set_pubkey(fX509Ptr,publicKeyObj);
}

//---------------------------------------------------------------------
// TX509Obj::PublicKeyAlgorithmShortName
//---------------------------------------------------------------------
std::string TX509Obj::PublicKeyAlgorithmShortName ()
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	return std::string(OBJ_nid2sn(OBJ_obj2nid(fX509Ptr->cert_info->key->algor->algorithm)));
}

//---------------------------------------------------------------------
// TX509Obj::PublicKeyAlgorithmLongName
//---------------------------------------------------------------------
std::string TX509Obj::PublicKeyAlgorithmLongName ()
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	return std::string(OBJ_nid2ln(OBJ_obj2nid(fX509Ptr->cert_info->key->algor->algorithm)));
}

//---------------------------------------------------------------------
// TX509Obj::SignatureAlgorithmShortName
//---------------------------------------------------------------------
std::string TX509Obj::SignatureAlgorithmShortName ()
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	return std::string(OBJ_nid2sn(OBJ_obj2nid(fX509Ptr->sig_alg->algorithm)));
}

//---------------------------------------------------------------------
// TX509Obj::SignatureAlgorithmLongName
//---------------------------------------------------------------------
std::string TX509Obj::SignatureAlgorithmLongName ()
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	return std::string(OBJ_nid2ln(OBJ_obj2nid(fX509Ptr->sig_alg->algorithm)));
}

//---------------------------------------------------------------------
// TX509Obj::SignatureType
//---------------------------------------------------------------------
int TX509Obj::SignatureType () const
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	return X509_get_signature_type(fX509Ptr);
}

//---------------------------------------------------------------------
// TX509Obj::SerialNumber
//---------------------------------------------------------------------
TBigNumBuffer TX509Obj::SerialNumber () const
{
	TBigNumBuffer		serialNumber;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	serialNumber = ASN1_INTEGER_to_BN(X509_get_serialNumber(fX509Ptr),NULL);
	
	return serialNumber;
}

//---------------------------------------------------------------------
// TX509Obj::SetSerialNumber
//---------------------------------------------------------------------
void TX509Obj::SetSerialNumber (TBigNumBuffer serialNumber)
{
	if (!IsSet())
		Initialize();
	
	if (X509_set_serialNumber(fX509Ptr,BN_to_ASN1_INTEGER(serialNumber,X509_get_serialNumber(fX509Ptr))) != 1)
		throw TSSLErrorObj(kSSLX509UnableToSetSerialNumber);
}

//---------------------------------------------------------------------
// TX509Obj::ValidNotBeforeDate
//---------------------------------------------------------------------
TTimeObj TX509Obj::ValidNotBeforeDate ()
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	return ConvertToTimeObj(X509_get_notBefore(fX509Ptr));
}

//---------------------------------------------------------------------
// TX509Obj::SetValidNotBeforeDate
//---------------------------------------------------------------------
void TX509Obj::SetValidNotBeforeDate (TTimeObj& beginValidDateObj)
{
	if (!IsSet())
		Initialize();
	
	ConvertFromTimeObj(beginValidDateObj,X509_get_notBefore(fX509Ptr));
}

//---------------------------------------------------------------------
// TX509Obj::ValidNotAfterDate
//---------------------------------------------------------------------
TTimeObj TX509Obj::ValidNotAfterDate ()
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	return ConvertToTimeObj(X509_get_notAfter(fX509Ptr));
}

//---------------------------------------------------------------------
// TX509Obj::SetValidNotAfterDate
//---------------------------------------------------------------------
void TX509Obj::SetValidNotAfterDate (TTimeObj& beginValidDateObj)
{
	if (!IsSet())
		Initialize();
	
	ConvertFromTimeObj(beginValidDateObj,X509_get_notAfter(fX509Ptr));
}

//---------------------------------------------------------------------
// TX509Obj::SetValidDates
//---------------------------------------------------------------------
void TX509Obj::SetValidDates (TTimeObj& beginValidDateObj, TTimeObj& endValidDateObj)
{
	if (!IsSet())
		Initialize();
	
	ConvertFromTimeObj(beginValidDateObj,X509_get_notBefore(fX509Ptr));
	ConvertFromTimeObj(endValidDateObj,X509_get_notAfter(fX509Ptr));
}

//---------------------------------------------------------------------
// TX509Obj::SetValidDates
//---------------------------------------------------------------------
void TX509Obj::SetValidDates (TTimeObj& beginValidDateObj, unsigned int days)
{
	TTimeObj		endValidDateObj(beginValidDateObj);
	
	if (!IsSet())
		Initialize();
	
	endValidDateObj.AdjustDate(days,0,0);
	
	SetValidDates(beginValidDateObj,endValidDateObj);
}

//---------------------------------------------------------------------
// TX509Obj::IssuerEntryCount
//---------------------------------------------------------------------
int TX509Obj::IssuerEntryCount ()
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	return X509_NAME_entry_count(X509_get_issuer_name(fX509Ptr));
}

//---------------------------------------------------------------------
// TX509Obj::GetIssuerEntries
//---------------------------------------------------------------------
size_t TX509Obj::GetIssuerEntries (StdStringList& issuerList)
{
	std::string	tempString;
	size_t		kBufferSize = 2048;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	issuerList.clear();
	tempString.resize(kBufferSize);
	
	X509_NAME_oneline(X509_get_issuer_name(fX509Ptr),const_cast<char*>(tempString.data()),kBufferSize-1);
	tempString.resize(strlen(tempString.c_str()));
	SplitStdString('/',tempString,issuerList,false);
	
	return issuerList.size();
}

//---------------------------------------------------------------------
// TX509Obj::AddIssuerEntry
//---------------------------------------------------------------------
void TX509Obj::AddIssuerEntry (const std::string& field, const std::string& entry)
{
	X509_NAME*		namePtr = NULL;
	
	if (!IsSet())
		Initialize();
	
	namePtr = X509_get_issuer_name(fX509Ptr);
	
	X509_NAME_add_entry_by_txt(namePtr,const_cast<char*>(field.c_str()),MBSTRING_ASC,reinterpret_cast<unsigned char*>(const_cast<char*>(entry.c_str())),-1,-1,0);
}

//---------------------------------------------------------------------
// TX509Obj::AddIssuerEntry
//---------------------------------------------------------------------
void TX509Obj::AddIssuerEntry (int nid, const std::string& entry)
{
	X509_NAME*		namePtr = NULL;
	
	if (!IsSet())
		Initialize();
	
	namePtr = X509_get_issuer_name(fX509Ptr);
	
	X509_NAME_add_entry_by_NID(namePtr,nid,MBSTRING_ASC,reinterpret_cast<unsigned char*>(const_cast<char*>(entry.c_str())),-1,-1,0);
}

//---------------------------------------------------------------------
// TX509Obj::SubjectEntryCount
//---------------------------------------------------------------------
int TX509Obj::SubjectEntryCount ()
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	return X509_NAME_entry_count(X509_get_subject_name(fX509Ptr));
}

//---------------------------------------------------------------------
// TX509Obj::GetSubjectEntries
//---------------------------------------------------------------------
size_t TX509Obj::GetSubjectEntries (StdStringList& subjectList)
{
	std::string	tempString;
	size_t		kBufferSize = 2048;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	subjectList.clear();
	tempString.resize(kBufferSize);
	
	X509_NAME_oneline(X509_get_subject_name(fX509Ptr),const_cast<char*>(tempString.data()),kBufferSize-1);
	tempString.resize(strlen(tempString.c_str()));
	SplitStdString('/',tempString,subjectList,false);
	
	return subjectList.size();
}

//---------------------------------------------------------------------
// TX509Obj::AddSubjectEntry
//---------------------------------------------------------------------
void TX509Obj::AddSubjectEntry (const std::string& field, const std::string& entry)
{
	X509_NAME*		namePtr = NULL;
	
	if (!IsSet())
		Initialize();
	
	namePtr = X509_get_subject_name(fX509Ptr);
	
	X509_NAME_add_entry_by_txt(namePtr,const_cast<char*>(field.c_str()),MBSTRING_ASC,reinterpret_cast<unsigned char*>(const_cast<char*>(entry.c_str())),-1,-1,0);
}

//---------------------------------------------------------------------
// TX509Obj::AddSubjectEntry
//---------------------------------------------------------------------
void TX509Obj::AddSubjectEntry (int nid, const std::string& entry)
{
	X509_NAME*		namePtr = NULL;
	
	if (!IsSet())
		Initialize();
	
	namePtr = X509_get_subject_name(fX509Ptr);
	
	X509_NAME_add_entry_by_NID(namePtr,nid,MBSTRING_ASC,reinterpret_cast<unsigned char*>(const_cast<char*>(entry.c_str())),-1,-1,0);
}

//---------------------------------------------------------------------
// TX509Obj::ExtensionCount
//---------------------------------------------------------------------
int TX509Obj::ExtensionCount () const
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	return X509_get_ext_count(fX509Ptr);
}

//---------------------------------------------------------------------
// TX509Obj::AddV3Extension
//---------------------------------------------------------------------
void TX509Obj::AddV3Extension (int nid, const std::string& entry)
{
	X509_EXTENSION*		extPtr = NULL;
	
	if (!IsSet())
		Initialize();
	
	extPtr = X509V3_EXT_conf_nid(NULL,NULL,nid,const_cast<char*>(entry.c_str()));
	if (!extPtr)
		throw TSSLErrorObj(kSSLX509NotInited);
	
	X509_add_ext(fX509Ptr,extPtr,-1);
	X509_EXTENSION_free(extPtr);
}

//---------------------------------------------------------------------
// TX509Obj::AddV3Extension
//---------------------------------------------------------------------
void TX509Obj::AddV3Extension (const std::string& name, const std::string& entry)
{
	X509_EXTENSION*		extPtr = NULL;
	
	if (!IsSet())
		Initialize();
	
	extPtr = X509V3_EXT_conf(NULL,NULL,const_cast<char*>(name.c_str()),const_cast<char*>(entry.c_str()));
	if (!extPtr)
		throw TSSLErrorObj(kSSLX509NotInited);
	
	X509_add_ext(fX509Ptr,extPtr,-1);
	X509_EXTENSION_free(extPtr);
}

//---------------------------------------------------------------------
// TX509Obj::Sign
//---------------------------------------------------------------------
void TX509Obj::Sign (const TDigest& digestObj, TPKeyObj& publicKeyObj)
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	X509_sign(fX509Ptr,publicKeyObj,digestObj);
}

//---------------------------------------------------------------------
// TX509Obj::Verify
//---------------------------------------------------------------------
bool TX509Obj::Verify (TPKeyObj& publicKeyObj) const
{
	bool		verified = false;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	if (X509_verify(fX509Ptr,publicKeyObj) <= 0)
		verified = false;
	else
		verified = true;
	
	return verified;
}

//---------------------------------------------------------------------
// TX509Obj::WriteToFile
//---------------------------------------------------------------------
void TX509Obj::WriteToFile (TFileObj& fileObj) const
{
	FILE*	streamPtr = NULL;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	// Manage the file we were given to make sure it's opened appropriately
	if (fileObj.Exists())
		fileObj.Delete();
	fileObj.Create(S_IRUSR|S_IWUSR,true);
	
	// Open a stream to the file
	streamPtr = fopen(fileObj.Path().c_str(),"w");
	if (streamPtr)
	{
		try
		{
			if (i2d_X509_fp(streamPtr,fX509Ptr) != 1)
				throw TSSLErrorObj(kSSLX509NotInited);
			
			// Close the file
			fclose(streamPtr);
		}
		catch (...)
		{
			// Close the stream before passing the exception through
			fclose(streamPtr);
			throw;
		}
	}
	else
		throw TSymLibErrorObj(errno);
}

//---------------------------------------------------------------------
// TX509Obj::ReadFromFile
//---------------------------------------------------------------------
void TX509Obj::ReadFromFile (TFileObj& fileObj)
{
	FILE*	streamPtr = NULL;
	
	if (!fileObj.Exists())
		throw TSymLibErrorObj(ENOENT,"Certificate file does not exist");
	
	Cleanup();
	
	// Open a stream to the file
	streamPtr = fopen(fileObj.Path().c_str(),"r");
	if (streamPtr)
	{
		try
		{
			fX509Ptr = d2i_X509_fp(streamPtr,NULL);
			if (!fX509Ptr)
				throw TSSLErrorObj(kSSLX509NotInited);
			
			// Close the file
			fclose(streamPtr);
		}
		catch (...)
		{
			// Close the stream before passing the exception through
			fclose(streamPtr);
			throw;
		}
	}
	else
		throw TSymLibErrorObj(errno);
}

//---------------------------------------------------------------------
// TX509Obj::CertificateType
//---------------------------------------------------------------------
int TX509Obj::CertificateType (EVP_PKEY* publicKeyPtr)
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLX509NotInited);
	
	return X509_certificate_type(fX509Ptr,publicKeyPtr);
}

//---------------------------------------------------------------------
// TX509Obj::Cleanup (protected)
//---------------------------------------------------------------------
void TX509Obj::Cleanup ()
{
	if (fX509Ptr)
	{
		X509_free(fX509Ptr);
		fX509Ptr = NULL;
	}
}

//---------------------------------------------------------------------
// TX509Obj::ConvertToTimeObj (protected)
//---------------------------------------------------------------------
TTimeObj TX509Obj::ConvertToTimeObj (ASN1_TIME* asn1TimePtr)
{
	TTimeObj		timeObj;
	
	if (asn1TimePtr)
	{
		int				dataLength = asn1TimePtr->length;
		unsigned char*	dataPtr = asn1TimePtr->data;
		bool			isGMT = false;
		
		if (asn1TimePtr->type == V_ASN1_UTCTIME)
		{
			int		tempYear = 0;
			
			// Make sure the data is long enough
			if (dataLength < 10)
				throw TSSLErrorObj(-1);
			
			// Make sure the part of the data we're interested in is all number
			for (int x = 0; x < 10; x++)
			{
				if (dataPtr[x] < '0' || dataPtr[x] > '9')
					throw TSSLErrorObj(-1);
			}
			
			// See if the time is in GMT
			if (dataPtr[dataLength-1] == 'Z')
				isGMT = true;
			
			// Extract the year
			tempYear = (dataPtr[0]-'0')*10+(dataPtr[1]-'0');
			if (tempYear < 50)
				tempYear += 100;
			timeObj.SetYear(tempYear+1900);
			
			// Extract the month
			timeObj.SetMonth((dataPtr[2]-'0')*10+(dataPtr[3]-'0'));
			if (timeObj.Month() < 1 || timeObj.Month() > 12)
				throw TSSLErrorObj(-1);
			
			// Extract the day
			timeObj.SetDay((dataPtr[4]-'0')*10+(dataPtr[5]-'0'));
			
			// Extract the hour
			timeObj.SetHour((dataPtr[6]-'0')*10+(dataPtr[7]-'0'));
			
			// Extract the minute
			timeObj.SetMinute((dataPtr[8]-'0')*10+(dataPtr[9]-'0'));
			if (timeObj.Minute() < 0 || timeObj.Minute() > 59)
				throw TSSLErrorObj(-1);
			
			// Extract the second, if it appears to be valid
			if (dataPtr[10] >= '0' && dataPtr[10] <= '9' && dataPtr[11] >= '0' && dataPtr[11] <= '9')
				timeObj.SetSecond((dataPtr[10]-'0')*10+(dataPtr[11]-'0'));
			
			// If the time is GMT then we need to make it a local time
			if (isGMT)
				timeObj.AdjustTime(0,MinutesWestOfGMT() * -1,0);
		}
		else if (asn1TimePtr->type == V_ASN1_GENERALIZEDTIME)
		{
			// Make sure the data is long enough
			if (dataLength < 12)
				throw TSSLErrorObj(-1);
			
			// Make sure the part of the data we're interested in is all number
			for (int x = 0; x < 12; x++)
			{
				if (dataPtr[x] < '0' || dataPtr[x] > '9')
					throw TSSLErrorObj(-1);
			}
			
			// See if the time is in GMT
			if (dataPtr[dataLength-1] == 'Z')
				isGMT = true;
			
			// Extract the year
			timeObj.SetYear((dataPtr[0]-'0')*1000+(dataPtr[1]-'0')*100+(dataPtr[2]-'0')*10+(dataPtr[3]-'0'));
			
			// Extract the month
			timeObj.SetMonth((dataPtr[4]-'0')*10+(dataPtr[5]-'0'));
			if (timeObj.Month() < 1 || timeObj.Month() > 12)
				throw TSSLErrorObj(-1);
			
			// Extract the day
			timeObj.SetDay((dataPtr[6]-'0')*10+(dataPtr[7]-'0'));
			
			// Extract the hour
			timeObj.SetHour((dataPtr[8]-'0')*10+(dataPtr[9]-'0'));
			
			// Extract the minute
			timeObj.SetMinute((dataPtr[10]-'0')*10+(dataPtr[11]-'0'));
			if (timeObj.Minute() < 0 || timeObj.Minute() > 59)
				throw TSSLErrorObj(-1);
			
			// Extract the second, if it appears to be valid
			if (dataPtr[12] >= '0' && dataPtr[12] <= '9' && dataPtr[13] >= '0' && dataPtr[13] <= '9')
				timeObj.SetSecond((dataPtr[12]-'0')*10+(dataPtr[13]-'0'));
			
			// If the time is GMT then we need to make it a local time
			if (isGMT)
				timeObj.AdjustTime(0,MinutesWestOfGMT() * -1,0);
		}
		else
		{
			// Unknown time thingy.  Throw an exception.
			throw TSSLErrorObj(-1);
		}
	}
	else
	{
		// Time thingy is missing.
		throw TSSLErrorObj(-1);
	}
	
	return timeObj;
}

//---------------------------------------------------------------------
// TX509Obj::ConvertFromTimeObj (protected)
//---------------------------------------------------------------------
void TX509Obj::ConvertFromTimeObj (TTimeObj& timeObj, ASN1_TIME* asn1TimePtr)
{
	if (asn1TimePtr)
	{
		time_t		seconds = timeObj.GetUnixSeconds();
		
		if (asn1TimePtr->type == V_ASN1_UTCTIME)
			ASN1_UTCTIME_set(asn1TimePtr,seconds);
		else
			ASN1_GENERALIZEDTIME_set(asn1TimePtr,seconds);
	}
	else
	{
		// Time thingy is missing.
		throw TSSLErrorObj(-1);
	}
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

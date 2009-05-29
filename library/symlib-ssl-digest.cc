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
#include "symlib-ssl-digest.h"

#include <algorithm>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TDigest
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TDigest::TDigest ()
	:	fDigestPtr(NULL)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TDigest::TDigest (const char* digestName)
	:	fDigestPtr(NULL)
{
	Set(digestName);
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TDigest::TDigest (const EVP_MD* algoPtr)
	:	fDigestPtr(algoPtr)
{
}

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
TDigest::TDigest (const TDigest& obj)
	:	fDigestPtr(obj.fDigestPtr)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TDigest::~TDigest ()
{
	fDigestPtr = NULL;
}

//---------------------------------------------------------------------
// TDigest::Set
//---------------------------------------------------------------------
void TDigest::Set (const EVP_MD* algoPtr)
{
	fDigestPtr = algoPtr;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLMessageDigestAlgoUnknown,"Invalid message digest");
}

//---------------------------------------------------------------------
// TDigest::Set
//---------------------------------------------------------------------
void TDigest::Set (const std::string& digestName)
{
	TDigestContext::LoadAllAlgorithms();
	
	Set(EVP_get_digestbyname(digestName.c_str()));
}

//---------------------------------------------------------------------
// TDigest::Set
//---------------------------------------------------------------------
void TDigest::Set (int type)
{
	TDigestContext::LoadAllAlgorithms();
	
	Set(EVP_get_digestbynid(type));
}

//---------------------------------------------------------------------
// TDigest::ShortName
//---------------------------------------------------------------------
const std::string TDigest::ShortName () const
{
	std::string		name;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLMessageDigestAlgoNotSet);
	
	name = OBJ_nid2sn(EVP_MD_type(fDigestPtr));
	
	return name;
}

//---------------------------------------------------------------------
// TDigest::LongName
//---------------------------------------------------------------------
const std::string TDigest::LongName () const
{
	std::string		name;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLMessageDigestAlgoNotSet);
	
	name = OBJ_nid2ln(EVP_MD_type(fDigestPtr));
	
	return name;
}

//---------------------------------------------------------------------
// TDigest::Type
//---------------------------------------------------------------------
int TDigest::Type () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLMessageDigestAlgoNotSet);
	
	return EVP_MD_type(fDigestPtr);
}

//---------------------------------------------------------------------
// TDigest::PublicKeyTypeID
//---------------------------------------------------------------------
int TDigest::PublicKeyTypeID () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLMessageDigestAlgoNotSet);
	
	return EVP_MD_pkey_type(fDigestPtr);
}

//---------------------------------------------------------------------
// TDigest::Size
//---------------------------------------------------------------------
int TDigest::Size () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLMessageDigestAlgoNotSet);
	
	return EVP_MD_size(fDigestPtr);
}

//---------------------------------------------------------------------
// TDigest::BlockSize
//---------------------------------------------------------------------
int TDigest::BlockSize () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLMessageDigestAlgoNotSet);
	
	return EVP_MD_block_size(fDigestPtr);
}

//*********************************************************************
// Class TDigestContext
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TDigestContext::TDigestContext ()
	:	fIsInited(false),
		fHasAlgorithm(false)
{
}

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
TDigestContext::TDigestContext (const TDigestContext& obj)
	:	fIsInited(obj.fIsInited),
		fHasAlgorithm(obj.fHasAlgorithm),
		fAlgorithm(obj.fAlgorithm)
{
	if (EVP_MD_CTX_copy(&fContext,const_cast<EVP_MD_CTX*>(&obj.fContext)) != 1)
		throw TSSLErrorObj(kSSLMessageDigestNotCopied);
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TDigestContext::~TDigestContext ()
{
}

//---------------------------------------------------------------------
// TDigestContext::Initialize
//---------------------------------------------------------------------
void TDigestContext::Initialize (const TDigest& digestObj)
{
	fAlgorithm = digestObj;
	EVP_DigestInit(&fContext,fAlgorithm.Ptr());
	fIsInited = true;
	fHasAlgorithm = true;
}

//---------------------------------------------------------------------
// TDigestContext::ReInitialize
//---------------------------------------------------------------------
void TDigestContext::ReInitialize ()
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLMessageDigestNotInited,"SSL: Message digest not initialized with an algorithm");
	
	EVP_DigestInit(&fContext,fAlgorithm.Ptr());
	fIsInited = true;
}

//---------------------------------------------------------------------
// TDigestContext::Update
//---------------------------------------------------------------------
void TDigestContext::Update (const void* bufferPtr, unsigned int bufferSize)
{
	if (HasAlgorithm() && !IsInited())
		ReInitialize();
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLMessageDigestNotInited);
	
	if (bufferPtr)
		EVP_DigestUpdate(&fContext,bufferPtr,bufferSize);
}

//---------------------------------------------------------------------
// TDigestContext::Update
//---------------------------------------------------------------------
void TDigestContext::Update (const std::string& buffer)
{
	Update(buffer.data(),buffer.length());
}

//---------------------------------------------------------------------
// TDigestContext::Update
//---------------------------------------------------------------------
void TDigestContext::Update (TFileObj& fileObj)
{
	if (HasAlgorithm() && !IsInited())
		ReInitialize();
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLMessageDigestNotInited);
	
	TUpdateScanMixin::Update(fileObj);
}

//---------------------------------------------------------------------
// TDigestContext::Final
//---------------------------------------------------------------------
std::string TDigestContext::Final ()
{
	std::string		digestValue;
	unsigned int	finalSize = 0;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLMessageDigestNotInited);
	
	digestValue.resize(MaxDigestSize());
	EVP_DigestFinal(&fContext,const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(digestValue.data())),&finalSize);
	digestValue.resize(finalSize);
	
	fIsInited = false;
	
	return digestValue;
}

//---------------------------------------------------------------------
// TDigestContext::Name
//---------------------------------------------------------------------
std::string TDigestContext::Name () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLMessageDigestAlgoNotSet);
	
	return fAlgorithm.Name();
}

//---------------------------------------------------------------------
// TDigestContext::Type
//---------------------------------------------------------------------
int TDigestContext::Type () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLMessageDigestAlgoNotSet);
	
	return fAlgorithm.Type();
}

//---------------------------------------------------------------------
// TDigestContext::PublicKeyTypeID
//---------------------------------------------------------------------
int TDigestContext::PublicKeyTypeID () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLMessageDigestAlgoNotSet);
	
	return fAlgorithm.PublicKeyTypeID();
}

//---------------------------------------------------------------------
// TDigestContext::Size
//---------------------------------------------------------------------
int TDigestContext::Size () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLMessageDigestAlgoNotSet);
	
	return fAlgorithm.Size();
}

//---------------------------------------------------------------------
// TDigestContext::BlockSize
//---------------------------------------------------------------------
int TDigestContext::BlockSize () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLMessageDigestAlgoNotSet);
	
	return fAlgorithm.BlockSize();
}

//---------------------------------------------------------------------
// TDigestContext::LoadAllAlgorithms (static)
//---------------------------------------------------------------------
void TDigestContext::LoadAllAlgorithms ()
{
	SSLEnvironmentObjPtr()->LoadAllDigestAlgorithms();
}

//---------------------------------------------------------------------
// TDigestContext::GetAllAlgorithmNames (static)
//---------------------------------------------------------------------
void TDigestContext::GetAllAlgorithmNames (StdStringList& digestNameList)
{
	digestNameList.clear();
	
	#ifndef NO_MD2
		digestNameList.push_back(OBJ_nid2sn(EVP_MD_type(EVP_md2())));
	#endif
	
	#ifndef NO_MD4
		digestNameList.push_back(OBJ_nid2sn(EVP_MD_type(EVP_md4())));
	#endif
	
	#ifndef NO_MD5
		digestNameList.push_back(OBJ_nid2sn(EVP_MD_type(EVP_md5())));
	#endif
	
	#ifndef NO_SHA
		digestNameList.push_back(OBJ_nid2sn(EVP_MD_type(EVP_sha())));
		digestNameList.push_back(OBJ_nid2sn(EVP_MD_type(EVP_sha1())));
		digestNameList.push_back(OBJ_nid2sn(EVP_MD_type(EVP_dss())));
		digestNameList.push_back(OBJ_nid2sn(EVP_MD_type(EVP_dss1())));
	#endif
	
	#ifndef NO_MDC2
		digestNameList.push_back(OBJ_nid2sn(EVP_MD_type(EVP_mdc2())));
	#endif
	
	#ifndef NO_RIPEMD
		digestNameList.push_back(OBJ_nid2sn(EVP_MD_type(EVP_ripemd160())));
	#endif
	
	sort(digestNameList.begin(),digestNameList.end());
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

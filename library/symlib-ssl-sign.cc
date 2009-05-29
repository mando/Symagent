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
#include "symlib-ssl-sign.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TSignContextBase
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSignContextBase::TSignContextBase ()
	:	fIsInited(false),
		fHasDigestObj(false)
{
}

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
TSignContextBase::TSignContextBase (const TSignContextBase& obj)
	:	fIsInited(obj.fIsInited),
		fHasDigestObj(obj.fHasDigestObj),
		fDigestObj(obj.fDigestObj),
		fDigestContextObj(obj.fDigestContextObj)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSignContextBase::~TSignContextBase ()
{
}

//---------------------------------------------------------------------
// TSignContextBase::Initialize
//---------------------------------------------------------------------
void TSignContextBase::Initialize (const TDigest& digestObj)
{
	fDigestObj = digestObj;
	_Init();
	fIsInited = true;
	fHasDigestObj = true;
}

//---------------------------------------------------------------------
// TSignContextBase::ReInitialize
//---------------------------------------------------------------------
void TSignContextBase::ReInitialize ()
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLSigningContextNotInited,"SSL: Signing context not initialized with an algorithm");
	
	_Init();
	fIsInited = true;
}

//---------------------------------------------------------------------
// TSignContextBase::Update
//---------------------------------------------------------------------
void TSignContextBase::Update (const void* bufferPtr, unsigned int bufferSize)
{
	if (HasAlgorithm() && !IsInited())
		ReInitialize();
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSigningContextNotInited);
	
	if (bufferPtr)
		_Update(bufferPtr,bufferSize);
}

//---------------------------------------------------------------------
// TSignContextBase::Update
//---------------------------------------------------------------------
void TSignContextBase::Update (const std::string& buffer)
{
	Update(buffer.data(),buffer.length());
}

//---------------------------------------------------------------------
// TSignContextBase::Update
//---------------------------------------------------------------------
void TSignContextBase::Update (TFileObj& fileObj)
{
	if (HasAlgorithm() && !IsInited())
		ReInitialize();
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSigningContextNotInited);
	
	TUpdateScanMixin::Update(fileObj);
}

//*********************************************************************
// Class TSignContext
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSignContext::TSignContext ()
{
}

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
TSignContext::TSignContext (const TSignContext& obj)
	:	Inherited(obj)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSignContext::~TSignContext ()
{
}

//---------------------------------------------------------------------
// TSignContext::Final
//---------------------------------------------------------------------
std::string TSignContext::Final (TPKeyObj& pkeyObj)
{
	std::string		signature;
	unsigned int	finalSize = 0;
	
	if (!fIsInited)
		throw TSSLErrorObj(kSSLSigningContextNotInited);
	
	// Set the signature buffer to a maximum size
	signature.resize(pkeyObj.Size());
	
	// Compute the actual signature
	if (EVP_SignFinal(fDigestContextObj,const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(signature.data())),&finalSize,pkeyObj) != 1)
		throw TSSLErrorObj(kSSLSigningContextSignatureFailure);
	
	// Resize the signature accordingly
	signature.resize(finalSize);
	
	fIsInited = false;
	
	return signature;
}

//---------------------------------------------------------------------
// TSignContext::_Init (protected)
//---------------------------------------------------------------------
void TSignContext::_Init ()
{
	EVP_SignInit(fDigestContextObj,fDigestObj);
}

//---------------------------------------------------------------------
// TSignContext::_Update (protected)
//---------------------------------------------------------------------
void TSignContext::_Update (const void* bufferPtr, unsigned int bufferSize)
{
	if (bufferPtr)
		EVP_SignUpdate(fDigestContextObj,bufferPtr,bufferSize);
}

//*********************************************************************
// Class TVerifyContext
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TVerifyContext::TVerifyContext ()
{
}

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
TVerifyContext::TVerifyContext (const TVerifyContext& obj)
	:	Inherited(obj)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TVerifyContext::~TVerifyContext ()
{
}

//---------------------------------------------------------------------
// TVerifyContext::Final
//---------------------------------------------------------------------
bool TVerifyContext::Final (std::string& signature, TPKeyObj& pkeyObj)
{
	bool	verified = false;
	int		verifyResult = 0;
	
	if (!fIsInited)
		throw TSSLErrorObj(kSSLSigningContextNotInited);
	
	// Perform the verification
	verifyResult = EVP_VerifyFinal(fDigestContextObj,const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(signature.data())),signature.length(),pkeyObj);
	if (verifyResult == -1)
		throw TSSLErrorObj(kSSLSigningContextSignatureFailure);
	else if (verifyResult == 1)
		verified = true;
	
	fIsInited = false;
	
	return verified;
}

//---------------------------------------------------------------------
// TVerifyContext::_Init (protected)
//---------------------------------------------------------------------
void TVerifyContext::_Init ()
{
	EVP_VerifyInit(fDigestContextObj,fDigestObj);
}

//---------------------------------------------------------------------
// TVerifyContext::_Update (protected)
//---------------------------------------------------------------------
void TVerifyContext::_Update (const void* bufferPtr, unsigned int bufferSize)
{
	if (bufferPtr)
		EVP_VerifyUpdate(fDigestContextObj,bufferPtr,bufferSize);
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

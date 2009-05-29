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
#		Last Modified:				23 Feb 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-ssl-cipher.h"

#include "symlib-utils.h"

#include <algorithm>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TCipher
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TCipher::TCipher ()
	:	fCipherPtr(NULL)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TCipher::TCipher (const std::string& cipherName)
	:	fCipherPtr(NULL)
{
	Set(cipherName);
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TCipher::TCipher (const EVP_CIPHER* cipherPtr)
	:	fCipherPtr(cipherPtr)
{
}

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
TCipher::TCipher (const TCipher& obj)
	:	fCipherPtr(obj.fCipherPtr)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TCipher::~TCipher ()
{
	fCipherPtr = NULL;
}

//---------------------------------------------------------------------
// TCipher::Set
//---------------------------------------------------------------------
void TCipher::Set (const EVP_CIPHER* cipherPtr)
{
	fCipherPtr = cipherPtr;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherAlgoUnknown,"Invalid cipher given during Set()");
}

//---------------------------------------------------------------------
// TCipher::Set
//---------------------------------------------------------------------
void TCipher::Set (const std::string& cipherName)
{
	TCipherContext::LoadAllAlgorithms();
	
	Set(EVP_get_cipherbyname(cipherName.c_str()));
}

//---------------------------------------------------------------------
// TCipher::Set
//---------------------------------------------------------------------
void TCipher::Set (int nid)
{
	TCipherContext::LoadAllAlgorithms();
	
	Set(EVP_get_cipherbynid(nid));
}

//---------------------------------------------------------------------
// TCipher::ShortName
//---------------------------------------------------------------------
const std::string TCipher::ShortName () const
{
	std::string		name;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	name = OBJ_nid2sn(EVP_CIPHER_nid(fCipherPtr));
	
	return name;
}

//---------------------------------------------------------------------
// TCipher::LongName
//---------------------------------------------------------------------
const std::string TCipher::LongName () const
{
	std::string		name;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	name = OBJ_nid2ln(EVP_CIPHER_nid(fCipherPtr));
	
	return name;
}

//---------------------------------------------------------------------
// TCipher::Type
//---------------------------------------------------------------------
int TCipher::Type () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return EVP_CIPHER_type(fCipherPtr);
}

//---------------------------------------------------------------------
// TCipher::NID
//---------------------------------------------------------------------
int TCipher::NID () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return EVP_CIPHER_nid(fCipherPtr);
}

//---------------------------------------------------------------------
// TCipher::BlockSize
//---------------------------------------------------------------------
int TCipher::BlockSize () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return EVP_CIPHER_block_size(fCipherPtr);
}

//---------------------------------------------------------------------
// TCipher::KeyLength
//---------------------------------------------------------------------
int TCipher::KeyLength () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return EVP_CIPHER_key_length(fCipherPtr);
}

//---------------------------------------------------------------------
// TCipher::IVLength
//---------------------------------------------------------------------
int TCipher::IVLength () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return EVP_CIPHER_iv_length(fCipherPtr);
}

//---------------------------------------------------------------------
// TCipher::Flags
//---------------------------------------------------------------------
unsigned long TCipher::Flags () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return EVP_CIPHER_flags(fCipherPtr);
}

//---------------------------------------------------------------------
// TCipher::Mode
//---------------------------------------------------------------------
unsigned long TCipher::Mode () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return EVP_CIPHER_mode(fCipherPtr);
}

//*********************************************************************
// Class TCipherContext
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TCipherContext::TCipherContext ()
	:	fIsInited(false),
		fHasAlgorithm(false)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TCipherContext::~TCipherContext ()
{
	Cleanup();
}

//---------------------------------------------------------------------
// TCipherContext::Initialize
//---------------------------------------------------------------------
void TCipherContext::Initialize (const TCipher& cipherObj,
								 std::string key,
								 std::string iv,
								 CipherMode mode)
{
	unsigned char*	keyPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(key.data()));
	unsigned char*	ivPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(iv.data()));
	
	// Destroy any existing context
	Cleanup();
	
	// Make sure the IV is big enough
	if (iv.capacity() < static_cast<unsigned int>(cipherObj.IVLength()))
		iv.resize(cipherObj.IVLength());
	
	fCipherObj = cipherObj;
	if (EVP_CipherInit(&fContext,fCipherObj.Ptr(),keyPtr,ivPtr,(mode == kEncrypt ? 1 : 0)) != 1)
		throw TSSLErrorObj(kSSLCipherInitFailure);
	fIsInited = true;
	fHasAlgorithm = true;
}

//---------------------------------------------------------------------
// TCipherContext::Update
//---------------------------------------------------------------------
void TCipherContext::Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherNotInited);
	
	tempBuffer.resize(inBufferSize + fCipherObj.BlockSize());
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	if (EVP_CipherUpdate(&fContext,tempBufferPtr,&tempBufferSize,inBufferPtr,inBufferSize) != 1)
		throw TSSLErrorObj(kSSLCipherUpdateFailure);
	if (tempBufferSize > 0)
	{
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
}

//---------------------------------------------------------------------
// TCipherContext::Update
//---------------------------------------------------------------------
void TCipherContext::Update (std::string& inBuffer, std::string& outBuffer)
{
	unsigned char*	inBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(inBuffer.data()));
	int				inBufferSize = inBuffer.length();
	
	Update(inBufferPtr,inBufferSize,outBuffer);
}

//---------------------------------------------------------------------
// TCipherContext::Update
//---------------------------------------------------------------------
void TCipherContext::Update (TFileObj& inFileObj, TFileObj& outFileObj)
{
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherNotInited);
	
	TUpdateMorphMixin::Update(inFileObj,outFileObj);
}

//---------------------------------------------------------------------
// TCipherContext::Final
//---------------------------------------------------------------------
void TCipherContext::Final (std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherNotInited);
	
	tempBuffer.resize(fCipherObj.BlockSize());
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	if (EVP_CipherFinal(&fContext,tempBufferPtr,&tempBufferSize) != 1)
		throw TSSLErrorObj(kSSLCipherFinalFailure);
	if (tempBufferSize > 0)
	{
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
	
	fIsInited = false;
}

//---------------------------------------------------------------------
// TCipherContext::Final
//---------------------------------------------------------------------
void TCipherContext::Final (TFileObj& outFileObj)
{
	std::string		tempBuffer;
	
	Final(tempBuffer);
	if (!tempBuffer.empty())
		outFileObj.Write(tempBuffer);
}

//---------------------------------------------------------------------
// TCipherContext::Cleanup
//---------------------------------------------------------------------
void TCipherContext::Cleanup ()
{
	if (IsInited())
	{
		if (EVP_CIPHER_CTX_cleanup(&fContext) != 1)
			throw TSSLErrorObj(kSSLCipherCleanupFailure);
	}
	
	fIsInited = false;
}

//---------------------------------------------------------------------
// TCipherContext::SetKeyLength
//---------------------------------------------------------------------
void TCipherContext::SetKeyLength (int keyLength)
{
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherNotInited);
	
	if (EVP_CIPHER_CTX_set_key_length(&fContext,keyLength) != 1)
		throw TSSLErrorObj(kSSLCipherSetKeyLengthFailure);
}

//---------------------------------------------------------------------
// TCipherContext::Control
//---------------------------------------------------------------------
void TCipherContext::Control (int type, int arg, void* data)
{
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherNotInited);
	
	if (EVP_CIPHER_CTX_ctrl(&fContext,type,arg,data) != 1)
		throw TSSLErrorObj(kSSLCipherSetKeyLengthFailure);
}

//---------------------------------------------------------------------
// TCipherContext::SetAppData
//---------------------------------------------------------------------
void TCipherContext::SetAppData (void* appDataPtr)
{
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherNotInited);
	
	EVP_CIPHER_CTX_set_app_data(&fContext,appDataPtr);
}

//---------------------------------------------------------------------
// TCipherContext::GetAppData
//---------------------------------------------------------------------
void* TCipherContext::GetAppData () const
{
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherNotInited);
	
	return EVP_CIPHER_CTX_get_app_data(&fContext);
}

//---------------------------------------------------------------------
// TCipherContext::Name
//---------------------------------------------------------------------
std::string TCipherContext::Name () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return fCipherObj.Name();
}

//---------------------------------------------------------------------
// TCipherContext::NID
//---------------------------------------------------------------------
int TCipherContext::NID () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return fCipherObj.NID();
}

//---------------------------------------------------------------------
// TCipherContext::Type
//---------------------------------------------------------------------
int TCipherContext::Type () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return fCipherObj.Type();
}

//---------------------------------------------------------------------
// TCipherContext::BlockSize
//---------------------------------------------------------------------
int TCipherContext::BlockSize () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return fCipherObj.BlockSize();
}

//---------------------------------------------------------------------
// TCipherContext::KeyLength
//---------------------------------------------------------------------
int TCipherContext::KeyLength () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return fCipherObj.KeyLength();
}

//---------------------------------------------------------------------
// TCipherContext::IVLength
//---------------------------------------------------------------------
int TCipherContext::IVLength () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return fCipherObj.IVLength();
}

//---------------------------------------------------------------------
// TCipherContext::Flags
//---------------------------------------------------------------------
unsigned long TCipherContext::Flags () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return fCipherObj.Flags();
}

//---------------------------------------------------------------------
// TCipherContext::Mode
//---------------------------------------------------------------------
unsigned long TCipherContext::Mode () const
{
	if (!HasAlgorithm())
		throw TSSLErrorObj(kSSLCipherAlgoNotSet);
	
	return fCipherObj.Mode();
}

//---------------------------------------------------------------------
// TCipherContext::RandomIV (static)
//---------------------------------------------------------------------
std::string TCipherContext::RandomIV ()
{
	std::string		randomBuffer;
	int				kMaxIVLength = TCipherContext::MaxIVLength();
	
	randomBuffer.resize(kMaxIVLength*2);
	RandomBytes(kMaxIVLength*2,const_cast<char*>(randomBuffer.data()),false);
	TSSLEnvironment::PRNGSeed(randomBuffer);
	
	return TSSLEnvironment::PRNGGetBytes(kMaxIVLength);
}

//---------------------------------------------------------------------
// TCipherContext::LoadAllAlgorithms (static)
//---------------------------------------------------------------------
void TCipherContext::LoadAllAlgorithms ()
{
	SSLEnvironmentObjPtr()->LoadAllCipherAlgorithms();
}

//---------------------------------------------------------------------
// TCipherContext::GetAllAlgorithmNames (static)
//---------------------------------------------------------------------
void TCipherContext::GetAllAlgorithmNames (StdStringList& algoNameList)
{
	algoNameList.clear();
	
	#if !defined(NO_DES) && !defined(OPENSSL_NO_DES) && HAVE_OPENSSL_DES_H
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_ecb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_ede())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_ede3())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_cfb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_ede_cfb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_ede3_cfb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_ofb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_ede_ofb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_ede3_ofb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_cbc())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_ede_cbc())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_des_ede3_cbc())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_desx_cbc())));
	#endif
	
	#if !defined(NO_RC4) && !defined(OPENSSL_NO_RC4) && HAVE_OPENSSL_RC4_H
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc4())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc4_40())));
	#endif
	
	#if !defined(NO_IDEA) && !defined(OPENSSL_NO_IDEA) && HAVE_OPENSSL_IDEA_H
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_idea_ecb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_idea_cfb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_idea_ofb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_idea_cbc())));
	#endif
	
	#if !defined(NO_RC2) && !defined(OPENSSL_NO_RC2) && HAVE_OPENSSL_RC2_H
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc2_ecb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc2_cbc())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc2_40_cbc())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc2_64_cbc())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc2_cfb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc2_ofb())));
	#endif
	
	#if !defined(NO_BF) && !defined(OPENSSL_NO_BF) && HAVE_OPENSSL_BLOWFISH_H
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_bf_ecb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_bf_cbc())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_bf_cfb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_bf_ofb())));
	#endif
	
	#if !defined(NO_CAST) && !defined(OPENSSL_NO_CAST) && HAVE_OPENSSL_CAST_H
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_cast5_ecb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_cast5_cbc())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_cast5_cfb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_cast5_ofb())));
	#endif
	
	#if !defined(NO_RC5) && !defined(OPENSSL_NO_RC5) && HAVE_OPENSSL_RC5_H
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc5_32_12_16_ecb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc5_32_12_16_cbc())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc5_32_12_16_cfb())));
		algoNameList.push_back(OBJ_nid2sn(EVP_CIPHER_nid(EVP_rc5_32_12_16_ofb())));
	#endif
	
	sort(algoNameList.begin(),algoNameList.end());
}

//*********************************************************************
// Class TEncryptContext
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TEncryptContext::TEncryptContext ()
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TEncryptContext::~TEncryptContext ()
{
}

//---------------------------------------------------------------------
// TEncryptContext::Initialize
//---------------------------------------------------------------------
void TEncryptContext::Initialize (const TCipher& cipherObj,
								  std::string key,
								  std::string iv)
{
	unsigned char*	keyPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(key.data()));
	unsigned char*	ivPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(iv.data()));
	
	// Destroy any existing context
	Cleanup();
	
	// Make sure the IV is big enough
	if (iv.capacity() < static_cast<unsigned int>(cipherObj.IVLength()))
		iv.resize(cipherObj.IVLength());
	
	fCipherObj = cipherObj;
	if (EVP_EncryptInit(&fContext,fCipherObj.Ptr(),keyPtr,ivPtr) != 1)
		throw TSSLErrorObj(kSSLCipherInitFailure);
	fIsInited = true;
	fHasAlgorithm = true;
}

//---------------------------------------------------------------------
// TEncryptContext::Update
//---------------------------------------------------------------------
void TEncryptContext::Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherNotInited);
	
	tempBuffer.resize(inBufferSize + fCipherObj.BlockSize());
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	if (EVP_EncryptUpdate(&fContext,tempBufferPtr,&tempBufferSize,inBufferPtr,inBufferSize) != 1)
		throw TSSLErrorObj(kSSLCipherUpdateFailure);
	if (tempBufferSize > 0)
	{
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
}

//---------------------------------------------------------------------
// TEncryptContext::Update
//---------------------------------------------------------------------
void TEncryptContext::Update (std::string& inBuffer, std::string& outBuffer)
{
	Inherited::Update(inBuffer,outBuffer);
}

//---------------------------------------------------------------------
// TEncryptContext::Update
//---------------------------------------------------------------------
void TEncryptContext::Update (TFileObj& inFileObj, TFileObj& outFileObj)
{
	Inherited::Update(inFileObj,outFileObj);
}

//---------------------------------------------------------------------
// TEncryptContext::Final
//---------------------------------------------------------------------
void TEncryptContext::Final (std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherNotInited);
	
	tempBuffer.resize(fCipherObj.BlockSize());
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	if (EVP_EncryptFinal(&fContext,tempBufferPtr,&tempBufferSize) != 1)
		throw TSSLErrorObj(kSSLCipherFinalFailure);
	if (tempBufferSize > 0)
	{
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
	
	fIsInited = false;
}

//---------------------------------------------------------------------
// TEncryptContext::Final
//---------------------------------------------------------------------
void TEncryptContext::Final (TFileObj& outFileObj)
{
	Inherited::Final(outFileObj);
}

//*********************************************************************
// Class TDecryptContext
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TDecryptContext::TDecryptContext ()
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TDecryptContext::~TDecryptContext ()
{
}

//---------------------------------------------------------------------
// TDecryptContext::Initialize
//---------------------------------------------------------------------
void TDecryptContext::Initialize (const TCipher& cipherObj,
								  std::string key,
								  std::string iv)
{
	unsigned char*	keyPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(key.data()));
	unsigned char*	ivPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(iv.data()));
	
	// Destroy any existing context
	Cleanup();
	
	// Make sure the IV is big enough
	if (iv.capacity() < static_cast<unsigned int>(cipherObj.IVLength()))
		iv.resize(cipherObj.IVLength());
	
	fCipherObj = cipherObj;
	if (EVP_DecryptInit(&fContext,fCipherObj.Ptr(),keyPtr,ivPtr) != 1)
		throw TSSLErrorObj(kSSLCipherInitFailure);
	fIsInited = true;
	fHasAlgorithm = true;
}

//---------------------------------------------------------------------
// TDecryptContext::Update
//---------------------------------------------------------------------
void TDecryptContext::Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherNotInited);
	
	tempBuffer.resize(inBufferSize + fCipherObj.BlockSize());
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	if (EVP_DecryptUpdate(&fContext,tempBufferPtr,&tempBufferSize,inBufferPtr,inBufferSize) != 1)
		throw TSSLErrorObj(kSSLCipherUpdateFailure);
	if (tempBufferSize > 0)
	{
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
}

//---------------------------------------------------------------------
// TDecryptContext::Update
//---------------------------------------------------------------------
void TDecryptContext::Update (std::string& inBuffer, std::string& outBuffer)
{
	Inherited::Update(inBuffer,outBuffer);
}

//---------------------------------------------------------------------
// TDecryptContext::Update
//---------------------------------------------------------------------
void TDecryptContext::Update (TFileObj& inFileObj, TFileObj& outFileObj)
{
	Inherited::Update(inFileObj,outFileObj);
}

//---------------------------------------------------------------------
// TDecryptContext::Final
//---------------------------------------------------------------------
void TDecryptContext::Final (std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLCipherNotInited);
	
	tempBuffer.resize(fCipherObj.BlockSize());
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	if (EVP_DecryptFinal(&fContext,tempBufferPtr,&tempBufferSize) != 1)
		throw TSSLErrorObj(kSSLCipherFinalFailure);
	if (tempBufferSize > 0)
	{
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
	
	fIsInited = false;
}

//---------------------------------------------------------------------
// TDecryptContext::Final
//---------------------------------------------------------------------
void TDecryptContext::Final (TFileObj& outFileObj)
{
	Inherited::Final(outFileObj);
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

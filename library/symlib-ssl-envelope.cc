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
#include "symlib-ssl-envelope.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TEnvelopeEncryptContext
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TEnvelopeEncryptContext::TEnvelopeEncryptContext ()
	:	fIsInited(false),
		fPKeyCount(0),
		fPKeyList(NULL),
		fPKeyPWList(NULL),
		fPKeyLengthList(NULL)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TEnvelopeEncryptContext::~TEnvelopeEncryptContext ()
{
	DestroyPKeyLists();
}

//---------------------------------------------------------------------
// TEnvelopeEncryptContext::Initialize
//---------------------------------------------------------------------
void TEnvelopeEncryptContext::Initialize (const TCipher& cipherObj, PKeyObjPtrList& pkeyObjPtrList)
{
	// Destroy any current context we might already have
	DestroyPKeyLists();
	fIV = "";
	
	// Setup our simple slots
	fCipher = cipherObj;
	fIV.resize(fCipher.MaxIVLength());
	
	// Allocate memory for our SSL arrays
	fPKeyCount = pkeyObjPtrList.size();
	fPKeyList = new EVP_PKEY*[fPKeyCount];
	fPKeyPWList = new unsigned char*[fPKeyCount];
	fPKeyLengthList = new int[fPKeyCount];
	
	// Plug key information into the arrays
	for (int x = 0; x < fPKeyCount; x++)
	{
		fPKeyList[x] = pkeyObjPtrList[x]->Ptr();
		fPKeyPWList[x] = new unsigned char[pkeyObjPtrList[x]->Size()];
		fPKeyLengthList[x] = 0;
	}
	
	// Seed the random number generator
	if (!TSSLEnvironment::PRNGIsValid())
		TSSLEnvironment::PRNGSeed(1024);
	
	// Now actually call the init routine
	if (EVP_SealInit(fCipherContext,const_cast<EVP_CIPHER*>(fCipher.Ptr()),fPKeyPWList,fPKeyLengthList,const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(fIV.data())),fPKeyList,fPKeyCount) == 0)
		throw TSSLErrorObj(kSSLEnvelopeInitFailure);
	
	fIsInited = true;
}

//---------------------------------------------------------------------
// TEnvelopeEncryptContext::Initialize
//---------------------------------------------------------------------
void TEnvelopeEncryptContext::Initialize (const TCipher& cipherObj, TPKeyObj& pkeyObj)
{
	PKeyObjPtrList		pkeyList;
	
	pkeyList.push_back(&pkeyObj);
	Initialize(cipherObj,pkeyList);
}

//---------------------------------------------------------------------
// TEnvelopeEncryptContext::Update
//---------------------------------------------------------------------
void TEnvelopeEncryptContext::Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLEnvelopeContextNotInited);
	
	// Init our temp buffer to hold the update result
	tempBuffer.resize(inBufferSize + fCipher.BlockSize());
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	
	// Call the update function
	if (EVP_SealUpdate(fCipherContext,tempBufferPtr,&tempBufferSize,inBufferPtr,inBufferSize) != 1)
		throw TSSLErrorObj(kSSLEnvelopeUpdateFailure);
	
	if (tempBufferSize > 0)
	{
		// Append the temp buffer to the outBuffer
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
}

//---------------------------------------------------------------------
// TEnvelopeEncryptContext::Update
//---------------------------------------------------------------------
void TEnvelopeEncryptContext::Update (const std::string& inBuffer, std::string& outBuffer)
{
	unsigned char*	inBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(inBuffer.data()));
	int				inBufferSize = inBuffer.length();
	
	Update(inBufferPtr,inBufferSize,outBuffer);
}

//---------------------------------------------------------------------
// TEnvelopeEncryptContext::Update
//---------------------------------------------------------------------
void TEnvelopeEncryptContext::Update (TFileObj& inFileObj, TFileObj& outFileObj)
{
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLEnvelopeContextNotInited);
	
	TUpdateMorphMixin::Update(inFileObj,outFileObj);
}

//---------------------------------------------------------------------
// TEnvelopeEncryptContext::Final
//---------------------------------------------------------------------
void TEnvelopeEncryptContext::Final (std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLEnvelopeContextNotInited);
	
	// Init our temp buffer to hold the final result
	tempBuffer.resize(fCipher.BlockSize());
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	
	// Call the final function
	EVP_SealFinal(fCipherContext,tempBufferPtr,&tempBufferSize);
	
	if (tempBufferSize > 0)
	{
		// Append the temp buffer to the outBuffer
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
	
	fIsInited = false;
}

//---------------------------------------------------------------------
// TEnvelopeEncryptContext::Final
//---------------------------------------------------------------------
void TEnvelopeEncryptContext::Final (TFileObj& outFileObj)
{
	std::string			tempBuffer;
	
	Final(tempBuffer);
	if (!tempBuffer.empty())
		outFileObj.Write(tempBuffer);
}

//---------------------------------------------------------------------
// TEnvelopeEncryptContext::NthEncryptedKey
//---------------------------------------------------------------------
std::string TEnvelopeEncryptContext::NthEncryptedKey (unsigned int n) const
{
	std::string		key;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLEnvelopeContextNotInited);
	
	if (n > static_cast<unsigned int>(fPKeyCount))
		throw TSSLErrorObj(kSSLEnvelopeInvalidKeyIndex);
	
	key.assign(reinterpret_cast<char*>(fPKeyPWList[n]),fPKeyLengthList[n]);
	
	return key;
}

//---------------------------------------------------------------------
// TEnvelopeEncryptContext::IV
//---------------------------------------------------------------------
std::string TEnvelopeEncryptContext::IV () const
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLEnvelopeContextNotInited);
	
	return fIV;
}

//---------------------------------------------------------------------
// TEnvelopeEncryptContext::DestroyPKeyLists (protected)
//---------------------------------------------------------------------
void TEnvelopeEncryptContext::DestroyPKeyLists ()
{
	for (int x = 0; x < fPKeyCount; x++)
	{
		if (fPKeyPWList[x])
		{
			if (fPKeyPWList[x])
				delete(fPKeyPWList[x]);
		}
	}
	
	fPKeyCount = 0;
	if (fPKeyList)
		delete(fPKeyList);
	if (fPKeyPWList)
		delete(fPKeyPWList);
	if (fPKeyLengthList)
		delete(fPKeyLengthList);
}

//*********************************************************************
// Class TEnvelopeDecryptContext
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TEnvelopeDecryptContext::TEnvelopeDecryptContext ()
	:	fIsInited(false)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TEnvelopeDecryptContext::~TEnvelopeDecryptContext ()
{
}

//---------------------------------------------------------------------
// TEnvelopeDecryptContext::Initialize
//---------------------------------------------------------------------
void TEnvelopeDecryptContext::Initialize (const TCipher& cipherObj,
										  const std::string& iv,
										  const std::string& encryptedKey,
										  TPKeyObj& pkeyObj)
{
	std::string		myIV(iv);
	unsigned char*	encryptedKeyPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(encryptedKey.data()));
	unsigned char*	ivPtr = NULL;
	
	fCipher = cipherObj;
	myIV.resize(TCipher::MaxIVLength());
	ivPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(myIV.data()));
	
	// Call the init function
	if (EVP_OpenInit(fCipherContext,const_cast<EVP_CIPHER*>(fCipher.Ptr()),encryptedKeyPtr,encryptedKey.length(),ivPtr,pkeyObj) == 0)
		throw TSSLErrorObj(kSSLEnvelopeInitFailure);
	
	fIsInited = true;
}

//---------------------------------------------------------------------
// TEnvelopeDecryptContext::Update
//---------------------------------------------------------------------
void TEnvelopeDecryptContext::Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLEnvelopeContextNotInited);
	
	// Prep the temp buffer
	tempBuffer.resize(inBufferSize + fCipher.BlockSize());
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	
	// Call the update function
	if (EVP_OpenUpdate(fCipherContext,tempBufferPtr,&tempBufferSize,inBufferPtr,inBufferSize) != 1)
		throw TSSLErrorObj(kSSLEnvelopeUpdateFailure);
	
	if (tempBufferSize > 0)
	{
		// Append the temp buffer to the outBuffer
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
}

//---------------------------------------------------------------------
// TEnvelopeDecryptContext::Update
//---------------------------------------------------------------------
void TEnvelopeDecryptContext::Update (std::string& inBuffer, std::string& outBuffer)
{
	unsigned char*	inBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(inBuffer.data()));
	int				inBufferSize = inBuffer.length();
	
	Update(inBufferPtr,inBufferSize,outBuffer);
}

//---------------------------------------------------------------------
// TEnvelopeDecryptContext::Update
//---------------------------------------------------------------------
void TEnvelopeDecryptContext::Update (TFileObj& inFileObj, TFileObj& outFileObj)
{
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLEnvelopeContextNotInited);
	
	TUpdateMorphMixin::Update(inFileObj,outFileObj);
}

//---------------------------------------------------------------------
// TEnvelopeDecryptContext::Final
//---------------------------------------------------------------------
void TEnvelopeDecryptContext::Final (std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	// Make sure we have a context
	if (!IsInited())
		throw TSSLErrorObj(kSSLEnvelopeContextNotInited);
	
	// Prep the temp buffer
	tempBuffer.resize(fCipher.BlockSize());
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	
	// Call the final function
	EVP_OpenFinal(fCipherContext,tempBufferPtr,&tempBufferSize);
	
	if (tempBufferSize > 0)
	{
		// Append the temp buffer to the outBuffer
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
	
	fIsInited = false;
}

//---------------------------------------------------------------------
// TEnvelopeDecryptContext::Final
//---------------------------------------------------------------------
void TEnvelopeDecryptContext::Final (TFileObj& outFileObj)
{
	std::string			tempBuffer;
	
	Final(tempBuffer);
	if (!tempBuffer.empty())
		outFileObj.Write(tempBuffer);
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

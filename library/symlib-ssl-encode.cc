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
#include "symlib-ssl-encode.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TSSLBase64
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLBase64::TSSLBase64 ()
	:	fIsInited(false)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSSLBase64::~TSSLBase64 ()
{
}

//---------------------------------------------------------------------
// TSSLBase64::Initialize
//---------------------------------------------------------------------
void TSSLBase64::Initialize ()
{
	_Init();
	fIsInited = true;
}

//---------------------------------------------------------------------
// TSSLBase64::Update
//---------------------------------------------------------------------
void TSSLBase64::Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	// Make sure we have a context
	if (!IsInited())
		Initialize();
	
	// Prep the temp buffer
	tempBuffer.resize(_CodedSize(inBufferSize));
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	
	// Perform the encoding
	tempBufferSize = _Update(tempBufferPtr,inBufferPtr,inBufferSize);
	
	if (tempBufferSize > 0)
	{
		// Append the temp buffer to outBuffer
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
}

//---------------------------------------------------------------------
// TSSLBase64::Update
//---------------------------------------------------------------------
void TSSLBase64::Update (std::string& inBuffer, std::string& outBuffer)
{
	unsigned char*	inBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(inBuffer.data()));
	int				inBufferSize = inBuffer.length();
	
	Update(inBufferPtr,inBufferSize,outBuffer);
}

//---------------------------------------------------------------------
// TSSLBase64::Update
//---------------------------------------------------------------------
void TSSLBase64::Update (TFileObj& inFileObj, TFileObj& outFileObj)
{
	// Make sure we have a context
	if (!IsInited())
		Initialize();
	
	TUpdateMorphMixin::Update(inFileObj,outFileObj);
}

//---------------------------------------------------------------------
// TSSLBase64::Final
//---------------------------------------------------------------------
void TSSLBase64::Final (std::string& outBuffer)
{
	std::string		tempBuffer;
	unsigned char*	tempBufferPtr = NULL;
	int				tempBufferSize = 0;
	
	// Make sure we have a context
	if (!IsInited())
		Initialize();
	
	// Prep the temp buffer
	tempBuffer.resize(_CodedSize(fContext.num));
	tempBufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tempBuffer.data()));
	
	// Call the final function
	tempBufferSize = _Final(tempBufferPtr);
	
	if (tempBufferSize > 0)
	{
		// Append the final bits to the outBuffer
		tempBuffer.resize(tempBufferSize);
		outBuffer.append(tempBuffer);
	}
	
	fIsInited = false;
}

//---------------------------------------------------------------------
// TSSLBase64::Final
//---------------------------------------------------------------------
void TSSLBase64::Final (TFileObj& outFileObj)
{
	std::string			tempBuffer;
	
	Final(tempBuffer);
	if (!tempBuffer.empty())
		outFileObj.Write(tempBuffer);
	
	fIsInited = false;
}

//*********************************************************************
// Class TEncodeContext
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TEncodeContext::TEncodeContext ()
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TEncodeContext::~TEncodeContext ()
{
}

//---------------------------------------------------------------------
// TEncodeContext::Encode
//---------------------------------------------------------------------
std::string TEncodeContext::Encode (const unsigned char* inBufferPtr, int inBufferSize)
{
	std::string		buffer;
	unsigned char*	bufferPtr = NULL;
	int				bufferSize = 0;
	
	// Prep the temp buffer
	buffer.resize(_CodedSize(inBufferSize));
	bufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buffer.data()));
	
	// Perform the encoding
	bufferSize = EVP_EncodeBlock(bufferPtr,inBufferPtr,inBufferSize);
	
	if (bufferSize > 0)
	{
		// Append the temp buffer to outBuffer
		buffer.resize(bufferSize);
	}
	
	return buffer;
}

//---------------------------------------------------------------------
// TEncodeContext::Encode
//---------------------------------------------------------------------
std::string TEncodeContext::Encode (const std::string& inBuffer)
{
	return Encode(reinterpret_cast<const unsigned char*>(inBuffer.data()),inBuffer.length());
}

//---------------------------------------------------------------------
// TEncodeContext::_Init (protected)
//---------------------------------------------------------------------
void TEncodeContext::_Init ()
{
	EVP_EncodeInit(&fContext);
}

//---------------------------------------------------------------------
// TEncodeContext::_CodedSize (protected)
//---------------------------------------------------------------------
int TEncodeContext::_CodedSize (int inSize)
{
	return EVP_ENCODE_LENGTH(inSize);
}

//---------------------------------------------------------------------
// TEncodeContext::_Update (protected)
//---------------------------------------------------------------------
int TEncodeContext::_Update (unsigned char* outPtr, unsigned char* inPtr, int inSize)
{
	int		outSize = 0;
	
	EVP_EncodeUpdate(&fContext,outPtr,&outSize,inPtr,inSize);
	
	return outSize;
}

//---------------------------------------------------------------------
// TEncodeContext::_Final (protected)
//---------------------------------------------------------------------
int TEncodeContext::_Final (unsigned char* outPtr)
{
	int		outSize = 0;
	
	EVP_EncodeFinal(&fContext,outPtr,&outSize);
	
	return outSize;
}

//*********************************************************************
// Class TDecodeContext
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TDecodeContext::TDecodeContext ()
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TDecodeContext::~TDecodeContext ()
{
}

//---------------------------------------------------------------------
// TDecodeContext::Decode
//---------------------------------------------------------------------
std::string TDecodeContext::Decode (unsigned char* inBufferPtr, int inBufferSize)
{
	std::string		buffer;
	unsigned char*	bufferPtr = NULL;
	int				bufferSize = 0;
	
	// Prep the temp buffer
	buffer.resize(_CodedSize(inBufferSize));
	bufferPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buffer.data()));
	
	// Perform the encoding
	bufferSize = EVP_DecodeBlock(bufferPtr,inBufferPtr,inBufferSize);
	
	if (bufferSize > 0)
	{
		// Append the temp buffer to outBuffer
		buffer.resize(bufferSize);
	}
	
	return buffer;
}

//---------------------------------------------------------------------
// TDecodeContext::Decode
//---------------------------------------------------------------------
std::string TDecodeContext::Decode (std::string& inBuffer)
{
	return Decode(const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(inBuffer.data())),inBuffer.length());
}

//---------------------------------------------------------------------
// TDecodeContext::_Init (protected)
//---------------------------------------------------------------------
void TDecodeContext::_Init ()
{
	EVP_DecodeInit(&fContext);
}

//---------------------------------------------------------------------
// TDecodeContext::_CodedSize (protected)
//---------------------------------------------------------------------
int TDecodeContext::_CodedSize (int inSize)
{
	return EVP_DECODE_LENGTH(inSize);
}

//---------------------------------------------------------------------
// TDecodeContext::_Update (protected)
//---------------------------------------------------------------------
int TDecodeContext::_Update (unsigned char* outPtr, unsigned char* inPtr, int inSize)
{
	int		outSize = 0;
	
	EVP_DecodeUpdate(&fContext,outPtr,&outSize,inPtr,inSize);
	
	return outSize;
}

//---------------------------------------------------------------------
// TDecodeContext::_Final (protected)
//---------------------------------------------------------------------
int TDecodeContext::_Final (unsigned char* outPtr)
{
	int		outSize = 0;
	
	EVP_DecodeFinal(&fContext,outPtr,&outSize);
	
	return outSize;
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

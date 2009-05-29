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

#if !defined(SYMLIB_SSL_ENVELOPE)
#define SYMLIB_SSL_ENVELOPE

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-ssl-util.h"
#include "symlib-ssl-cipher.h"
#include "symlib-ssl-pkey.h"

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
class TEnvelopeEncryptContext;
class TEnvelopeDecryptContext;

//---------------------------------------------------------------------
// Class TEnvelopeEncryptContext
//
// This class wraps the EVP_Sealxxx methods, which encrypts a message
// with a symmetric cipher seeded with a random key that is in turn
// encrypted with one or more public keys.
//
// In addition to supplying the same functionality as the original
// EVP_Sealxxx methods, this class supports encryption of entire
// files -- see the Update() methods.
//---------------------------------------------------------------------
class TEnvelopeEncryptContext : public TUpdateMorphMixin
{
	public:
		
		TEnvelopeEncryptContext ();
			// Constructor
	
	private:
		
		TEnvelopeEncryptContext (const TEnvelopeEncryptContext&) {}
			// Copy constructor not allowed
	
	public:
		
		virtual ~TEnvelopeEncryptContext ();
			// Destructor
		
		virtual void Initialize (const TCipher& algorithm, PKeyObjPtrList& pkeyObjPtrList);
			// Initializes the context with the given cipher algorithm
			// and list of public keys.  A random key for the cipher will be
			// generated and then encrypted separately with each public key.
			// Use NthEncryptedKey() to obtain each of those keys.  An IV will
			// also be generated; use the IV() method to obtain that value.
			// Note that due to TCipher construction options you can pass
			// either a TCipher object, the name of a cipher algorithm as
			// a std::string, or a EVP_CIPHER* as the algorithm argument.
			// OpenSSL functions:  EVP_SealInit
		
		virtual void Initialize (const TCipher& algorithm, TPKeyObj& pkeyObj);
			// Same as previous version but accepts only a single public key object.
		
		virtual void Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer);
			// Identical to TEncryptContext::Update().  Encrypts the contents
			// of inBufferPtr, which is inBufferSize in length, and concatenates
			// the results to outBuffer.
			// OpenSSL functions:  EVP_SealUpdate
		
		virtual void Update (const std::string& inBuffer, std::string& outBuffer);
			// Identical to TEncryptContext::Update().  Encrypts the contents
			// of inBuffer and concatenates the result to outBuffer.
		
		virtual void Update (TFileObj& inFileObj, TFileObj& outFileObj);
			// Encrypts the contents of the file pointed to by inFileObj,
			// concatenating the results into outFileObj.  outFileObj
			// will be created if it doesn't already exist.  outFileObj will
			// be left open when this method completes.  Note:  You must call
			// Final() on the output file to finish the process.
		
		virtual void Final (std::string& outBuffer);
			// Identical to TEncryptContext::Final().  Completes the encryption process
			// and concatenates the results to outBuffer.
			// OpenSSL functions:  EVP_SealFinal
		
		virtual void Final (TFileObj& outFileObj);
			// The last stage of encryption.  The final bits of data are
			// concatenated to the file pointed to by outFileObj.  After
			// this method completes, you must call Initialized() again
			// before reusing this context.  outFileObj must already be open
			// and writable, and this method leaves the file open for future
			// writing if necessary.
		
		virtual std::string NthEncryptedKey (unsigned int n) const;
			// Returns the nth key generated for the nth public key object
			// added to the context.  Valid only after Initialize() has
			// been called.
		
		virtual std::string IV () const;
			// Returns the IV used with the context.  Valid only after
			// Initialize() has been called.
	
	protected:
		
		virtual void DestroyPKeyLists ();
			// Tears down all SSL arrays within this object.
	
	public:
		
		// Accessors
		
		inline bool IsInited() const
			{ return fIsInited; }
		
		inline int PKeyCount () const
			{ return fPKeyCount; }
	
	protected:
		
		bool									fIsInited;
		TCipher									fCipher;
		TCipherContext							fCipherContext;
		std::string								fIV;
		int										fPKeyCount;
		EVP_PKEY**								fPKeyList;
		unsigned char**							fPKeyPWList;
		int*									fPKeyLengthList;
};

//---------------------------------------------------------------------
// Class TEnvelopeDecryptContext
//
// This class wraps the EVP_Openxxx methods, which decrypts a message
// encrypted with EVP_Sealxxx (TEnvelopeEncryptContext) methods.
//
// In addition to supplying the same functionality as the original
// EVP_Openxxx methods, this class supports encryption of entire
// files -- see the Update() methods.
//---------------------------------------------------------------------
class TEnvelopeDecryptContext : public TUpdateMorphMixin
{
	public:
		
		TEnvelopeDecryptContext ();
			// Constructor
	
	private:
		
		TEnvelopeDecryptContext (const TEnvelopeDecryptContext&) {}
			// Copy constructor not allowed
	
	public:
		
		virtual ~TEnvelopeDecryptContext ();
			// Destructor
		
		virtual void Initialize (const TCipher& algorithm,
								 const std::string& iv,
								 const std::string& encryptedKey,
								 TPKeyObj& pkeyObj);
			// Initializes the decryption context.  Note that due to TCipher
			// construction options you can pass either a TCipher object,
			// the name of a cipher algorithm as a std::string, or a EVP_CIPHER* as
			// the algorithm argument.  The iv argument should be as generated by
			// TEnvelopeEncryptContext::IV().  The encryptedKey argument should
			// be as returned by a call to TEnvelopeEncryptContext::NthEncryptedKey().
			// OpenSSL functions:  EVP_OpenInit
		
		virtual void Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer);
			// Identical to TDecryptContext::Update().  Decrypts the contents
			// of inBufferPtr, which is inBufferSize in length, and concatenates
			// the results to outBuffer.
			// OpenSSL functions:  EVP_OpenUpdate
		
		virtual void Update (std::string& inBuffer, std::string& outBuffer);
			// Identical to TDecryptContext::Update().  Decrypts the contents
			// of inBuffer and concatenates the result to outBuffer.
		
		virtual void Update (TFileObj& inFileObj, TFileObj& outFileObj);
			// Decrypts the contents of the file pointed to by inFileObj,
			// concatenating the results into outFileObj.  outFileObj
			// will be created if it doesn't already exist.  outFileObj will
			// be left open when this method completes.  Note:  You must call
			// Final() on the output file to finish the process.
		
		virtual void Final (std::string& outBuffer);
			// Identical to TDecryptContext::Final().  Completes the decryption process
			// and concatenates the results to outBuffer.
			// OpenSSL functions:  EVP_OpenFinal
		
		virtual void Final (TFileObj& outFileObj);
			// The last stage of decryption.  The final bits of data are
			// concatenated to the file pointed to by outFileObj.  After
			// this method completes, you must call Initialized() again
			// before reusing this context.  outFileObj must already be open
			// and writable, and this method leaves the file open for future
			// writing if necessary.
		
		// Accessors
		
		inline bool IsInited() const
			{ return fIsInited; }
	
	protected:
		
		bool									fIsInited;
		TCipher									fCipher;
		TCipherContext							fCipherContext;
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif

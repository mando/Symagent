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

#if !defined(SYMLIB_SSL_SIGN)
#define SYMLIB_SSL_SIGN

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-ssl-util.h"
#include "symlib-ssl-digest.h"
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
class TSignContextBase;
class TSignContext;
class TVerifyContext;

//---------------------------------------------------------------------
// Class TSignContextBase
//
// This is a base class implementing the algorithms surrounding the
// EVP_SignXXX and EVP_VerifyXXX routines.  Since virtually everything
// works the same, it makes sense to combine the logic into one class
// and implement only the differences in subclasses.
//
// Users should not directly instantiate this class.  Instead, use
// TSignContext or TVerifyContext.
//---------------------------------------------------------------------
class TSignContextBase : public TUpdateScanMixin
{
	public:
		
		TSignContextBase ();
			// Constructor
		
		TSignContextBase (const TSignContextBase& obj);
			// Copy constructor
		
		virtual ~TSignContextBase ();
			// Destructor
		
		virtual void Initialize (const TDigest& digestObj);
			// Initializes the context.  Note that due to TDigest construction
			// options you can pass either a TDigest object, the name of a
			// digest algorithm as a std::string, or a EVP_MD* as the argument.
		
		virtual void ReInitialize ();
			// Once you have initialized this object with Initialize() you can call this
			// method to reinitialize the context with the same algorithm.
		
		virtual void Update (const void* bufferPtr, unsigned int bufferSize);
			// Updates the context with the contents of bufferPtr, which
			// is bufferSize bytes in length.
		
		virtual void Update (const std::string& buffer);
			// Updates the context with the contents of the buffer object.
		
		virtual void Update (TFileObj& fileObj);
			// Updates the context with the contents of the file referenced
			// by the argument.  If the file is not open then it will be
			// temporarily opened with read-only permissions, then closed
			// before the method returns.  If it is already open then read
			// permission must be allowed.  Also, if the file was already
			// opened, then the current file position is preserved.
		
		// Accessors
		
		inline bool IsInited () const
			{ return fIsInited; }
		
		inline bool HasAlgorithm () const
			{ return fHasDigestObj; }
		
		inline operator const EVP_MD* () const
			{ return fDigestObj.Ptr(); }
		
		inline operator EVP_MD_CTX* ()
			{ return fDigestContextObj.Ptr(); }
		
		inline operator const EVP_MD_CTX* () const
			{ return fDigestContextObj.Ptr(); }
	
	protected:
		
		virtual void _Init () = 0;
			// Performs whatever initializations are necessary.
			// Subclasses must override this method.
		
		virtual void _Update (const void* bufferPtr, unsigned int bufferSize) = 0;
			// // Updates the context with the contents of bufferPtr, which
			// is bufferSize bytes in length.  Subclasses must override
			// this method.
	
	protected:
		
		bool									fIsInited;
		bool									fHasDigestObj;
		TDigest									fDigestObj;
		TDigestContext							fDigestContextObj;
};

//---------------------------------------------------------------------
// Class TSignContext
//
// This class wraps the EVP_Signxxx methods, which perform message
// digest computation and then 'signs' the result with the private
// key component of a public key object.
//
// In addition to supplying the same functionality as the original
// EVP_Signxxx methods, this class supports signing an entire
// file -- see the Update() methods.
//
/* Example Usage:

		TSignContext			signContextObj;
		TPKeyObj				publicKeyObj;
		TFileObj				publicKeyFileObj("priv.key");
		std::string				message("This is a test message");
		std::string				signature;
		
		// Load the public key from a file
		publicKeyObj.ReadPrivateKeyFromFile(publicKeyFileObj);
		
		// Initialize the context
		signContextObj.Initialize("MD5");
		
		// Push the message through the context
		signContextObj.Update(message);
		
		// Get the signature
		signature = signContextObj.GetSignature(publicKeyObj);
		
		// Echo the message and signature
		cout << "Original message: " << message << endl;
		cout << "Signature: " << signature.AsBase64Encoded() << endl;
*/
//---------------------------------------------------------------------
class TSignContext : public TSignContextBase
{
	private:
		
		typedef		TSignContextBase			Inherited;
		
	public:
		
		TSignContext ();
			// Constructor
		
		TSignContext (const TSignContext& obj);
			// Copy constructor
		
		virtual ~TSignContext ();
			// Destructor
		
		virtual std::string Final (TPKeyObj& pkeyObj);
			// Completes the update of the current context and signs it
			// with the private key portion of the given public key object.
			// Returns the signature.
			// OpenSSL functions:  EVP_SignFinal
		
		inline std::string GetSignature (TPKeyObj& pkeyObj)
			{ return Final(pkeyObj); }
	
	protected:
		
		virtual void _Init ();
			// Override.
			// OpenSSL functions:  EVP_SignInit
		
		virtual void _Update (const void* bufferPtr, unsigned int bufferSize);
			// Override.
			// OpenSSL functions:  EVP_SignUpdate
};

//---------------------------------------------------------------------
// Class TVerifyContext
//
// This class wraps the EVP_Verifyxxx methods, which verify a signature
// of a message against the public component of a public key object.
//
// In addition to supplying the same functionality as the original
// EVP_Verifyxxx methods, this class supports the verification of an entire
// file -- see the Update() methods.
//
/* Example Usage:

		TVerifyContext			verifyContextObj;
		TPKeyObj				publicKeyObj;
		TFileObj				publicKeyFileObj("pub.key");
		std::string				message("This is a test message");
		std::string				signature;
		bool					verified = false;
		
		// Load the public key from a file
		publicKeyObj.ReadPublicKeyFromFile(publicKeyFileObj);
		
		// Initialize the context
		verifyContextObj.Initialize("MD5");
		
		// Push the message through the context
		verifyContextObj.Update(message);
		
		// Verify the computed signature against the given signature.
		// Note that the signature variable must have been populated
		// elsewhere.  This example won't work as-is.
		verified = verifyContextObj.VerifySignature(signature,publicKeyObj);
		
		// Echo the message and the result
		cout << "Original message: " << message << endl;
		if (verified)
			cout << "Signature verified!" << endl;
		else
			cout << "Signature DOES NOT verify." << endl;
*/
//---------------------------------------------------------------------
class TVerifyContext : public TSignContextBase
{
	private:
		
		typedef		TSignContextBase			Inherited;
		
	public:
		
		TVerifyContext ();
			// Constructor
		
		TVerifyContext (const TVerifyContext& obj);
			// Copy constructor
		
		virtual ~TVerifyContext ();
			// Destructor
		
		virtual bool Final (std::string& signature, TPKeyObj& pkeyObj);
			// Completes the update of the current context and compares the resulting
			// signature, using the public portion of the given public key object,
			// with the given signature.  Returns a boolean indicating whether the
			// signature verifies correctly or not.
			// OpenSSL functions:  EVP_VerifyFinal
		
		inline bool VerifySignature (std::string& signature, TPKeyObj& pkeyObj)
			{ return Final(signature,pkeyObj); }
	
	protected:
		
		virtual void _Init ();
			// Override.
			// OpenSSL functions:  EVP_VerifyInit
		
		virtual void _Update (const void* bufferPtr, unsigned int bufferSize);
			// Override.
			// OpenSSL functions:  EVP_VerifyUpdate
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif

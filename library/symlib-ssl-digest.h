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

#if !defined(SYMLIB_SSL_DIGEST)
#define SYMLIB_SSL_DIGEST

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-ssl-util.h"

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
class TDigest;
class TDigestContext;

//---------------------------------------------------------------------
// Class TDigest
//
// This class wraps OpenSSL EVP_MD objects.  Coercion operators
// supply conversions to EVP_MD* so this object can be used
// as in function calls that require EVP_MD* arguments.
//---------------------------------------------------------------------
class TDigest
{
	public:
		
		TDigest ();
			// Constructor
		
		TDigest (const char* digestName);
			// Constructor
		
		TDigest (const EVP_MD* algoPtr);
			// Constructor
		
		TDigest (const TDigest& obj);
			// Copy constructor
		
		virtual ~TDigest ();
			// Destructor
		
		virtual void Set (const EVP_MD* algoPtr);
			// Sets the current algorithm to the argument.
		
		virtual void Set (const std::string& digestName);
			// Sets the current algorithm to the given name.
			// OpenSSL functions: EVP_get_digestbyname
		
		virtual void Set (int type);
			// Sets the current algorithm to the given type.
			// OpenSSL functions: EVP_get_digestbynid
		
		inline const std::string Name () const
			{ return ShortName(); }
		
		virtual const std::string ShortName () const;
			// Returns the short name of the current algorithm.
			// OpenSSL functions: EVP_MD_type, OBJ_nid2sn
		
		virtual const std::string LongName () const;
			// Returns the long name of the current algorithm.
			// OpenSSL functions: EVP_MD_type, OBJ_nid2ln
		
		virtual int Type () const;
			// Returns the type of the current algorithm.
			// OpenSSL functions: EVP_MD_type
		
		virtual int PublicKeyTypeID () const;
			// Returns the type of the associated public key
			// signing algorithm.
			// OpenSSL functions: EVP_MD_pkey_type
		
		virtual int Size () const;
			// Returns the number of bytes used by the current
			// algorithm.
			// OpenSSL functions: EVP_MD_size
		
		virtual int BlockSize () const;
			// Returns the block size used by the current algorithm,
			// in bytes.
			// OpenSSL functions: EVP_MD_block_size
		
		static inline int MaxDigestSize ()
			{ return EVP_MAX_MD_SIZE; }
			// Maximum number of bytes that will be used by the
			// current algorithm.
		
		// Accessors
		
		inline bool IsInited () const
			{ return (fDigestPtr != NULL); }
		
		inline const EVP_MD* Ptr () const
			{ return fDigestPtr; }
		
		inline operator const EVP_MD* () const
			{ return Ptr(); }
	
	protected:
		
		const EVP_MD*							fDigestPtr;
};

//---------------------------------------------------------------------
// Class TDigestContext
//
// This class wraps OpenSSL EVP_MD_CTX objects.  Coercion operators
// supply conversions to EVP_MD_CTX* so this object can be used
// as in function calls that require EVP_MD_CTX* arguments.
//
// In addition to supplying the same functionality as the original
// EVP_MD_CTX environment, this class can computate the message
// digest of entire files -- see the Update() methods.
//
/* Example Usage:

		TDigestContext			digestContextObj;
		std::string				message("This is a test message");
		std::string				digestValue;
		
		// Initialize the context
		digestContextObj.Initialize("MD5");
		
		// Push the message through the context
		digestContextObj.Update(message);
		
		// Get the final digest value
		digestValue = digestContextObj.Final();
		
		// Echo the message and digest value
		cout << "Original message: " << message << endl;
		cout << "Digest Value: " << digestValue.AsBase64Encoded() << endl;
*/
//---------------------------------------------------------------------
class TDigestContext : public TUpdateScanMixin
{
	public:
		
		TDigestContext ();
			// Constructor
		
		TDigestContext (const TDigestContext& obj);
			// Copy constructor
			// OpenSSL functions: EVP_MD_CTX_copy
		
		virtual ~TDigestContext ();
			// Destructor
		
		virtual void Initialize (const TDigest& digestObj);
			// Initializes the digest.  Note that due to TDigest construction
			// options you can pass either a TDigest object, the name of a
			// digest algorithm as a std::string, or a EVP_MD* as the argument.
			// OpenSSL functions: EVP_DigestInit
		
		virtual void ReInitialize ();
			// Once you have initialized this object with Initialize() you can call this
			// method to reinitialize the context with the same algorithm.
			// OpenSSL functions: EVP_DigestInit
		
		virtual void Update (const void* bufferPtr, unsigned int bufferSize);
			// Updates the digest with the contents of bufferPtr, which
			// is bufferSize bytes in length.
			// OpenSSL functions: EVP_DigestUpdate
		
		virtual void Update (const std::string& buffer);
			// Updates the digest with the contents of the buffer object.
		
		virtual void Update (TFileObj& fileObj);
			// Updates the digest with the contents of the file referenced
			// by the argument.
		
		virtual std::string Final ();
			// Returns the final digest value.
			// OpenSSL functions: EVP_DigestFinal
		
		virtual std::string Name () const;
			// Returns the name of the current algorithm.
		
		virtual int Type () const;
			// Returns the type of the current algorithm.
		
		virtual int PublicKeyTypeID () const;
			// Returns the type of the associated public key
			// signing algorithm.
		
		virtual int Size () const;
			// Returns the number of bytes used by the current
			// algorithm.
		
		virtual int BlockSize () const;
			// Returns the block size used by the current algorithm,
			// in bytes.
		
		static inline int MaxDigestSize ()
			{ return EVP_MAX_MD_SIZE; }
			// Maximum number of bytes that will be used by the
			// current algorithm.
		
		static void LoadAllAlgorithms ();
			// Ensures that all message digest algorithms are loaded.
		
		static void GetAllAlgorithmNames (StdStringList& digestNameList);
			// Destructively modifies the argument to contain a sorted
			// list of all available digest algorithm names.
			// OpenSSL functions: EVP_MD_type
		
		// Accessors
		
		inline bool IsInited () const
			{ return fIsInited; }
		
		inline bool HasAlgorithm () const
			{ return fHasAlgorithm; }
		
		inline EVP_MD_CTX* Ptr ()
			{ return &fContext; }
		
		inline const EVP_MD_CTX* Ptr () const
			{ return &fContext; }
		
		inline operator EVP_MD_CTX* ()
			{ return Ptr(); }
		
		inline operator const EVP_MD_CTX* () const
			{ return Ptr(); }
	
	protected:
		
		bool									fIsInited;
		bool									fHasAlgorithm;
		EVP_MD_CTX								fContext;
		TDigest									fAlgorithm;
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif

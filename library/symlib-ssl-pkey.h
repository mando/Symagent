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

#if !defined(SYMLIB_SSL_PUBLIC_KEY)
#define SYMLIB_SSL_PUBLIC_KEY

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-ssl-util.h"
#include "symlib-ssl-cipher.h"

#include <vector>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TPKeyObj;
class TPKeyObjPtrList;
#if !defined(NO_RSA)
	class TRSAObj;
#endif
#if !defined(NO_DSA)
	class TDSAObj;
#endif
#if !defined(NO_DH)
	class TDHObj;
#endif

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef		std::vector<TPKeyObj*>				PKeyObjPtrList;
typedef		PKeyObjPtrList::iterator			PKeyObjPtrList_iter;
typedef		PKeyObjPtrList::const_iterator		PKeyObjPtrList_const_iter;

//---------------------------------------------------------------------
// Class TPKeyObj
//---------------------------------------------------------------------
class TPKeyObj
{
	public:
		
		TPKeyObj ();
			// Constructor
		
		TPKeyObj (const EVP_PKEY* evpPkeyPtr);
			// Constructor.  Note that this does not duplicate the EVP_PKEY
			// structure, it only increments the structure's reference count.
		
		#if !defined(NO_RSA)
			TPKeyObj (TRSAObj& rsaAlgoObj);
				// Constructor
				// OpenSSL functions:  EVP_PKEY_set1_RSA
		#endif
		
		#if !defined(NO_DSA)
			TPKeyObj (TDSAObj& dsaAlgoObj);
				// OpenSSL functions:  EVP_PKEY_set1_DSA
				// Constructor
		#endif
		
		#if !defined(NO_DH)
			TPKeyObj (TDHObj& dhAlgoObj);
				// Constructor
				// OpenSSL functions:  EVP_PKEY_set1_DH
		#endif
		
		TPKeyObj (const TPKeyObj& obj);
			// Copy constructor.  Note that this does not duplicate the EVP_PKEY
			// structure in the argument, it only increments the structure's
			// reference count.
		
		virtual ~TPKeyObj ();
			// Destructor
		
		virtual std::string Encrypt (const std::string& value);
			// Encrypts the argument with the current key.  This is typically used to
			// encrypt a randomly-generated key which is used in a symmetric cipher.
			// OpenSSL functions:  EVP_PKEY_encrypt
		
		virtual std::string Decrypt (const std::string& value);
			// Decrypts the argument with the current key, which must
			// contain a private key component.    This is typically used to
			// encrypt a randomly-generated key which is used in a symmetric
			// cipher.
			// OpenSSL functions:  EVP_PKEY_decrypt
		
		virtual std::string PublicKey ();
			// Returns the public key component of the current object
			// in a temporary buffer object.
			// OpenSSL functions:  i2d_PublicKey
		
		virtual std::string PrivateKey ();
			// Returns the private key component of the current object
			// in a temporary buffer object.
			// OpenSSL functions:  i2d_PrivateKey
		
		virtual void SetPublicKey (int keyType, const std::string& publicKey);
			// Sets the public key component of this object to the given
			// key type and data.  The publicKey is the same as returned
			// by the PublicKey() method.
			// OpenSSL functions:  d2i_PublicKey
		
		virtual void SetPrivateKey (int keyType, const std::string& privateKey);
			// Sets the private key component of this object to the given
			// key type and data.  The privateKey is the same as returned
			// by the PrivateKey() method.
			// OpenSSL functions:  d2i_PrivateKey
		
		virtual void SetKey (EVP_PKEY* evpPkeyPtr);
			// Sets the public key component of this object from the argument.
			// Note that this does not duplicate the EVP_PKEY structure in
			// the argument, it only increments the structure's reference count.
		
		#if !defined(NO_RSA)
			virtual void SetKey (TRSAObj& rsaAlgoObj);
				// Sets the public key component of this object from the argument.
				// Note that this does not duplicate the EVP_PKEY structure in
				// the argument, it only increments the structure's reference count.
				// OpenSSL functions:  EVP_PKEY_set1_RSA
		#endif
		
		#if !defined(NO_DSA)
			virtual void SetKey (TDSAObj& dsaAlgoObj);
				// Sets the public key component of this object from the argument.
				// Note that this does not duplicate the EVP_PKEY structure in
				// the argument, it only increments the structure's reference count.
				// OpenSSL functions:  EVP_PKEY_set1_DSA
		#endif
		
		#if !defined(NO_DA)
			virtual void SetKey (TDHObj& dhAlgoObj);
				// Sets the public key component of this object from the argument.
				// Note that this does not duplicate the EVP_PKEY structure in
				// the argument, it only increments the structure's reference count.
				// OpenSSL functions:  EVP_PKEY_set1_DH
		#endif
		
		virtual void WritePublicKeyToFile (TFileObj& pkeyFileObj);
			// Writes the public key component of the current object
			// to the given file. The destination file cannot exist
			// before this function is called.
			// OpenSSL functions:  PEM_write_PUBKEY
		
		virtual void ReadPublicKeyFromFile (TFileObj& pkeyFileObj);
			// Reads the public key file indicated by the argument into
			// the current object, destroying any existing information here.
			// OpenSSL functions:  PEM_read_PUBKEY
		
		virtual void WritePrivateKeyToFile (TFileObj& pkeyFileObj);
			// Writes the private key component of the current object
			// to the given file in PKCS#8 PrivateKeyInfo (unencrypted)format.
			// The destination file cannot exist before this function is called.
			// OpenSSL functions:  PEM_write_PKCS8PrivateKey
		
		virtual void WritePrivateKeyToFile (TFileObj& pkeyFileObj,
											TCipher& cipherObj,
											std::string passphrasePrompt = "",
											std::string passphrase = "");
			// Writes the private key component of the current object
			// to the given file in PKCS#8 EncryptedPrivateKeyInfo format.
			// If passphrasePrompt is not empty then it is used as the prompt
			// to the user for their passphrase; otherwise, if passphrase is
			// not empty then it is used as the encryption key.  If both
			// arguments are empty then OpenSSL will request the passphrase
			// using the default prompt (see TSSLEnvironment::DefaultPasswordPrompt()).
			// The destination file cannot exist before this function is called.
			// OpenSSL functions:  PEM_write_PKCS8PrivateKey
		
		virtual void ReadPrivateKeyFromFile (TFileObj& pkeyFileObj,
											 std::string passphrasePrompt = "",
											 std::string passphrase = "");
			// Reads the private and public key components from the file
			// indicated by pkeyFileObj.  The file contents may be either
			// encrypted or unencrypted.  If passphrasePrompt is not empty then
			// it is used as the prompt to the user for their passphrase; otherwise,
			// if passphrase is not empty then it is used as the encryption key.  If both
			// arguments are empty then OpenSSL will request the passphrase using the
			// default prompt (see TSSLEnvironment::DefaultPasswordPrompt()).  The file
			// information is loaded into the current object, destroying any existing key
			// already loaded.
			// OpenSSL functions:  PEM_read_PKCS8PrivateKey
		
		virtual int Type () const;
			// Returns the specific type of current key.  Possible return values
			// include all EVP_PKEY_RSAxxx, EVP_PKEY_DSAxxx and EVP_PKEY_DHxxx
			// variations.
		
		virtual int GeneralType () const;
			// Returns the general type of current key.  Possible return values are
			// EVP_PKEY_RSA, EVP_PKEY_DSA and EVP_PKEY_DH.
		
		virtual int BitSize () const;
			// If the current algorithm is RSA, returns the number of
			// bits used in the modulus.  If DSA, returns the number of
			// bits in the p parameter.  Returns zero for all other
			// algorithms.
			// OpenSSL functions:  EVP_PKEY_bits
		
		virtual int Size () const;
			// This appears to return the number of bytes used by BitSize().
			// Maybe not, though.
			// OpenSSL functions:  EVP_PKEY_size
		
		static int TypeFromNID (int nid);
			// Translates a specific object NID, representing a specific
			// instance of one of the many EVP_PKEY_RSAxxx, EVP_PKEY_DSAxxx,
			// or EVP_PKEY_DHxxx objects, to a general type ID.  Possible
			// return values are EVP_PKEY_RSA, EVP_PKEY_DSA and EVP_PKEY_DH.
			// OpenSSL functions:  EVP_PKEY_type
	
	protected:
		
		virtual void Setup ();
			// Resets our internal state.
			// OpenSSL functions:  EVP_PKEY_new
		
		virtual void Cleanup ();
			// Resets our object to NULL values.
			// OpenSSL functions:  EVP_PKEY_free
	
	public:
		
		// Accessors
		
		inline bool IsSet() const
			{ return (fPKeyPtr != NULL); }
		
		inline const EVP_PKEY* Ptr () const
			{ return fPKeyPtr; }
		
		inline EVP_PKEY* Ptr ()
			{ return fPKeyPtr; }
		
		inline operator const EVP_PKEY* () const
			{ return fPKeyPtr; }
		
		inline operator EVP_PKEY* ()
			{ return fPKeyPtr; }
	
	protected:
		
		EVP_PKEY*								fPKeyPtr;
};

#if !defined(NO_RSA)
	//---------------------------------------------------------------------
	// Class TRSAObj
	//---------------------------------------------------------------------
	class TRSAObj : public TPKeyObj
	{
		private:
			
			typedef		TPKeyObj			Inherited;
		
		public:
			
			TRSAObj ();
				// Constructor
		
			TRSAObj (const RSA* rsaPtr);
				// Constructor.  Note that this does not duplicate the RSA
				// structure, it only increments the structure's reference count.
				// OpenSSL functions:  EVP_PKEY_set1_RSA
			
			TRSAObj (const TRSAObj& obj);
				// Copy constructor.  Note that this does not duplicate the RSA
				// structure in the argument, it only increments the structure's
				// reference count.
				// OpenSSL functions:  EVP_PKEY_set1_RSA
			
			virtual ~TRSAObj ();
				// Destructor
				// OpenSSL functions:  RSA_free
			
			virtual void GenerateKeys (int modulusInBits, int exponent);
				// Creates a new RSA public/private key pair using the
				// parameters provided.
				// OpenSSL functions:  RSA_generate_key, EVP_PKEY_set1_RSA
			
			virtual std::string PublicKey ();
				// Returns the public key component of the current object
				// in a temporary buffer object.
				// OpenSSL functions:  i2d_RSAPublicKey
			
			virtual std::string PrivateKey ();
				// Returns the private key component of the current object
				// in a temporary buffer object.
				// OpenSSL functions:  i2d_RSAPrivateKey
			
			virtual void SetPublicKey (const std::string& publicKey);
				// Sets the public key component of this object to the given
				// data.  The publicKey is the same as returned by the
				// PublicKey() method.
				// OpenSSL functions:  d2i_RSAPublicKey, EVP_PKEY_set1_RSA
			
			virtual void SetPrivateKey (const std::string& privateKey);
				// Sets the private key component of this object to the given
				// data.  The privateKey is the same as returned by the
				// PrivateKey() method.
				// OpenSSL functions:  d2i_RSAPrivateKey, EVP_PKEY_set1_RSA
			
			virtual void WritePublicKeyToFile (TFileObj& pkeyFileObj);
				// Writes the public key component of the current object
				// to the given file. The destination file cannot exist
				// before this function is called.
				// OpenSSL functions:  PEM_write_RSAPublicKey
			
			virtual void ReadPublicKeyFromFile (TFileObj& pkeyFileObj);
				// Reads the public key file indicated by the argument into
				// the current object, destroying any existing information here.
				// OpenSSL functions:  PEM_read_RSAPublicKey, EVP_PKEY_set1_RSA
			
			virtual void WritePrivateKeyToFile (TFileObj& pkeyFileObj);
				// Writes the private key component of the current object
				// to the given file in PKCS#8 PrivateKeyInfo (unencrypted)format.
				// The destination file cannot exist before this function is called.
				// OpenSSL functions:  PEM_write_RSAPrivateKey
			
			virtual void WritePrivateKeyToFile (TFileObj& pkeyFileObj,
												TCipher& cipherObj,
												std::string passphrasePrompt = "",
												std::string passphrase = "");
				// Writes the private key component of the current object
				// to the given file in PKCS#8 EncryptedPrivateKeyInfo format.
				// If passphrasePrompt is not empty then it is used as the prompt
				// to the user for their passphrase; otherwise, if passphrase is
				// not empty then it is used as the encryption key.  If both
				// arguments are empty then OpenSSL will request the passphrase
				// using the default prompt (see TSSLEnvironment::DefaultPasswordPrompt()).
				// The destination file cannot exist before this function is called.
				// OpenSSL functions:  PEM_write_RSAPrivateKey
			
			virtual void ReadPrivateKeyFromFile (TFileObj& pkeyFileObj,
												 std::string passphrasePrompt = "",
												 std::string passphrase = "");
				// Reads the private and public key components from the file
				// indicated by pkeyFileObj.  The file contents may be either
				// encrypted or unencrypted.  If passphrasePrompt is not empty then
				// it is used as the prompt to the user for their passphrase; otherwise,
				// if passphrase is not empty then it is used as the encryption key.  If both
				// arguments are empty then OpenSSL will request the passphrase using the
				// default prompt (see TSSLEnvironment::DefaultPasswordPrompt()).  The file
				// information is loaded into the current object, destroying any existing key
				// already loaded.
				// OpenSSL functions:  PEM_read_RSAPrivateKey, EVP_PKEY_set1_RSA
		
		protected:
			
			virtual void Cleanup ();
				// Resets our object to NULL values.
				// OpenSSL functions:  RSA_free
		
		public:
			
			// Accessors
			
			inline bool IsSet() const
				{ return (fInternal != NULL); }
			
			inline operator RSA* ()
				{ return fInternal; }
			
			inline operator const RSA* () const
				{ return fInternal; }
		
		protected:
			
			RSA*									fInternal;
	};
#endif

//---------------------------------------------------------------------
// Class TDSAObj
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	class TDSAObj : public TPKeyObj
	{
		private:
			
			typedef		TPKeyObj			Inherited;
		
		public:
			
			TDSAObj ();
				// Constructor
		
			TDSAObj (const DSA* dsaPtr);
				// Constructor.  Note that this does not duplicate the DSA
				// structure, it only increments the structure's reference count.
				// OpenSSL functions:  EVP_PKEY_set1_DSA
			
			TDSAObj (const TDSAObj& obj);
				// Copy constructor.  Note that this does not duplicate the DSA
				// structure in the argument, it only increments the structure's
				// reference count.
				// OpenSSL functions:  EVP_PKEY_set1_DSA
			
			virtual ~TDSAObj ();
				// Destructor
				// OpenSSL functions:  DSA_free
			
			virtual void GenerateKeys (int primeLengthInBits);
				// Creates a new DSA public/private key pair using the
				// parameter provided.
				// OpenSSL functions:  DSA_generate_parameters, EVP_PKEY_set1_DSA
			
			virtual std::string PublicKey ();
				// Returns the public key component of the current object
				// in a temporary buffer object.
				// OpenSSL functions:  i2d_DSAPublicKey
			
			virtual std::string PrivateKey ();
				// Returns the private key component of the current object
				// in a temporary buffer object.
				// OpenSSL functions:  i2d_DSAPrivateKey
			
			virtual void SetPublicKey (const std::string& publicKey);
				// Sets the public key component of this object to the given
				// data.  The publicKey is the same as returned by the
				// PublicKey() method.
				// OpenSSL functions:  d2i_DSAPublicKey, EVP_PKEY_set1_DSA
			
			virtual void SetPrivateKey (const std::string& privateKey);
				// Sets the private key component of this object to the given
				// data.  The privateKey is the same as returned by the
				// PrivateKey() method.
				// OpenSSL functions:  d2i_DSAPrivateKey, EVP_PKEY_set1_DSA
			
			virtual void WritePrivateKeyToFile (TFileObj& pkeyFileObj);
				// Writes the private key component of the current object
				// to the given file in PKCS#8 PrivateKeyInfo (unencrypted)format.
				// The destination file cannot exist before this function is called.
				// OpenSSL functions:  PEM_write_DSAPrivateKey
			
			virtual void WritePrivateKeyToFile (TFileObj& pkeyFileObj,
												TCipher& cipherObj,
												std::string passphrasePrompt = "",
												std::string passphrase = "");
				// Writes the private key component of the current object
				// to the given file in PKCS#8 EncryptedPrivateKeyInfo format.
				// If passphrasePrompt is not empty then it is used as the prompt
				// to the user for their passphrase; otherwise, if passphrase is
				// not empty then it is used as the encryption key.  If both
				// arguments are empty then OpenSSL will request the passphrase
				// using the default prompt (see TSSLEnvironment::DefaultPasswordPrompt()).
				// The destination file cannot exist before this function is called.
				// OpenSSL functions:  PEM_write_DSAPrivateKey
			
			virtual void ReadPrivateKeyFromFile (TFileObj& pkeyFileObj,
												 std::string passphrasePrompt = "",
												 std::string passphrase = "");
				// Reads the private and public key components from the file
				// indicated by pkeyFileObj.  The file contents may be either
				// encrypted or unencrypted.  If passphrasePrompt is not empty then
				// it is used as the prompt to the user for their passphrase; otherwise,
				// if passphrase is not empty then it is used as the encryption key.  If both
				// arguments are empty then OpenSSL will request the passphrase using the
				// default prompt (see TSSLEnvironment::DefaultPasswordPrompt()).  The file
				// information is loaded into the current object, destroying any existing key
				// already loaded.
				// OpenSSL functions:  PEM_read_DSAPrivateKey, EVP_PKEY_set1_DSA
		
		protected:
			
			virtual void Cleanup ();
				// Resets our object to NULL values.
				// OpenSSL functions:  DSA_free
		
		public:
			
			// Accessors
			
			inline bool IsSet() const
				{ return (fInternal != NULL); }
			
			inline operator DSA* ()
				{ return fInternal; }
			
			inline operator const DSA* () const
				{ return fInternal; }
		
		protected:
			
			DSA*									fInternal;
	};
#endif

//---------------------------------------------------------------------
// Class TDHObj
//---------------------------------------------------------------------
#if !defined(NO_DH)
	class TDHObj : public TPKeyObj
	{
		private:
			
			typedef		TPKeyObj			Inherited;
		
		public:
			
			TDHObj ();
				// Constructor
		
			TDHObj (const DH* daPtr);
				// Constructor.  Note that this does not duplicate the DH
				// structure, it only increments the structure's reference count.
				// OpenSSL functions:  EVP_PKEY_set1_DH
			
			TDHObj (const TDHObj& obj);
				// Copy constructor.  Note that this does not duplicate the DH
				// structure in the argument, it only increments the structure's
				// reference count.
				// OpenSSL functions:  EVP_PKEY_set1_DH
			
			virtual ~TDHObj ();
				// Destructor
				// OpenSSL functions:  DH_free
			
			virtual void GenerateParameters (int primeLengthInBits, int generator);
				// Generates a new Diffie-Hellman public and private key with
				// random components.  GenerateKeys() must be called to
				// complete the key generation process.
				// OpenSSL functions:  DH_generate_parameters, DH_check, DH_generate_key
			
			virtual void SetParameters (const TBigNumBuffer& p, const TBigNumBuffer& g);
				// Generates a new Diffie-Hellman public and private key with
				// predetermined p and g values -- necessary if you need to create
				// a shared secret with someone else.  GenerateKeys() must
				// be called to complete the key generation process.
				// OpenSSL functions:  DH_new, DH_check, DH_generate_key
			
			virtual void SetParameters (const std::string& parameters);
				// Sets the parameters for the current object from the given argument,
				// which should be constructed as if it was the result from a call
				// to Parameters().  GenerateKeys() nees to be called with the
				// other's public key value in order to compute the shared
				// secret key.
				// OpenSSL functions:  d2i_DHparams, EVP_PKEY_set1_DH
			
			virtual void SetParameters (TFileObj& pkeyFileObj);
				// Reads the Diffie-Hellman parameters from the file indicated
				// by the argument, destroying any information already loaded
				// into this object.  This method can be used instead of either
				// GenerateParameters() or SetParameters(), which
				// also means that GenerateKeys() needs to be called with the
				// other's public key value in order to compute the shared secret key.
				// OpenSSL functions:  PEM_read_DHparams, EVP_PKEY_set1_DH
			
			virtual void GenerateKeys (const TBigNumBuffer& publicKey);
				// Completes the key generation by integrating the other's
				// public key with the private key created by GenerateParameters()
				// or SetParameters().
				// OpenSSL functions:  DH_compute_key, EVP_PKEY_set1_DH
			
			virtual std::string Parameters ();
				// Returns the current parameters in a temporary buffer.  This method
				// can be called after GenerateParameters() or SetParameters().
				// OpenSSL functions:  i2d_DHparams
			
			virtual void WriteParametersToFile (TFileObj& pkeyFileObj);
				// Writes the Diffie-Hellman parameters from the current
				// object to the given file.  The destination file cannot exist
				// before this function is called.  The parameters are encoded
				// in PKCS#3 DHparameter format.  This method can be called after
				// either GenerateParameters() or SetParameters().
				// OpenSSL functions:  PEM_write_DHparams
			
			virtual TBigNumBuffer P () const;
				// Returns a copy of the p value of the current structure.  Suitable
				// value as an argument to SetParameters().
			
			virtual TBigNumBuffer G () const;
				// Returns a copy of the g value of the current structure.  Suitable
				// value as an argument to SetParameters().
			
			virtual TBigNumBuffer PublicKey () const;
				// Returns a copy of the public key.  GenerateParameters() must
				// be called before this function will complete successfully.
			
			virtual std::string SharedSecret () const;
				// Returns a copy of the shared secret key.  GenerateKeys()
				// must be called before this function will complete successfully.
		
		protected:
			
			virtual void Cleanup ();
				// Resets our object to NULL values.
				// OpenSSL functions:  DH_free
		
		public:
			
			// Accessors
			
			inline bool IsSet() const
				{ return fIsSet; }
			
			inline operator DH* ()
				{ return fInternal; }
			
			inline operator const DH* () const
				{ return fInternal; }
		
		protected:
			
			DH*										fInternal;
			bool									fIsSet;
			std::string								fSharedSecret;
	};
#endif

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif

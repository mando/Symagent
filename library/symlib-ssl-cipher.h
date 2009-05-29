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

#ifndef SYMLIB_SSL_CIPHER
#define SYMLIB_SSL_CIPHER

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-ssl-util.h"

#include <vector>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TCipher;
class TCipherContext;
class TEncryptContext;
class TDecryptContext;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef		std::vector<TCipher>			TCipherList;
typedef		TCipherList::iterator			TCipherList_iter;
typedef		TCipherList::const_iterator		TCipherList_const_iter;

//---------------------------------------------------------------------
// Class TCipher
//
// This class wraps OpenSSL EVP_CIPHER objects.  Coercion operators
// supply conversions to const EVP_CIPHER* so this object can be used
// as in function calls that require const EVP_CIPHER* arguments.
//---------------------------------------------------------------------
class TCipher
{
	public:
		
		TCipher ();
			// Constructor
		
		TCipher (const std::string& cipherName);
			// Constructor
		
		TCipher (const EVP_CIPHER* cipherPtr);
			// Constructor
		
		TCipher (const TCipher& obj);
			// Copy constructor
		
		virtual ~TCipher ();
			// Destructor
		
		virtual void Set (const std::string& cipherName);
			// Sets the current algorithm to the given name.
			// OpenSSL functions:  EVP_get_cipherbyname
		
		virtual void Set (const EVP_CIPHER* cipherPtr);
			// Sets the current algorithm to the argument.
		
		virtual void Set (int nid);
			// Sets the current algorithm to the given NID.
			// OpenSSL functions:  EVP_get_cipherbynid
		
		inline const std::string Name () const
			{ return ShortName(); }
		
		virtual const std::string ShortName () const;
			// Returns the short name of the current algorithm.
			// OpenSSL functions:  EVP_CIPHER_nid, OBJ_nid2sn
		
		virtual const std::string LongName () const;
			// Returns the long name of the current algorithm.
			// OpenSSL functions:  EVP_CIPHER_nid, OBJ_nid2ln
		
		virtual int Type () const;
			// Returns the type of the current algorithm.
			// OpenSSL functions:  EVP_CIPHER_type
		
		virtual int NID () const;
			// Returns the NID of the current algorithm.
			// OpenSSL functions:  EVP_CIPHER_nid
		
		virtual int BlockSize () const;
			// Returns the block size used by the current algorithm,
			// in bytes.
			// OpenSSL functions:  EVP_CIPHER_block_size
		
		static inline int MaxBlockSize ()
			{ return EVP_MAX_IV_LENGTH; }
			// Maximum block size that will be used by any algorithm.
		
		virtual int KeyLength () const;
			// Returns the key length used by the current algorithm,
			// in bytes.
			// OpenSSL functions:  EVP_CIPHER_key_length
		
		static inline int MaxKeyLength ()
			{ return EVP_MAX_KEY_LENGTH; }
			// Maximum key length supported by any algorithm.
		
		virtual int IVLength () const;
			// Returns the IV size used by the current algorithm,
			// in bytes.
			// OpenSSL functions:  EVP_CIPHER_iv_length
		
		static inline int MaxIVLength ()
			{ return EVP_MAX_IV_LENGTH; }
			// Maximum IV size supported by any algorithm.
		
		virtual unsigned long Flags () const;
			// Returns the flags used by the current algorithm.
			// OpenSSL functions:  EVP_CIPHER_flags
		
		virtual unsigned long Mode () const;
			// Returns the mode used by the current algorithm.
			// OpenSSL functions:  EVP_CIPHER_mode
		
		// Accessors
		
		inline bool IsInited () const
			{ return (fCipherPtr != NULL); }
		
		inline const EVP_CIPHER* Ptr () const
			{ return fCipherPtr; }
		
		inline operator const EVP_CIPHER* () const
			{ return Ptr(); }
	
	protected:
		
		const EVP_CIPHER*						fCipherPtr;
};

//---------------------------------------------------------------------
// Class TCipherContext
//
// This class wraps OpenSSL EVP_CIPHER_CTX objects.  Coercion operators
// supply conversions to const EVP_CIPHER_CTX* so this object can be used
// as in function calls that require const EVP_CIPHER_CTX* arguments.
//
// In addition to supplying the same functionality as the original
// EVP_CIPHER_CTX environment, this class supports encryption and
// decryption of entire files -- see the Update() methods.
//
/* Example Usage:

		TCipherContext			cipherContextObj;
		TCipher					cipherObj;
		std::string				iv;
		std::string				key("SecretKey");
		std::string				message("This is a test message");
		std::string				encryptedMessage;
		std::string				decryptedMessage;
		
		// Set the cipher algorithm
		cipherObj.Set("CAST5-CBC");
		
		// Initialize the IV with some random stuff
		iv.CopyFrom(TCipherContext::RandomIV());
		
		// Initialize the context for encryption
		cipherContextObj.Initialize(cipherObj,key,iv,TCipherContext::kEncrypt);
		
		// Encrypt the message
		cipherContextObj.Update(message,encryptedMessage);
		
		// Call final to complete the encryption
		cipherContextObj.Final(encryptedMessage);
		
		// Now initialize the context for decryption
		cipherContextObj.Initialize(cipherObj,key,iv,TCipherContext::kDecrypt);
		
		// Decrypt the encrypted message
		cipherContextObj.Update(encryptedMessage,decryptedMessage);
		
		// Call final to complete the decryption
		cipherContextObj.Final(decryptedMessage);
		
		// Echo the message, encrypted and decrypted versions
		cout << "Original message: " << message << endl;
		cout << "Encrypted: " << encryptedMessage.AsBase64Encoded() << endl;
		cout << "Decrypted: " << decryptedMessage << endl;
*/
//---------------------------------------------------------------------
class TCipherContext : public TUpdateMorphMixin
{
	public:
		
		typedef	enum	{
							kEncrypt,
							kDecrypt
						}	CipherMode;
		
	public:
		
		TCipherContext ();
			// Constructor
	
	private:
		
		TCipherContext (const TCipherContext&) {}
			// Copy constructor not allowed
	
	public:
		
		virtual ~TCipherContext ();
			// Destructor
		
		virtual void Initialize (const TCipher& cipherObj,
								 std::string key,
								 std::string iv,
								 CipherMode mode);
			// Initializes the cipher context.
			// OpenSSL functions:  EVP_CipherInit
		
		virtual void Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer);
			// Performs the encryption or decryption action (set by the
			// mode argument in Initialize()) on the memory pointed to
			// by inBufferPtr, which is inBufferSize bytes in size.
			// The results of the update are concatenated to outBuffer.
			// OpenSSL functions:  EVP_CipherUpdate
		
		virtual void Update (std::string& inBuffer, std::string& outBuffer);
			// Performs the encryption or decryption action (set by the
			// mode argument in Initialize()) on the contents of inBuffer.
			// The results of the update are concatenated to outBuffer.
		
		virtual void Update (TFileObj& inFileObj, TFileObj& outFileObj);
			// Performs the encryption or decryption action (set by the
			// mode argument in Initialize()) on the file cited by the inFileObj
			// argument, concatenating the results into outFileObj.  outFileObj
			// will be created if it doesn't already exist.  outFileObj will
			// be left open when this method completes.  Note:  You must call
			// Final() on the output file to finish the process.
		
		virtual void Final (std::string& outBuffer);
			// The last stage of encryption or decryption.  The final bits
			// of data are concatenated to outBuffer.  After this method
			// completes, you must call Initialize() again before reusing
			// this context.
			// OpenSSL functions:  EVP_CipherFinal
		
		virtual void Final (TFileObj& outFileObj);
			// The last stage of encryption or decryption.  The final bits
			// of data are concatenated to the file pointed to by outFileObj.
			// After this method completes, you must call Initialized() again
			// before reusing this context.  outFileObj must already be open
			// and writable, and this method leaves the file open for future
			// writing if necessary.
		
		virtual void Cleanup ();
			// Destroys any cipher contexts we may have, removing
			// sensitive information from memory.
			// OpenSSL functions:  EVP_CIPHER_CTX_cleanup
		
		virtual void SetKeyLength (int keyLength);
			// Sets the key length of the existing cipher context.
			// OpenSSL functions:  EVP_CIPHER_CTX_set_key_length
		
		virtual void Control (int type, int arg, void* data);
			// Provides additional hooks into the cipher context.  Only certain
			// algorithms support this.
			// OpenSSL functions:  EVP_CIPHER_CTX_ctrl
		
		virtual void SetAppData (void* appDataPtr);
			// Presumably this allows you to attach some portion of memory
			// to the current cipher context.
			// OpenSSL functions:  EVP_CIPHER_CTX_set_app_data
		
		virtual void* GetAppData () const;
			// Returns the pointer supplied in a previous call to
			// SetAppData().
			// OpenSSL functions:  EVP_CIPHER_CTX_get_app_data
		
		virtual std::string Name () const;
			// Returns the name of the current algorithm.
		
		virtual int Type () const;
			// Returns the type ID of the current algorithm.
		
		virtual int NID () const;
			// Returns the NID of the current algorithm.
		
		virtual int BlockSize () const;
			// Returns the block size used by the current algorithm.
		
		static inline int MaxBlockSize ()
			{ return EVP_MAX_IV_LENGTH; }
			// Maximum block size that will be used by any algorithm.
		
		virtual int KeyLength () const;
			// Returns the key length used by the current algorithm.
		
		static inline int MaxKeyLength ()
			{ return EVP_MAX_KEY_LENGTH; }
			// Maximum key length supported by any algorithm.
		
		virtual int IVLength () const;
			// Returns the IV length used by the current algorithm.
		
		static inline int MaxIVLength ()
			{ return EVP_MAX_IV_LENGTH; }
			// Maximum IV size supported by any algorithm.
		
		virtual unsigned long Flags () const;
			// Returns the flags set by the current algorithm.
		
		virtual unsigned long Mode () const;
			// Returns the mode of the current algorithm.
		
		static std::string RandomIV ();
			// Returns a randomly-computed IV.
		
		static void LoadAllAlgorithms ();
			// Ensures that all cipher algorithms are loaded.
		
		static void GetAllAlgorithmNames (StdStringList& algoNameList);
			// Destructively modifies the argument to contain a sorted
			// list of all available cipher algorithm names.
			// OpenSSL functions:  EVP_CIPHER_nid
		
		// Accessors
		
		inline bool IsInited () const
			{ return fIsInited; }
		
		inline bool HasAlgorithm () const
			{ return fHasAlgorithm; }
		
		inline EVP_CIPHER_CTX* Ptr ()
			{ return &fContext; }
		
		inline const EVP_CIPHER_CTX* Ptr () const
			{ return &fContext; }
		
		inline operator EVP_CIPHER_CTX* ()
			{ return Ptr(); }
		
		inline operator const EVP_CIPHER_CTX* () const
			{ return Ptr(); }
	
	protected:
		
		bool									fIsInited;
		bool									fHasAlgorithm;
		EVP_CIPHER_CTX							fContext;
		TCipher									fCipherObj;
};

//---------------------------------------------------------------------
// Class TEncryptContext
//
// This is a specialization of TCipherContext that supplies only encryption
// methods.  It inherits the const EVP_CIPHER_CTX* conversions so can be
// used in function calls that require const EVP_CIPHER_CTX* arguments.
//
// In addition to supplying the same functionality as the original
// EVP_CIPHER_CTX environment, this class supports encryption of entire
// files -- see the Update() methods.
/* Example Usage:

		TEncryptContext			encryptContextObj;
		TCipher					cipherObj;
		std::string				iv;
		std::string				key("SecretKey");
		std::string				message("This is a test message");
		std::string				encryptedMessage;
		
		// Set the cipher algorithm
		cipherObj.Set("CAST5-CBC");
		
		// Initialize the IV with some random stuff
		iv.CopyFrom(TCipherContext::RandomIV());
		
		// Initialize the context for encryption
		encryptContextObj.Initialize(cipherObj,key,iv);
		
		// Encrypt the message
		encryptContextObj.Update(message,encryptedMessage);
		
		// Call final to complete the encryption
		encryptContextObj.Final(encryptedMessage);
		
		// Echo the message and the encrypted version
		cout << "Original message: " << message << endl;
		cout << "Encrypted: " << encryptedMessage.AsBase64Encoded() << endl;
*/
//---------------------------------------------------------------------
class TEncryptContext : public TCipherContext
{
	private:
		
		typedef		TCipherContext			Inherited;
	
	public:
		
		TEncryptContext ();
			// Constructor
	
	private:
		
		TEncryptContext (const TEncryptContext&) {}
			// Copy constructor not allowed
	
	public:
		
		virtual ~TEncryptContext ();
			// Destructor
		
		virtual void Initialize (const TCipher& cipherObj,
								 std::string key,
								 std::string iv);
			// Initializes the encryption context.
			// OpenSSL functions:  EVP_EncryptInit
		
		virtual void Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer);
			// Encrypts the memory pointed to by inBufferPtr, which is
			// inBufferSize bytes in size.  The results of the encryption
			// are concatenated to outBuffer.
			// OpenSSL functions:  EVP_EncryptUpdate
		
		virtual void Update (std::string& inBuffer, std::string& outBuffer);
			// Encrypts the contents of inBuffer, concatenating the results
			// to outBuffer.
		
		virtual void Update (TFileObj& inFileObj, TFileObj& outFileObj);
			// Encrypts the contents of the file pointed to by inFileObj,
			// concatenating the results into outFileObj.  outFileObj
			// will be created if it doesn't already exist.  outFileObj will
			// be left open when this method completes.  Note:  You must call
			// Final() on the output file to finish the process.
		
		virtual void Final (std::string& outBuffer);
			// The last stage of encryption.  The final bits of data are
			// concatenated to outBuffer.  After this method completes,
			// you must call Initialize() again before reusing this context.
			// OpenSSL functions:  EVP_EncryptFinal
		
		virtual void Final (TFileObj& outFileObj);
			// The last stage of encryption.  The final bits of data are
			// concatenated to the file pointed to by outFileObj.  After
			// this method completes, you must call Initialized() again
			// before reusing this context.  outFileObj must already be open
			// and writable, and this method leaves the file open for future
			// writing if necessary.
};

//---------------------------------------------------------------------
// Class TDecryptContext
//
// This is a specialization of TCipherContext that supplies only decryption
// methods.  It inherits the const EVP_CIPHER_CTX* conversions so can be
// used in function calls that require const EVP_CIPHER_CTX* arguments.
//
// In addition to supplying the same functionality as the original
// EVP_CIPHER_CTX environment, this class supports decryption of entire
// files -- see the Update() methods.
/* Example Usage:

		TDecryptContext			decryptContextObj;
		TCipher					cipherObj;
		std::string				iv;
		std::string				key("SecretKey");
		std::string				encryptedMessage;
		std::string				decryptedMessage;
		
		// Set the cipher algorithm
		cipherObj.Set("CAST5-CBC");
		
		// Note that the iv and encryptedMessage variables should have
		// been set elsewhere (perhaps magically).  This example,
		// as-is, won't work because these variables have not been
		// populated.
		
		// Initialize the context for encryption
		decryptContextObj.Initialize(cipherObj,key,iv);
		
		// Decrypt the message
		decryptContextObj.Update(encryptedMessage,decryptedMessage);
		
		// Call final to complete the encryption
		decryptContextObj.Final(decryptedMessage);
		
		// Echo the message and the encrypted version
		cout << "Encrypted: " << encryptedMessage.AsBase64Encoded() << endl;
		cout << "Decrypted: " << decryptedMessage << endl;
*/
//---------------------------------------------------------------------
class TDecryptContext : public TCipherContext
{
	private:
		
		typedef		TCipherContext			Inherited;
	
	public:
		
		TDecryptContext ();
			// Constructor
	
	private:
		
		TDecryptContext (const TDecryptContext&) {}
			// Copy constructor not allowed
	
	public:
		
		virtual ~TDecryptContext ();
			// Destructor
		
		virtual void Initialize (const TCipher& cipherObj,
								 std::string key,
								 std::string iv);
			// Initializes the decryption context.
			// OpenSSL functions:  EVP_DecryptInit
		
		virtual void Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer);
			// Decrypts the memory pointed to by inBufferPtr, which is
			// inBufferSize bytes in size.  The results of the decryption
			// are concatenated to outBuffer.
			// OpenSSL functions:  EVP_DecryptUpdate
		
		virtual void Update (std::string& inBuffer, std::string& outBuffer);
			// Decrypts the contents of inBuffer, concatenating the results
			// to outBuffer.
		
		virtual void Update (TFileObj& inFileObj, TFileObj& outFileObj);
			// Decrypts the contents of the file pointed to by inFileObj,
			// concatenating the results into outFileObj.  outFileObj
			// will be created if it doesn't already exist.  outFileObj will
			// be left open when this method completes.  Note:  You must call
			// Final() on the output file to finish the process.
		
		virtual void Final (std::string& outBuffer);
			// The last stage of decryption.  The final bits of data are
			// concatenated to outBuffer.  After this method completes,
			// you must call Initialize() again before reusing this context.
			// OpenSSL functions:  EVP_DecryptFinal
		
		virtual void Final (TFileObj& outFileObj);
			// The last stage of decryption.  The final bits of data are
			// concatenated to the file pointed to by outFileObj.  After
			// this method completes, you must call Initialized() again
			// before reusing this context.  outFileObj must already be open
			// and writable, and this method leaves the file open for future
			// writing if necessary.
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif

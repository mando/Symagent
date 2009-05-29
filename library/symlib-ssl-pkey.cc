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
#include "symlib-ssl-pkey.h"

#include "openssl/pem.h"

#include <algorithm>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TPKeyObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPKeyObj::TPKeyObj ()
	:	fPKeyPtr(NULL)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPKeyObj::TPKeyObj (const EVP_PKEY* evpPkeyPtr)
	:	fPKeyPtr(NULL)
{
	fPKeyPtr = const_cast<EVP_PKEY*>(evpPkeyPtr);
	++fPKeyPtr->references;
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	TPKeyObj::TPKeyObj (TRSAObj& rsaAlgoObj)
		:	fPKeyPtr(NULL)
	{
		Setup();
		
		if (EVP_PKEY_set1_RSA(fPKeyPtr,rsaAlgoObj) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	TPKeyObj::TPKeyObj (TDSAObj& dsaAlgoObj)
		:	fPKeyPtr(NULL)
	{
		Setup();
		
		if (EVP_PKEY_set1_DSA(fPKeyPtr,dsaAlgoObj) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
#if !defined(NO_DH)
	TPKeyObj::TPKeyObj (TDHObj& dhAlgoObj)
		:	fPKeyPtr(NULL)
	{
		Setup();
		
		if (EVP_PKEY_set1_DH(fPKeyPtr,dhAlgoObj) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
TPKeyObj::TPKeyObj (const TPKeyObj& obj)
	:	fPKeyPtr(NULL)
{
	fPKeyPtr = const_cast<EVP_PKEY*>(obj.fPKeyPtr);
	++fPKeyPtr->references;
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPKeyObj::~TPKeyObj ()
{
	Cleanup();
}

//---------------------------------------------------------------------
// TPKeyObj::Encrypt
//---------------------------------------------------------------------
std::string TPKeyObj::Encrypt (const std::string& value)
{
	std::string		encryptedValue;
	unsigned char*	encryptedValuePtr = NULL;
	int				encryptedLength = 0;
	unsigned char*	valuePtr = NULL;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
	
	// Prep the destination buffer
	encryptedValue.resize(Max(static_cast<unsigned int>(Size()),value.length())*2);
	encryptedValuePtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(encryptedValue.data()));
	valuePtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(value.data()));
	
	// Call the actual encryption routine
	encryptedLength = EVP_PKEY_encrypt(encryptedValuePtr,valuePtr,value.length(),fPKeyPtr);
	if (encryptedLength < 0)
		throw TSSLErrorObj(kSSLPKeyCannotEncrypt);
	
	// Adjust the size of the destination buffer
	encryptedValue.resize(encryptedLength);
	
	return encryptedValue;
}

//---------------------------------------------------------------------
// TPKeyObj::Decrypt
//---------------------------------------------------------------------
std::string TPKeyObj::Decrypt (const std::string& value)
{
	std::string		decryptedValue;
	unsigned char*	decryptedValuePtr = NULL;
	int				decryptedLength = 0;
	unsigned char*	valuePtr = NULL;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
	
	// Prep the destination buffer
	decryptedValue.resize(Max(static_cast<unsigned int>(Size()),value.length())*2);
	decryptedValuePtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(decryptedValue.data()));
	valuePtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(value.data()));
	
	// Call the actual decryption routine
	decryptedLength = EVP_PKEY_decrypt(decryptedValuePtr,valuePtr,value.length(),fPKeyPtr);
	if (decryptedLength < 0)
		throw TSSLErrorObj(kSSLPKeyCannotDecrypt);
	
	// Adjust the size of the destination buffer
	decryptedValue.resize(decryptedLength);
	
	return decryptedValue;
}

//---------------------------------------------------------------------
// TPKeyObj::PublicKey
//---------------------------------------------------------------------
std::string TPKeyObj::PublicKey ()
{
	std::string	buffer;
	int			bufferSize = 0;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
	
	// Get the size of the final key
	bufferSize = i2d_PublicKey(fPKeyPtr,NULL);
	
	if (bufferSize > 0)
	{
		unsigned char*		ptr = NULL;
		
		// Prepare the buffer
		buffer.resize(bufferSize);
		ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buffer.data()));
		
		// Get the key
		i2d_PublicKey(fPKeyPtr,&ptr);
	}
	
	return buffer;
}

//---------------------------------------------------------------------
// TPKeyObj::PrivateKey
//---------------------------------------------------------------------
std::string TPKeyObj::PrivateKey ()
{
	std::string	buffer;
	int			bufferSize = 0;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
	
	// Get the size of the final key
	bufferSize = i2d_PrivateKey(fPKeyPtr,NULL);
	
	if (bufferSize > 0)
	{
		unsigned char*		ptr = NULL;
		
		// Prepare the buffer
		buffer.resize(bufferSize);
		ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buffer.data()));
		
		// Get the key
		i2d_PrivateKey(fPKeyPtr,&ptr);
	}
	
	return buffer;
}

//---------------------------------------------------------------------
// TPKeyObj::SetPublicKey
//---------------------------------------------------------------------
void TPKeyObj::SetPublicKey (int keyType, const std::string& publicKey)
{
#if (1 == 1)
	const unsigned char* 	ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(publicKey.data()));
#else
	unsigned char*			ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(publicKey.data()));	
#endif

	Cleanup();
	
	fPKeyPtr = d2i_PublicKey(keyType,NULL,&ptr,publicKey.length());
	if (!fPKeyPtr)
		throw TSSLErrorObj(kSSLPKeyNotInited);
}

//---------------------------------------------------------------------
// TPKeyObj::SetPrivateKey
//---------------------------------------------------------------------
void TPKeyObj::SetPrivateKey (int keyType, const std::string& privateKey)
{
#if (1 == 1)
	const unsigned char*	ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(privateKey.data()));
#else
	unsigned char*			ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(privateKey.data()));
#endif

	Cleanup();
	
	fPKeyPtr = d2i_PrivateKey(keyType,NULL,&ptr,privateKey.length());
	if (!fPKeyPtr)
		throw TSSLErrorObj(kSSLPKeyNotInited);
}

//---------------------------------------------------------------------
// TPKeyObj::SetKey
//---------------------------------------------------------------------
void TPKeyObj::SetKey (EVP_PKEY* evpPkeyPtr)
{
	Cleanup();
	
	fPKeyPtr = evpPkeyPtr;
	++fPKeyPtr->references;
}

//---------------------------------------------------------------------
// TPKeyObj::SetKey
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	void TPKeyObj::SetKey (TRSAObj& rsaAlgoObj)
	{
		Setup();
		
		if (EVP_PKEY_set1_RSA(fPKeyPtr,rsaAlgoObj) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TPKeyObj::SetKey
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	void TPKeyObj::SetKey (TDSAObj& dsaAlgoObj)
	{
		Setup();
		
		if (EVP_PKEY_set1_DSA(fPKeyPtr,dsaAlgoObj) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TPKeyObj::SetKey
//---------------------------------------------------------------------
#if !defined(NO_DH)
	void TPKeyObj::SetKey (TDHObj& dhAlgoObj)
	{
		Setup();
		
		if (EVP_PKEY_set1_DH(fPKeyPtr,dhAlgoObj) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TPKeyObj::WritePublicKeyToFile
//---------------------------------------------------------------------
void TPKeyObj::WritePublicKeyToFile (TFileObj& pkeyFileObj)
{
	FILE*	streamPtr = NULL;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
	
	if (pkeyFileObj.Exists())
		throw TSymLibErrorObj(EEXIST);
	
	// Manage the file we were given to make sure it's opened appropriately
	pkeyFileObj.Create(S_IRUSR|S_IWUSR,true);
	
	// Open a stream to the file
	streamPtr = fopen(pkeyFileObj.Path().c_str(),"w");
	if (streamPtr)
	{
		try
		{
			if (PEM_write_PUBKEY(streamPtr,fPKeyPtr) != 1)
				throw TSSLErrorObj(kSSLPKeyCannotWriteToFile);
			
			// Close the file
			fclose(streamPtr);
		}
		catch (...)
		{
			// Close the stream before passing the exception through
			fclose(streamPtr);
			throw;
		}
	}
	else
		throw TSymLibErrorObj(errno);
}

//---------------------------------------------------------------------
// TPKeyObj::ReadPublicKeyFromFile
//---------------------------------------------------------------------
void TPKeyObj::ReadPublicKeyFromFile (TFileObj& pkeyFileObj)
{
	FILE*	streamPtr = NULL;
	
	if (!pkeyFileObj.Exists())
		throw TSymLibErrorObj(ENOENT,"Public key file does not exist");
	
	Cleanup();
	
	// Open a stream to the file
	streamPtr = fopen(pkeyFileObj.Path().c_str(),"r");
	if (streamPtr)
	{
		try
		{
			fPKeyPtr = PEM_read_PUBKEY(streamPtr,NULL,NULL,NULL);
			if (!fPKeyPtr)
				throw TSSLErrorObj(kSSLPKeyCannotReadFromFile);
			
			// Close the file
			fclose(streamPtr);
		}
		catch (...)
		{
			// Close the stream before passing the exception through
			fclose(streamPtr);
			throw;
		}
	}
	else
		throw TSymLibErrorObj(errno);
}

//---------------------------------------------------------------------
// TPKeyObj::WritePrivateKeyToFile
//---------------------------------------------------------------------
void TPKeyObj::WritePrivateKeyToFile (TFileObj& pkeyFileObj)
{
	FILE*	streamPtr = NULL;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
	
	if (pkeyFileObj.Exists())
		throw TSymLibErrorObj(EEXIST);
	
	// Manage the file we were given to make sure it's opened appropriately
	pkeyFileObj.Create(S_IRUSR|S_IWUSR,true);
	
	// Open a stream to the file
	streamPtr = fopen(pkeyFileObj.Path().c_str(),"w");
	if (streamPtr)
	{
		try
		{
			if (PEM_write_PKCS8PrivateKey(streamPtr,fPKeyPtr,NULL,NULL,0,NULL,NULL) != 1)
				throw TSSLErrorObj(kSSLPKeyCannotWriteToFile);
			
			// Close the file
			fclose(streamPtr);
		}
		catch (...)
		{
			// Close the stream before passing the exception through
			fclose(streamPtr);
			throw;
		}
	}
	else
		throw TSymLibErrorObj(errno);
}

//---------------------------------------------------------------------
// TPKeyObj::WritePrivateKeyToFile
//---------------------------------------------------------------------
void TPKeyObj::WritePrivateKeyToFile (TFileObj& pkeyFileObj,
									  TCipher& cipherObj,
									  std::string passphrasePrompt,
									  std::string passphrase)
{
	FILE*	streamPtr = NULL;
	
	if (!IsSet())
		throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
	
	if (pkeyFileObj.Exists())
		throw TSymLibErrorObj(EEXIST);
	
	// Manage the file we were given to make sure it's opened appropriately
	pkeyFileObj.Create(S_IRUSR|S_IWUSR,true);
	
	streamPtr = fopen(pkeyFileObj.Path().c_str(),"w");
	if (streamPtr)
	{
		try
		{
			char*	passphrasePtr = NULL;
			int		(*promptPtr)(char*,int,int,void*) = NULL;
			
			if (!passphrasePrompt.empty())
			{
				promptPtr = TSSLEnvironment::GetPWFromSTDINCallback;
				passphrasePtr = const_cast<char*>(passphrasePrompt.c_str());
			}
			else if (!passphrase.empty())
			{
				passphrasePtr = const_cast<char*>(passphrase.c_str());
			}
			
			if (PEM_write_PKCS8PrivateKey(streamPtr,fPKeyPtr,cipherObj,NULL,0,promptPtr,passphrasePtr) != 1)
				throw TSSLErrorObj(kSSLPKeyCannotWriteToFile);
			
			// Close the file
			fclose(streamPtr);
		}
		catch (...)
		{
			// Close the stream before passing the exception through
			fclose(streamPtr);
			throw;
		}
	}
	else
		throw TSymLibErrorObj(errno);
}

//---------------------------------------------------------------------
// TPKeyObj::ReadPrivateKeyFromFile
//---------------------------------------------------------------------
void TPKeyObj::ReadPrivateKeyFromFile (TFileObj& pkeyFileObj,
									   std::string passphrasePrompt,
									   std::string passphrase)
{
	FILE*	streamPtr = NULL;
	
	if (!pkeyFileObj.Exists())
		throw TSymLibErrorObj(ENOENT,"Private key file does not exist");
	
	Cleanup();
	
	streamPtr = fopen(pkeyFileObj.Path().c_str(),"r");
	if (streamPtr)
	{
		try
		{
			char*	passphrasePtr = NULL;
			int		(*promptPtr)(char*,int,int,void*) = NULL;
			
			if (!passphrasePrompt.empty())
			{
				promptPtr = TSSLEnvironment::GetPWFromSTDINCallback;
				passphrasePtr = const_cast<char*>(passphrasePrompt.c_str());
			}
			else if (!passphrase.empty())
			{
				passphrasePtr = const_cast<char*>(passphrase.c_str());
			}
			
			fPKeyPtr = PEM_read_PrivateKey(streamPtr,NULL,promptPtr,passphrasePtr);
			if (!fPKeyPtr)
				throw TSSLErrorObj(kSSLPKeyCannotReadFromFile);
			
			// Close the file
			fclose(streamPtr);
		}
		catch (...)
		{
			// Close the stream before passing the exception through
			fclose(streamPtr);
			throw;
		}
	}
	else
		throw TSymLibErrorObj(errno);
}

//---------------------------------------------------------------------
// TPKeyObj::Type
//---------------------------------------------------------------------
int TPKeyObj::Type () const
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
	
	return fPKeyPtr->type;
}

//---------------------------------------------------------------------
// TPKeyObj::GeneralType
//---------------------------------------------------------------------
int TPKeyObj::GeneralType () const
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
	
	return TypeFromNID(fPKeyPtr->type);
}

//---------------------------------------------------------------------
// TPKeyObj::BitSize
//---------------------------------------------------------------------
int TPKeyObj::BitSize () const
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
	
	return EVP_PKEY_bits(fPKeyPtr);
}

//---------------------------------------------------------------------
// TPKeyObj::Size
//---------------------------------------------------------------------
int TPKeyObj::Size () const
{
	if (!IsSet())
		throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
	
	return EVP_PKEY_size(fPKeyPtr);
}

//---------------------------------------------------------------------
// TPKeyObj::TypeFromNID (static)
//---------------------------------------------------------------------
int TPKeyObj::TypeFromNID (int nid)
{
	return EVP_PKEY_type(nid);
}

//---------------------------------------------------------------------
// TPKeyObj::Setup (protected)
//---------------------------------------------------------------------
void TPKeyObj::Setup ()
{
	Cleanup();
	
	fPKeyPtr = EVP_PKEY_new();
	if (!fPKeyPtr)
		throw TSSLErrorObj(kSSLPKeyNotInited);
}

//---------------------------------------------------------------------
// TPKeyObj::Cleanup (protected)
//---------------------------------------------------------------------
void TPKeyObj::Cleanup ()
{
	if (fPKeyPtr)
	{
		EVP_PKEY_free(fPKeyPtr);
		fPKeyPtr = NULL;
	}
}

//*********************************************************************
// Class TRSAObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	TRSAObj::TRSAObj ()
		:	Inherited(),
			fInternal(NULL)
	{
	}
#endif

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	TRSAObj::TRSAObj (const RSA* rsaPtr)
		:	Inherited(),
			fInternal(NULL)
	{
		fInternal = const_cast<RSA*>(rsaPtr);
		++fInternal->references;
		
		if (EVP_PKEY_set1_RSA(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	TRSAObj::TRSAObj (const TRSAObj& obj)
		:	Inherited(),
			fInternal(NULL)
	{
		fInternal = const_cast<RSA*>(obj.fInternal);
		++fInternal->references;
		
		if (EVP_PKEY_set1_RSA(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	TRSAObj::~TRSAObj ()
	{
		if (fInternal)
		{
			RSA_free(fInternal);
			fInternal = NULL;
		}
	}
#endif

//---------------------------------------------------------------------
// TRSAObj::GenerateKeys
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	void TRSAObj::GenerateKeys (int modulusInBits, int exponent)
	{
		Setup();
		
		// Generate a new RSA key
		fInternal = RSA_generate_key(modulusInBits,exponent,NULL,NULL);
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		// Setup the EVP version
		if (EVP_PKEY_set1_RSA(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TRSAObj::PublicKey
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	std::string TRSAObj::PublicKey ()
	{
		std::string	buffer;
		int			bufferSize = 0;
		
		if (!IsSet())
			throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
		
		// Determine the size of the final key
		bufferSize = i2d_RSAPublicKey(fInternal,NULL);
		if (bufferSize > 0)
		{
			unsigned char*		ptr = NULL;
			
			// Prep the buffer
			buffer.resize(bufferSize);
			ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buffer.data()));
			
			// Obtain the key
			i2d_RSAPublicKey(fInternal,&ptr);
		}
		
		return buffer;
	}
#endif

//---------------------------------------------------------------------
// TRSAObj::PrivateKey
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	std::string TRSAObj::PrivateKey ()
	{
		std::string	buffer;
		int			bufferSize = 0;
		
		if (!IsSet())
			throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
		
		// Determine the size of the final key
		bufferSize = i2d_RSAPrivateKey(fInternal,NULL);
		if (bufferSize > 0)
		{
			unsigned char*		ptr = NULL;
			
			// Prep the buffer
			buffer.resize(bufferSize);
			ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buffer.data()));
			
			// Obtain the key
			i2d_RSAPrivateKey(fInternal,&ptr);
		}
		
		return buffer;
	}
#endif

//---------------------------------------------------------------------
// TRSAObj::SetPublicKey
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	void TRSAObj::SetPublicKey (const std::string& publicKey)
	{
		#if RSA_KEY_BUFFER_PTR_IS_CONST
			const unsigned char*		ptr = reinterpret_cast<const unsigned char*>(publicKey.data());
		#else
			unsigned char*		ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(publicKey.data()));
		#endif
		
		Cleanup();
		
		// Set the RSA key from the buffer
		fInternal = d2i_RSAPublicKey(NULL,&ptr,publicKey.length());
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		// Set the EVP object
		if (EVP_PKEY_set1_RSA(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TRSAObj::SetPrivateKey
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	void TRSAObj::SetPrivateKey (const std::string& privateKey)
	{
		#if RSA_KEY_BUFFER_PTR_IS_CONST
			const unsigned char*		ptr = reinterpret_cast<const unsigned char*>(privateKey.data());
		#else
			unsigned char*		ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(privateKey.data()));
		#endif
		
		Cleanup();
		
		// Set the RSA key from the buffer
		fInternal = d2i_RSAPrivateKey(NULL,&ptr,privateKey.length());
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		// Set the EVP object
		if (EVP_PKEY_set1_RSA(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TRSAObj::WritePublicKeyToFile
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	void TRSAObj::WritePublicKeyToFile (TFileObj& pkeyFileObj)
	{
		FILE*	streamPtr = NULL;
		
		if (!IsSet())
			throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
		
		if (pkeyFileObj.Exists())
			throw TSymLibErrorObj(EEXIST);
		
		// Manage the file we were given to make sure it's opened appropriately
		pkeyFileObj.Create(S_IRUSR|S_IWUSR,true);
		
		// Open a stream to the file
		streamPtr = fopen(pkeyFileObj.Path().c_str(),"w");
		if (streamPtr)
		{
			try
			{
				if (PEM_write_RSAPublicKey(streamPtr,fInternal) != 1)
					throw TSSLErrorObj(kSSLPKeyCannotWriteToFile);
				
				// Close the file
				fclose(streamPtr);
			}
			catch (...)
			{
				// Close the stream before passing the exception through
				fclose(streamPtr);
				throw;
			}
		}
		else
			throw TSymLibErrorObj(errno);
	}
#endif

//---------------------------------------------------------------------
// TRSAObj::ReadPublicKeyFromFile
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	void TRSAObj::ReadPublicKeyFromFile (TFileObj& pkeyFileObj)
	{
		FILE*	streamPtr = NULL;
		
		if (!pkeyFileObj.Exists())
			throw TSymLibErrorObj(ENOENT,"Public key file does not exist");
		
		Setup();
		
		// Open a stream to the file
		streamPtr = fopen(pkeyFileObj.Path().c_str(),"r");
		if (streamPtr)
		{
			try
			{
				fInternal = PEM_read_RSAPublicKey(streamPtr,NULL,NULL,NULL);
				if (!fInternal)
					throw TSSLErrorObj(kSSLPKeyCannotReadFromFile);
				
				// Close the file
				fclose(streamPtr);
				
				// Set the EVP object
				if (EVP_PKEY_set1_RSA(fPKeyPtr,fInternal) != 1)
					throw TSSLErrorObj(kSSLPKeyNotInited);
			}
			catch (...)
			{
				// Close the stream before passing the exception through
				fclose(streamPtr);
				throw;
			}
		}
		else
			throw TSymLibErrorObj(errno);
	}
#endif

//---------------------------------------------------------------------
// TRSAObj::WritePrivateKeyToFile
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	void TRSAObj::WritePrivateKeyToFile (TFileObj& pkeyFileObj)
	{
		FILE*	streamPtr = NULL;
		
		if (!IsSet())
			throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
		
		if (pkeyFileObj.Exists())
			throw TSymLibErrorObj(EEXIST);
		
		// Manage the file we were given to make sure it's opened appropriately
		pkeyFileObj.Create(S_IRUSR|S_IWUSR,true);
		
		// Open a stream to the file
		streamPtr = fopen(pkeyFileObj.Path().c_str(),"w");
		if (streamPtr)
		{
			try
			{
				if (PEM_write_RSAPrivateKey(streamPtr,fInternal,NULL,NULL,0,NULL,NULL) != 1)
					throw TSSLErrorObj(kSSLPKeyCannotWriteToFile);
				
				// Close the file
				fclose(streamPtr);
			}
			catch (...)
			{
				// Close the stream before passing the exception through
				fclose(streamPtr);
				throw;
			}
		}
		else
			throw TSymLibErrorObj(errno);
	}
#endif

//---------------------------------------------------------------------
// TRSAObj::WritePrivateKeyToFile
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	void TRSAObj::WritePrivateKeyToFile (TFileObj& pkeyFileObj,
										 TCipher& cipherObj,
										 std::string passphrasePrompt,
										 std::string passphrase)
	{
		FILE*	streamPtr = NULL;
		
		if (!IsSet())
			throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
		
		if (pkeyFileObj.Exists())
			throw TSymLibErrorObj(EEXIST);
		
		// Manage the file we were given to make sure it's opened appropriately
		pkeyFileObj.Create(S_IRUSR|S_IWUSR,true);
		
		// Open a stream to the file
		streamPtr = fopen(pkeyFileObj.Path().c_str(),"w");
		if (streamPtr)
		{
			try
			{
				char*	passphrasePtr = NULL;
				int		(*promptPtr)(char*,int,int,void*) = NULL;
				
				if (!passphrasePrompt.empty())
				{
					promptPtr = TSSLEnvironment::GetPWFromSTDINCallback;
					passphrasePtr = const_cast<char*>(passphrasePrompt.c_str());
				}
				else if (!passphrase.empty())
				{
					passphrasePtr = const_cast<char*>(passphrase.c_str());
				}
				
				if (PEM_write_RSAPrivateKey(streamPtr,fInternal,cipherObj,NULL,0,promptPtr,passphrasePtr) != 1)
					throw TSSLErrorObj(kSSLPKeyCannotWriteToFile);
				
				// Close the file
				fclose(streamPtr);
			}
			catch (...)
			{
				// Close the stream before passing the exception through
				fclose(streamPtr);
				throw;
			}
		}
		else
			throw TSymLibErrorObj(errno);
	}
#endif

//---------------------------------------------------------------------
// TRSAObj::ReadPrivateKeyFromFile
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	void TRSAObj::ReadPrivateKeyFromFile (TFileObj& pkeyFileObj,
										  std::string passphrasePrompt,
										  std::string passphrase)
	{
		FILE*	streamPtr = NULL;
		
		if (!pkeyFileObj.Exists())
			throw TSymLibErrorObj(ENOENT,"Private key file does not exist");
		
		Setup();
		
		// Open a stream to the file
		streamPtr = fopen(pkeyFileObj.Path().c_str(),"r");
		if (streamPtr)
		{
			try
			{
				char*	passphrasePtr = NULL;
				int		(*promptPtr)(char*,int,int,void*) = NULL;
				
				if (!passphrasePrompt.empty())
				{
					promptPtr = TSSLEnvironment::GetPWFromSTDINCallback;
					passphrasePtr = const_cast<char*>(passphrasePrompt.c_str());
				}
				else if (!passphrase.empty())
				{
					passphrasePtr = const_cast<char*>(passphrase.c_str());
				}
				
				fInternal = PEM_read_RSAPrivateKey(streamPtr,NULL,promptPtr,passphrasePtr);
				if (!fInternal)
					throw TSSLErrorObj(kSSLPKeyCannotReadFromFile);
				
				// Close the file
				fclose(streamPtr);
				
				// Set the EVP object
				if (EVP_PKEY_set1_RSA(fPKeyPtr,fInternal) != 1)
					throw TSSLErrorObj(kSSLPKeyNotInited);
			}
			catch (...)
			{
				// Close the stream before passing the exception through
				fclose(streamPtr);
				throw;
			}
		}
		else
			throw TSymLibErrorObj(errno);
	}
#endif

//---------------------------------------------------------------------
// TRSAObj::Cleanup (protected)
//---------------------------------------------------------------------
#if !defined(NO_RSA)
	void TRSAObj::Cleanup ()
	{
		if (fInternal)
		{
			RSA_free(fInternal);
			fInternal = NULL;
		}
		
		Inherited::Cleanup();
	}
#endif

//*********************************************************************
// Class TDSAObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	TDSAObj::TDSAObj ()
		:	Inherited(),
			fInternal(NULL)
	{
	}
#endif

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	TDSAObj::TDSAObj (const DSA* dsaPtr)
		:	Inherited(),
			fInternal(NULL)
	{
		fInternal = const_cast<DSA*>(dsaPtr);
		++fInternal->references;
		
		if (EVP_PKEY_set1_DSA(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	TDSAObj::TDSAObj (const TDSAObj& obj)
		:	Inherited(),
			fInternal(NULL)
	{
		fInternal = const_cast<DSA*>(obj.fInternal);
		++fInternal->references;
		
		if (EVP_PKEY_set1_DSA(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	TDSAObj::~TDSAObj ()
	{
		if (fInternal)
		{
			DSA_free(fInternal);
			fInternal = NULL;
		}
	}
#endif

//---------------------------------------------------------------------
// TDSAObj::GenerateKeys
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	void TDSAObj::GenerateKeys (int primeLengthInBits)
	{
		Setup();
		
		// Generate the DSA parameters
		fInternal = DSA_generate_parameters(primeLengthInBits,NULL,0,NULL,NULL,NULL,NULL);
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		if (DSA_generate_key(fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		// Setup the EVP version
		if (EVP_PKEY_set1_DSA(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TDSAObj::PublicKey
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	std::string TDSAObj::PublicKey ()
	{
		std::string	buffer;
		int			bufferSize = 0;
		
		if (!IsSet())
			throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
		
		// Determine the size of the key
		bufferSize = i2d_DSAPublicKey(fInternal,NULL);
		if (bufferSize > 0)
		{
			unsigned char*		ptr = NULL;
			
			// Prep the buffer
			buffer.resize(bufferSize);
			ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buffer.data()));
			
			// Get the key
			i2d_DSAPublicKey(fInternal,&ptr);
		}
		
		return buffer;
	}
#endif

//---------------------------------------------------------------------
// TDSAObj::PrivateKey
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	std::string TDSAObj::PrivateKey ()
	{
		std::string	buffer;
		int			bufferSize = 0;
		
		if (!IsSet())
			throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
		
		// Determine the size of the key
		bufferSize = i2d_DSAPrivateKey(fInternal,NULL);
		if (bufferSize > 0)
		{
			unsigned char*		ptr = NULL;
			
			// Prep the buffer
			buffer.resize(bufferSize);
			ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buffer.data()));
			
			// Get the key
			i2d_DSAPrivateKey(fInternal,&ptr);
		}
		
		return buffer;
	}
#endif

//---------------------------------------------------------------------
// TDSAObj::SetPublicKey
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	void TDSAObj::SetPublicKey (const std::string& publicKey)
	{
		#if DSA_KEY_BUFFER_PTR_IS_CONST
			const unsigned char*		ptr = reinterpret_cast<const unsigned char*>(publicKey.data());
		#else
			unsigned char*		ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(publicKey.data()));
		#endif
		
		Cleanup();
		
		// Set the key from the buffer
		fInternal = d2i_DSAPublicKey(NULL,&ptr,publicKey.length());
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		// Set the EVP object
		if (EVP_PKEY_set1_DSA(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TDSAObj::SetPrivateKey
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	void TDSAObj::SetPrivateKey (const std::string& privateKey)
	{
		#if DSA_KEY_BUFFER_PTR_IS_CONST
			const unsigned char*		ptr = reinterpret_cast<const unsigned char*>(privateKey.data());
		#else
			unsigned char*		ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(privateKey.data()));
		#endif
		
		Cleanup();
		
		// Set the key from the buffer
		fInternal = d2i_DSAPrivateKey(NULL,&ptr,privateKey.length());
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		// Set the EVP object
		if (EVP_PKEY_set1_DSA(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TDSAObj::WritePrivateKeyToFile
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	void TDSAObj::WritePrivateKeyToFile (TFileObj& pkeyFileObj)
	{
		FILE*	streamPtr = NULL;
		
		if (!IsSet())
			throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
		
		if (pkeyFileObj.Exists())
			throw TSymLibErrorObj(EEXIST);
		
		// Manage the file we were given to make sure it's opened appropriately
		pkeyFileObj.Create(S_IRUSR|S_IWUSR,true);
		
		// Open a stream to the file
		streamPtr = fopen(pkeyFileObj.Path().c_str(),"w");
		if (streamPtr)
		{
			try
			{
				if (PEM_write_DSAPrivateKey(streamPtr,fInternal,NULL,NULL,0,NULL,NULL) != 1)
					throw TSSLErrorObj(kSSLPKeyCannotWriteToFile);
				
				// Close the file
				fclose(streamPtr);
			}
			catch (...)
			{
				// Close the stream before passing the exception through
				fclose(streamPtr);
				throw;
			}
		}
		else
			throw TSymLibErrorObj(errno);
	}
#endif

//---------------------------------------------------------------------
// TDSAObj::WritePrivateKeyToFile
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	void TDSAObj::WritePrivateKeyToFile (TFileObj& pkeyFileObj,
										 TCipher& cipherObj,
										 std::string passphrasePrompt,
										 std::string passphrase)
	{
		FILE*	streamPtr = NULL;
		
		if (!IsSet())
			throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
		
		if (pkeyFileObj.Exists())
			throw TSymLibErrorObj(EEXIST);
		
		// Manage the file we were given to make sure it's opened appropriately
		pkeyFileObj.Create(S_IRUSR|S_IWUSR,true);
		
		// Open a stream to the file
		streamPtr = fopen(pkeyFileObj.Path().c_str(),"w");
		if (streamPtr)
		{
			try
			{
				char*	passphrasePtr = NULL;
				int		(*promptPtr)(char*,int,int,void*) = NULL;
				
				if (!passphrasePrompt.empty())
				{
					promptPtr = TSSLEnvironment::GetPWFromSTDINCallback;
					passphrasePtr = const_cast<char*>(passphrasePrompt.c_str());
				}
				else if (!passphrase.empty())
				{
					passphrasePtr = const_cast<char*>(passphrase.c_str());
				}
				
				if (PEM_write_DSAPrivateKey(streamPtr,fInternal,cipherObj,NULL,0,promptPtr,passphrasePtr) != 1)
					throw TSSLErrorObj(kSSLPKeyCannotWriteToFile);
				
				// Close the file
				fclose(streamPtr);
			}
			catch (...)
			{
				// Close the stream before passing the exception through
				fclose(streamPtr);
				throw;
			}
		}
		else
			throw TSymLibErrorObj(errno);
	}
#endif

//---------------------------------------------------------------------
// TDSAObj::ReadPrivateKeyFromFile
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	void TDSAObj::ReadPrivateKeyFromFile (TFileObj& pkeyFileObj,
										  std::string passphrasePrompt,
										  std::string passphrase)
	{
		FILE*	streamPtr = NULL;
		
		if (!pkeyFileObj.Exists())
			throw TSymLibErrorObj(ENOENT,"Private key file does not exist");
		
		Setup();
		
		// Open a stream to the file
		streamPtr = fopen(pkeyFileObj.Path().c_str(),"r");
		if (streamPtr)
		{
			try
			{
				char*	passphrasePtr = NULL;
				int		(*promptPtr)(char*,int,int,void*) = NULL;
				
				if (!passphrasePrompt.empty())
				{
					promptPtr = TSSLEnvironment::GetPWFromSTDINCallback;
					passphrasePtr = const_cast<char*>(passphrasePrompt.c_str());
				}
				else if (!passphrase.empty())
				{
					passphrasePtr = const_cast<char*>(passphrase.c_str());
				}
				
				fInternal = PEM_read_DSAPrivateKey(streamPtr,NULL,promptPtr,passphrasePtr);
				if (!fInternal)
					throw TSSLErrorObj(kSSLPKeyCannotReadFromFile);
				
				// Close the file
				fclose(streamPtr);
				
				// Set the EVP object
				if (EVP_PKEY_set1_DSA(fPKeyPtr,fInternal) != 1)
					throw TSSLErrorObj(kSSLPKeyNotInited);
			}
			catch (...)
			{
				// Close the stream before passing the exception through
				fclose(streamPtr);
				throw;
			}
		}
		else
			throw TSymLibErrorObj(errno);
	}
#endif

//---------------------------------------------------------------------
// TDSAObj::Cleanup (protected)
//---------------------------------------------------------------------
#if !defined(NO_DSA)
	void TDSAObj::Cleanup ()
	{
		if (fInternal)
		{
			DSA_free(fInternal);
			fInternal = NULL;
		}
		
		Inherited::Cleanup();
	}
#endif

//*********************************************************************
// Class TDHObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
#if !defined(NO_DH)
	TDHObj::TDHObj ()
		:	Inherited(),
			fInternal(NULL),
			fIsSet(false)
	{
	}
#endif

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
#if !defined(NO_DH)
	TDHObj::TDHObj (const DH* dhPtr)
		:	Inherited(),
			fInternal(NULL)
	{
		fInternal = const_cast<DH*>(dhPtr);
		++fInternal->references;
		
		if (EVP_PKEY_set1_DH(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
#if !defined(NO_DH)
	TDHObj::TDHObj (const TDHObj& obj)
		:	Inherited(),
			fInternal(NULL)
	{
		fInternal = const_cast<DH*>(obj.fInternal);
		++fInternal->references;
		
		if (EVP_PKEY_set1_DH(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
#if !defined(NO_DH)
	TDHObj::~TDHObj ()
	{
		if (fInternal)
		{
			DH_free(fInternal);
			fInternal = NULL;
		}
		fIsSet = false;
		fSharedSecret = "";
	}
#endif

//---------------------------------------------------------------------
// TDHObj::GenerateParameters
//---------------------------------------------------------------------
#if !defined(NO_DH)
	void TDHObj::GenerateParameters (int primeLengthInBits, int generator)
	{
		bool				doGenerate = true;
		
		while (doGenerate)
		{
			int		checkCodes = 0;
			
			Setup();
			
			// Seed the random number generator
			if (!TSSLEnvironment::PRNGIsValid())
				TSSLEnvironment::PRNGSeed(primeLengthInBits*2);
			
			// Generate the Diffie-Hellman parameters
			fInternal = DH_generate_parameters(primeLengthInBits,generator,NULL,NULL);
			if (!fInternal)
				throw TSSLErrorObj(kSSLPKeyNotInited);
			
			// Check the DH parameters just generated
			if (DH_check(fInternal,&checkCodes) == 1)
			{
				if ((checkCodes & DH_UNABLE_TO_CHECK_GENERATOR) != 0)
					throw TSSLErrorObj(kSSLDHGeneratorInvalid);
				if ((checkCodes & DH_NOT_SUITABLE_GENERATOR) != 0)
					throw TSSLErrorObj(kSSLDHGeneratorNotSuitable);
				
				if (checkCodes == 0)
					doGenerate = false;
			}
		}
		
		// Generate the key from the parameters
		if (DH_generate_key(fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TDHObj::SetParameters
//---------------------------------------------------------------------
#if !defined(NO_DH)
	void TDHObj::SetParameters (const TBigNumBuffer& p, const TBigNumBuffer& g)
	{
		Setup();
		
		// Get a new, empty DH object
		fInternal = DH_new();
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		// Set the DH internal slots
		fInternal->p = BN_dup(p);
		fInternal->g = BN_dup(g);
		
		// Generate the key from the parameters
		if (DH_generate_key(fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TDHObj::SetParameters
//---------------------------------------------------------------------
#if !defined(NO_DH)
	void TDHObj::SetParameters (const std::string& parameters)
	{
		#if DH_PARAM_BUFFER_PTR_IS_CONST
			const unsigned char*		ptr = reinterpret_cast<const unsigned char*>(parameters.data());
		#else
			unsigned char*		ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(parameters.data()));
		#endif
		
		Cleanup();
		
		// Set the parameters from the buffer
		fInternal = d2i_DHparams(NULL,&ptr,parameters.length());
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		// Set the EVP object
		if (EVP_PKEY_set1_DH(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
	}
#endif

//---------------------------------------------------------------------
// TDHObj::SetParameters
//---------------------------------------------------------------------
#if !defined(NO_DH)
	void TDHObj::SetParameters (TFileObj& pkeyFileObj)
	{
		FILE*	streamPtr = NULL;
		
		if (!pkeyFileObj.Exists())
			throw TSymLibErrorObj(ENOENT,"Public key file does not exist");
		
		Setup();
		
		// Open a stream to the file
		streamPtr = fopen(pkeyFileObj.Path().c_str(),"r");
		if (streamPtr)
		{
			try
			{
				fInternal = PEM_read_DHparams(streamPtr,NULL,NULL,NULL);
				if (!fInternal)
					throw TSSLErrorObj(kSSLPKeyCannotReadFromFile);
				
				// Close the file
				fclose(streamPtr);
				
				// Set the EVP object
				if (EVP_PKEY_set1_DH(fPKeyPtr,fInternal) != 1)
					throw TSSLErrorObj(kSSLPKeyNotInited);
			}
			catch (...)
			{
				// Close the stream before passing the exception through
				fclose(streamPtr);
				throw;
			}
		}
		else
			throw TSymLibErrorObj(errno);
	}
#endif

//---------------------------------------------------------------------
// TDHObj::GenerateKeys
//---------------------------------------------------------------------
#if !defined(NO_DH)
	void TDHObj::GenerateKeys (const TBigNumBuffer& publicKey)
	{
		int		sharedSecretSize = 0;
		
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		// Prep the shared secret buffer
		fSharedSecret.resize(DH_size(fInternal));
		
		// Compute the shared secret
		sharedSecretSize = DH_compute_key(const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(fSharedSecret.data())),const_cast<BIGNUM*>(publicKey.AsBigNumPtr()),fInternal);
		if (sharedSecretSize == -1)
			throw TSSLErrorObj(kSSLDHSharedSecretNotSet);
		
		// Adjust the buffer size
		fSharedSecret.resize(sharedSecretSize);
		
		// Setup the EVP object
		if (EVP_PKEY_set1_DH(fPKeyPtr,fInternal) != 1)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		fIsSet = true;
	}
#endif

//---------------------------------------------------------------------
// TDHObj::Parameters
//---------------------------------------------------------------------
#if !defined(NO_DH)
	std::string TDHObj::Parameters ()
	{
		std::string	buffer;
		int			bufferSize = 0;
		
		if (!IsSet())
			throw TSSLErrorObj(kSSLPKeyAlgoNotSet);
		
		// Determine the size of the parameters
		bufferSize = i2d_DHparams(fInternal,NULL);
		if (bufferSize > 0)
		{
			unsigned char*		ptr = NULL;
			
			// Prep the buffer
			buffer.resize(bufferSize);
			ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buffer.data()));
			
			// Get the parameters
			i2d_DHparams(fInternal,&ptr);
		}
		
		return buffer;
	}
#endif

//---------------------------------------------------------------------
// TDHObj::WriteParametersToFile
//---------------------------------------------------------------------
#if !defined(NO_DH)
	void TDHObj::WriteParametersToFile (TFileObj& pkeyFileObj)
	{
		FILE*	streamPtr = NULL;
		
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		if (pkeyFileObj.Exists())
			throw TSymLibErrorObj(EEXIST);
		
		// Manage the file we were given to make sure it's opened appropriately
		pkeyFileObj.Create(S_IRUSR|S_IWUSR,true);
		
		// Open a stream to the file
		streamPtr = fopen(pkeyFileObj.Path().c_str(),"w");
		if (streamPtr)
		{
			try
			{
				if (PEM_write_DHparams(streamPtr,fInternal) != 1)
					throw TSSLErrorObj(kSSLPKeyCannotWriteToFile);
				
				// Close the file
				fclose(streamPtr);
			}
			catch (...)
			{
				// Close the stream before passing the exception through
				fclose(streamPtr);
				throw;
			}
		}
		else
			throw TSymLibErrorObj(errno);
	}
#endif

//---------------------------------------------------------------------
// TDHObj::P
//---------------------------------------------------------------------
#if !defined(NO_DH)
	TBigNumBuffer TDHObj::P () const
	{
		TBigNumBuffer		bigNumBuffer;
		
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		bigNumBuffer = fInternal->p;
		
		return bigNumBuffer;
	}
#endif

//---------------------------------------------------------------------
// TDHObj::G
//---------------------------------------------------------------------
#if !defined(NO_DH)
	TBigNumBuffer TDHObj::G () const
	{
		TBigNumBuffer		bigNumBuffer;
		
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		bigNumBuffer = fInternal->g;
		
		return bigNumBuffer;
	}
#endif

//---------------------------------------------------------------------
// TDHObj::PublicKey
//---------------------------------------------------------------------
#if !defined(NO_DH)
	TBigNumBuffer TDHObj::PublicKey () const
	{
		TBigNumBuffer		bigNumBuffer;
		
		if (!fInternal)
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		bigNumBuffer = fInternal->pub_key;
		
		return bigNumBuffer;
	}
#endif

//---------------------------------------------------------------------
// TDHObj::SharedSecret
//---------------------------------------------------------------------
#if !defined(NO_DH)
	std::string TDHObj::SharedSecret () const
	{
		if (!IsSet())
			throw TSSLErrorObj(kSSLPKeyNotInited);
		
		return fSharedSecret;
	}
#endif

//---------------------------------------------------------------------
// TDHObj::Cleanup (protected)
//---------------------------------------------------------------------
#if !defined(NO_DH)
	void TDHObj::Cleanup ()
	{
		if (fInternal)
		{
			DH_free(fInternal);
			fInternal = NULL;
		}
		fIsSet = false;
		fSharedSecret = "";
		
		Inherited::Cleanup();
	}
#endif

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

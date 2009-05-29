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

#if !defined(SYMLIB_SSL_UTIL)
#define SYMLIB_SSL_UTIL

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-config.h"

#include "symlib-exception.h"
#include "symlib-file.h"
#include "symlib-threads.h"

#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"

#define OPENSSL_THREAD_DEFINES
#include "openssl/opensslconf.h"
#if defined(THREADS) || defined(OPENSSL_THREADS)
	#define	SYMLIB_SSL_THREADS
#endif

#if !defined(OPENSSL_VERSION_NUMBER) || (OPENSSL_VERSION_NUMBER < 0x0090603fL)
	#error OpenSSL version 0.9.6c or later is required for this library
#elif OPENSSL_VERSION_NUMBER == 0x0090603fL
	// We need to rewrite one macro defined in evp.h that had a syntax error
	#undef EVP_CIPHER_mode
	#define EVP_CIPHER_mode(e)		((e)->flags & EVP_CIPH_MODE)
#endif

//---------------------------------------------------------------------
// Pre-namespace Definitions
//---------------------------------------------------------------------
#if defined(SYMLIB_SSL_THREADS)
	struct CRYPTO_dynlock_value
		{
			symbiot::TPthreadMutexObj*	mutexObjPtr;
		};
#endif

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

// Error codes used throughout the SSL library suite
#define		kSSLMessageDigestAlgoUnknown					-31011
#define		kSSLMessageDigestAlgoNotSet						-31012
#define		kSSLMessageDigestNotInited						-31013
#define		kSSLMessageDigestNotCopied						-31014

#define		kSSLCipherAlgoUnknown							-31021
#define		kSSLCipherAlgoNotSet							-31022
#define		kSSLCipherNotInited								-31023
#define		kSSLCipherInitFailure							-31024
#define		kSSLCipherUpdateFailure							-31025
#define		kSSLCipherFinalFailure							-31026
#define		kSSLCipherSetKeyLengthFailure					-31027
#define		kSSLCipherCleanupFailure						-31028

#define		kSSLPKeyAlgoUnknown								-31031
#define		kSSLPKeyAlgoNotSet								-31032
#define		kSSLPKeyNotInited								-31033
#define		kSSLDHGeneratorInvalid							-31034
#define		kSSLDHGeneratorNotSuitable						-31035
#define		kSSLDHSharedSecretNotSet						-31036
#define		kSSLPKeyCannotDecrypt							-31037
#define		kSSLPKeyCannotEncrypt							-31038
#define		kSSLPKeyCannotWriteToFile						-31039
#define		kSSLPKeyCannotReadFromFile						-31040

#define		kSSLSigningContextNotInited						-31041
#define		kSSLSigningContextSignatureFailure				-31042

#define		kSSLEnvelopeContextNotInited					-31051
#define		kSSLEnvelopeInitFailure							-31052
#define		kSSLEnvelopeUpdateFailure						-31053
#define		kSSLEnvelopeInvalidKeyIndex						-31054

#define		kSSLRANDCannotGenerateSeedFilePath				-31061
#define		kSSLRANDCannotWriteSeedFile						-31062
#define		kSSLRANDCannotReadSeedFile						-31063
#define		kSSLRANDCannotObtainBytes						-31064

#define		kSSLX509NotInited								-31071
#define		kSSLX509InitFailure								-31072
#define		kSSLX509CopyFailure								-31073
#define		kSSLX509UnableToSetVersion						-31074
#define		kSSLX509UnableToSetSerialNumber					-31075

#define		kSSLSSLContextSetMethodFailure					-31081
#define		kSSLSSLInitializeFailure						-31082
#define		kSSLSSLNotInited								-31083
#define		kSSLUnableToSetNetworkSocket					-31084
#define		kSSLUnableToShutdownConnection					-31085
#define		kSSLAlreadyConnected							-31086
#define		kSSLNotConnected								-31087
#define		kSSLConnectionTerminated						-31088
#define		kSSLNoDataToReadOrWrite							-31089
#define		kSSLNoValidCiphers								-31090
#define		kSSLCannotSetPrivateKey							-31091
#define		kSSLCannotSetCertificate						-31092
#define		kSSLCannotSetCertificateAuthority				-31093
#define		kSSLPrivateKeyFailedVerification				-31094
#define		kSSLSessionNotInited							-31095
#define		kSSLCannotSetSessionTime						-31096
#define		kSSLCannotSetSessionTimeout						-31097
#define		kSSLCannotAddSession							-31098
#define		kSSLContextNotInited							-31099
#define		kSSLContextIDCannotBeSet						-31100
#define		kSSLSessionIsInvalidError						-31101
#define		kSSLPeerCertificateMissing						-31102
#define		kSSLPeerCertificateVerificationFailure			-31103

// Definitions of the functions used by the random number generator.
// Provided as a convenience for function calls.
typedef		void (*RANDSeedFunc)(const void* buf, int num);
typedef		void (*RANDAddBytesFunc)(const void* buf, int num, double entropy);
typedef		int (*RANDGetBytesFunc)(unsigned char* buf, int num);
typedef		int (*RANDGetPseudoBytesFunc)(unsigned char* buf, int num);
typedef		int (*RANDStatusFunc)();
typedef		void (*RANDCleanupFunc)();

//---------------------------------------------------------------------
// Macros
//---------------------------------------------------------------------
#if !defined(Max)
	#define Max(x,y)			((x >= y) ? x : y)
#endif

#if !defined(Min)
	#define Min(x,y)			((x <= y) ? x : y)
#endif

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TSSLEnvironment;
class TPRNGStateFileObj;
class TBigNumBuffer;
class TUpdateScanMixin;
class TUpdateMorphMixin;
class TSSLErrorObj;

//---------------------------------------------------------------------
// Global Variables
//---------------------------------------------------------------------
extern TSSLEnvironment	gSSLEnvironmentObj;

//---------------------------------------------------------------------
// Class TSSLEnvironment
//
// A catch-all class that encompasses random pieces of the OpenSSL
// architecture.  Some items need to be loaded by a singleton, which
// explains the global TSSLEnvironment object found in the source file.
// Many methods are static, defined here mainly to provide a unique
// namespace for them.
//---------------------------------------------------------------------
class TSSLEnvironment
{
	private:
		
		#if defined(SYMLIB_SSL_THREADS)
			typedef std::map<int,TPthreadMutexObj*,std::less<int> >			LockMap;
			typedef LockMap::iterator										LockMap_iter;
			typedef LockMap::const_iterator									LockMap_const_iter;
			
			typedef std::vector<CRYPTO_dynlock_value*>						DynLockList;
			typedef DynLockList::iterator									DynLockList_iter;
			typedef DynLockList::const_iterator								DynLockList_const_iter;
		#endif
	
	public:
		
		TSSLEnvironment ();
			// Constructor
			// OpenSSL functions:  CRYPTO_set_locking_callback, CRYPTO_set_id_callback,
			// CRYPTO_set_dynlock_create_callback, CRYPTO_set_dynlock_lock_callback,
			// CRYPTO_set_dynlock_destroy_callback
	
	private:
		
		TSSLEnvironment (const TSSLEnvironment&) {}
			// Copy constructor is illegal
	
	public:
		
		~TSSLEnvironment ();
			// Destructor
			// OpenSSL functions:  EVP_cleanup
		
		void LoadAllDigestAlgorithms ();
			// Ensures that all message digest algorithms are loaded.  Thread-aware.
			// OpenSSL functions:  OpenSSL_add_all_digests
		
		void LoadAllCipherAlgorithms ();
			// Ensures that all message encryption algorithms are loaded.  Thread-aware.
			// OpenSSL functions:  OpenSSL_add_all_ciphers
		
		void LoadAllSSLAlgorithms ();
			// Ensures that all SSL algorithms are loaded.  Thread-aware.
			// OpenSSL functions:  OpenSSL_add_all_digests, OpenSSL_add_all_ciphers
		
		// -------------------------------------
		// Accessors
		// -------------------------------------
		
		#if defined(SYMLIB_SSL_THREADS)
			inline LockMap& LockMapRef ()
				{ return fLockMap; }
			
			inline TPthreadMutexObj& LockMapMutexRef ()
				{ return fLockMapMutex; }
			
			inline DynLockList& DynLockListRef ()
				{ return fDynLockList; }
			
			inline TPthreadMutexObj& DynLockListMutexRef ()
				{ return fDynLockListMutex; }
		#endif
		
		// -------------------------------------
		// Static Methods
		// -------------------------------------
		
		static std::string GetVersionString ();
			// Returns the textual representation of the OpenSSL library currently in use.
			// OpenSSL functions:  SSLeay_version
		
		static unsigned long GetMajorVersion ();
			// Returns the major version number of the OpenSSL library currently in use.
			// OpenSSL functions:  SSLeay
		
		static unsigned long GetMinorVersion ();
			// Returns the minor version number of the OpenSSL library currently in use.
			// OpenSSL functions:  SSLeay
		
		static unsigned long GetFixVersion ();
			// Returns the 'fix' version number of the OpenSSL library currently in use.
			// OpenSSL functions:  SSLeay
		
		static unsigned long GetPatchVersion ();
			// Returns the 'patch' version number of the OpenSSL library currently in use.
			// When the full version is converted to text, the number returned by this
			// method is converted to a character (1 = 'a', etc.).
			// OpenSSL functions:  SSLeay
		
		static unsigned long GetStatusVersion ();
			// Returns the 'status' version number of the OpenSSL library currently in use.
			// A status of zero indicates development; status values 1-14 indicate beta;
			// a status of 15 indicates final.
			// OpenSSL functions:  SSLeay
		
		static std::string DefaultPasswordPrompt ();
			// Returns the current default password prompt as defined within OpenSSL.
			// OpenSSL functions:  EVP_get_pw_prompt
		
		static std::string GetPWFromSTDIN (const std::string& prompt, bool verify);
			// Prompts the user for a password using the given prompt.  The method
			// adds a ':' character to the end of the prompt, so you shouldn't
			// provide one.
		
		static int GetPWFromSTDINCallback (char* buf, int size, int rwflag, void* u);
			// Used by SSL PEM routines to prompt the user for a password or passphrase.
			// The entered value should be stuffed into the buf argument, which cannot
			// exceed size bytes in length.  The u argument, if not NULL, should be
			// the NULL-terminated prompt.  Method returns the length of the entered
			// value, or zero if there has been a problem.
		
		static TFileObj PRNGDefaultStateFileObj ();
			// Returns a file object pointing to the default location for
			// a PRNG seed file.
			// OpenSSL functions:  RAND_file_name
		
		static void PRNGWriteStateToFile (TFileObj& fileObj);
			// Saves the state of the current PRNG to the file indicated
			// by the argument.
			// OpenSSL functions:  RAND_write_file
		
		static void PRNGReadStateFromFile (TFileObj& fileObj);
			// Loads a PRNG state previously saved via a call to PRNGWriteStateToFile().
			// OpenSSL functions:  RAND_load_file
		
		static bool PRNGIsValid ();
			// Returns true if the current PRNG has been seeded with enough data to
			// return valid random numbers.  Calls the current RANDStatusFunc
			// function.
		
		static void PRNGCleanup ();
			// Resets and reinitializes the current PRNG.  Calls the current
			// RANDCleanupFunc function.
		
		static void PRNGSeed (const void* buffer, int bufferSize);
			// Seeds the current PRNG with the contents of the memory pointed to by
			// buffer, which is bufferSize in length. Calls the current RANDSeedFunc function.
		
		static void PRNGSeed (const std::string& buffer);
			// Seeds the current PRNG with the contents of the given buffer.
		
		static void PRNGSeed (unsigned long byteCount);
			// Seeds the current PRNG straight from the /dev/random number generator.
			// Possibly not a great idea, but definitely an easy way to kick the PRNG
			// in the ass to get it started.
		
		static void PRNGAddBytes (const void* buffer, int bufferSize, double entropyValue = 0);
			// Adds the bytes pointed to by the buffer argument, which is bufferSize
			// in length, to the current PRNG state.  The entropyValue
			// argument is (the lower bound of) an estimate of how much randomness
			// is contained in buffer, measured in bytes.  Calls the current
			// RANDAddBytesFunc function.
		
		static void PRNGAddBytes (const std::string& buffer, double entropyValue = 0);
			// Adds the bytes pointed to by the buffer argument, which is bufferSize to
			// the current PRNG state.  The entropyValue argument is (the lower bound of)
			// an estimate of how much randomness is contained in buffer, measured in bytes.
		
		static void PRNGAddBytes (unsigned long byteCount);
			// Adds the given number of bytes from the /dev/random number generator to
			// the current PRNG.  This is the simplest, albeit not the most secure, way
			// to stir additional information into the PRNG.
		
		static std::string PRNGGetBytes (int numBytes);
			// Retrieves numBytes of cryptographically-strong random numbers from the
			// current PRNG and returns them in a temporary std::string object.  Calls the
			// current RANDGetBytesFunc function.
		
		static std::string PRNGGetPseudoBytes (int numBytes);
			// Retrieves numBytes of random numbers from the current PRNG and returns
			// them in a std::string object.  The numbers returned are not necessarily
			// cryptographically strong.  Calls the current RANDGetPseudoBytesFunc function.
		
		static RAND_METHOD_TYPE* RANDMethodStructPtr ();
			// Returns the RAND_METHOD structure OpenSSL uses for random number generation.
			// OpenSSL functions: RAND_get_rand_method
		
		static void RANDSetMethodStructPtr (RAND_METHOD_TYPE* methodStructPtr);
			// Sets the RAND_METHOD structure OpenSSL uses for random number generation.
			// OpenSSL functions: RAND_set_rand_method
		
		static RANDSeedFunc RANDSeedFunctionPtr ();
			// Returns the function pointer used to seed the random number generator or
			// NULL if the function is not implemented.  Calls RANDMethodStructPtr() to
			// retrieve the current RAND_METHOD structure.
		
		static void RANDSetSeedFunctionPtr (RANDSeedFunc seedFunctionPtr);
			// Sets the function pointer used to seed the random number generator.  Calls
			// RANDMethodStructPtr() to retrieve the current RAND_METHOD structure.
		
		static RANDAddBytesFunc RANDAddBytesFunctionPtr ();
			// Returns the function pointer used to add entropy to the random number generator
			// or NULL if the function is not implemented.  Calls RANDMethodStructPtr() to
			// retrieve the current RAND_METHOD structure.
		
		static void RANDSetAddBytesFunctionPtr (RANDAddBytesFunc addBytesFunctionPtr);
			// Sets the function pointer used to add entropy to the random number generator.
			// Calls RANDMethodStructPtr() to retrieve the current RAND_METHOD structure.
		
		static inline RANDGetBytesFunc RANDGetBytesFunctionPtr ();
			// Returns the function pointer used to get data from the random number generator
			// or NULL if the function is not implemented.  Calls RANDMethodStructPtr() to
			// retrieve the current RAND_METHOD structure.
		
		static void RANDSetGetBytesFunctionPtr (RANDGetBytesFunc getBytesFunctionPtr);
			// Sets the function pointer used to get data from the random number generator.
			// Calls RANDMethodStructPtr() to retrieve the current RAND_METHOD structure.
		
		static RANDGetPseudoBytesFunc RANDGetPseudoBytesFunctionPtr ();
			// Returns the function pointer used to get pseudorandom data from the random number generator
			// or NULL if the function is not implemented.  Calls RANDMethodStructPtr() to
			// retrieve the current RAND_METHOD structure.
		
		static void RANDSetGetPseudoBytesFunctionPtr (RANDGetPseudoBytesFunc getPseudoBytesFunctionPtr);
			// Sets the function pointer used to get pseudorandom data from the random number generator.
			// Calls RANDMethodStructPtr() to retrieve the current RAND_METHOD structure.
		
		static RANDStatusFunc RANDStatusFunctionPtr ();
			// Returns the function pointer used to get the current status of the random number generator
			// or NULL if the function is not implemented.  Calls RANDMethodStructPtr() to
			// retrieve the current RAND_METHOD structure.
		
		static void RANDSetStatusFunctionPtr (RANDStatusFunc statusFunctionPtr);
			// Sets the function pointer used to get the current status of the random number generator.
			// Calls RANDMethodStructPtr() to retrieve the current RAND_METHOD structure.
		
		static RANDCleanupFunc RANDCleanupFunctionPtr ();
			// Returns the function pointer used to cleanup/teardown the random number generator
			// or NULL if the function is not implemented.  Calls RANDMethodStructPtr() to
			// retrieve the current RAND_METHOD structure.
		
		static void RANDSetCleanupFunctionPtr (RANDCleanupFunc cleanupFunctionPtr);
			// Sets the function pointer used to clean/teardown the the random number generator.
			// Calls RANDMethodStructPtr() to retrieve the current RAND_METHOD structure.
		
	#if defined(SYMLIB_SSL_THREADS)
		private:
			
			static void LockFunction (int mode, int n, const char* file, int line);
				// Callback function required by SSL library.  Seizes or
				// releases the lock indexed by n, depending on the value
				// of the mode argument.
			
			static unsigned long IDFunction ();
				// Callback function required by the SSL library.  Returns an ID
				// for the current thread.
			
			static CRYPTO_dynlock_value* CreateDynamicLock (const char* file, int line);
				// Callback function required by the SSL library.  Creates a
				// dynamic lock and returns a pointer to a structure containing
				// that lock.
			
			static void SetDynamicLock (int mode, CRYPTO_dynlock_value* lockPtr, const char* file, int line);
				// Callback function required by the SSL library.  Seizes or
				// releases the lock indicated by the lockptr argument, depending
				// on the value of the mode argument.
			
			static void DestroyDynamicLock (CRYPTO_dynlock_value* lockPtr, const char* file, int line);
				// Callback function required by the SSL library.  Destroys the
				// lock indicated by the lockPtr argument.
	#endif
		
		private:
			
			bool									fDigestAlgosLoaded;
			bool									fCipherAlgosLoaded;
			TPthreadMutexObj						fAlgorithmLoadMutex;
			#if defined(SYMLIB_SSL_THREADS)
				LockMap								fLockMap;
				TPthreadMutexObj					fLockMapMutex;
				DynLockList							fDynLockList;
				TPthreadMutexObj					fDynLockListMutex;
			#endif
};

//---------------------------------------------------------------------
// Class TPRNGStateFileObj
//
// This class manages a seed file for the current random number generator.
// The constructor for the object can be passed a path or TFileObj that
// points to a (possibly nonexisting) seed file.  If the file is present
// then its contents are used to seed the current PRNG.  The destructor
// for the object writes the current PRNG state back to the file.  Note
// that everything is wrapped in try/catch blocks that effectively
// suppress exceptions.  If no path or TFileObj is passed to the constructor
// then the default path (as per OpenSSL) is used.
//---------------------------------------------------------------------
class TPRNGStateFileObj
{
	public:
		
		TPRNGStateFileObj () : fValid(false)
			{
				try
				{
					fStateFileObj = TSSLEnvironment::PRNGDefaultStateFileObj();
					if (fStateFileObj.Exists())
						TSSLEnvironment::PRNGReadStateFromFile(fStateFileObj);
					fValid = true;
				}
				catch (...)
				{
				}
			}
		
		TPRNGStateFileObj (const TFileObj& stateFileObj) : fStateFileObj(stateFileObj),fValid(false)
			{
				try
				{
					if (fStateFileObj.Exists())
						TSSLEnvironment::PRNGReadStateFromFile(fStateFileObj);
					fValid = true;
				}
				catch (...)
				{
				}
			}
		
		~TPRNGStateFileObj ()
			{
				try
				{
					if (fValid)
						TSSLEnvironment::PRNGWriteStateToFile(fStateFileObj);
				}
				catch (...)
				{
				}
			}
		
		inline bool IsValid () const
			{ return fValid; }
		
		inline std::string Path () const
			{ return fStateFileObj.Path(); }
		
		inline bool Exists () const
			{ return fStateFileObj.Exists(); }
	
	private:
		
		TFileObj								fStateFileObj;
		bool									fValid;
};

//---------------------------------------------------------------------
// Class TBigNumBuffer
//
// This is a simple wrapper class for BigNum integers, supported through
// the BN library.  It's primary purpose is to aid in the conversion of
// BigNums to alternate representations, such as hexadecimal.  Since
// coercion operators are defined, you can free substitute an instance
// of this class as either a BigNum or a pointer to a BigNum in function
// calls.
//---------------------------------------------------------------------
class TBigNumBuffer : public std::string
{
	private:
		
		typedef		std::string			Inherited;
	
	public:
		
		TBigNumBuffer ();
			// Constructor
			// OpenSSL functions:  BN_new
		
		TBigNumBuffer (const BIGNUM& bigNum);
			// Constructor
			// OpenSSL functions:  BN_dup
		
		TBigNumBuffer (const BIGNUM* bigNumPtr);
			// Constructor
			// OpenSSL functions:  BN_dup
		
		TBigNumBuffer (unsigned long integer);
			// Constructor
			// OpenSSL functions:  BN_new, BN_set_word
		
		TBigNumBuffer (const TBigNumBuffer& obj);
			// Copy constructor
			// OpenSSL functions:  BN_dup
		
		virtual ~TBigNumBuffer ();
			// Destructor
			// OpenSSL functions:  BN_clear_free
		
		virtual void Clear ();
			// Resets the internal BigNum value.
			// OpenSSL functions:  BN_clear
		
		virtual BIGNUM* AsBigNumPtr ()
			{ return fBigNumPtr; }
		
		virtual const BIGNUM* AsBigNumPtr () const
			{ return fBigNumPtr; }
		
		virtual std::string AsBinary () const;
			// Returns the current BigNum value in binary format.
			// OpenSSL functions:  BN_num_bytes, BN_bn2bin
		
		virtual void FromBinary (const std::string& binary);
			// Overwrites the current BigNum value with the value
			// of the argument, which is in binary format (as if
			// generated by AsBinary()).
			// OpenSSL functions:  BN_bin2bn
		
		virtual std::string AsHex () const;
			// Returns a printable hexadecimal version of the current
			// BigNum value.
			// OpenSSL functions:  BN_bn2hex, OPENSSL_free
		
		virtual void FromHex (const std::string& hex);
			// Overwrites the current BigNum value with the value
			// of the argument, which is in hexadecimal format (as if
			// generated by AsHex()).
			// OpenSSL functions:  BN_hex2bn
		
		virtual std::string AsDecimal () const;
			// Returns a printable decimal version of the current
			// BigNum value.
			// OpenSSL functions:  BN_bn2dec, OPENSSL_free
		
		virtual void FromDecimal (const std::string& decimal);
			// Overwrites the current BigNum value with the value
			// of the argument, which is in decimal format (as if
			// generated by AsDecimal()).
			// OpenSSL functions:  BN_dec2bn
		
		virtual TBigNumBuffer Sqrt ();
			// Returns the integer portion of the square root of the
			// current value as a temporary bignum buffer.
			// OpenSSL functions:  BN_num_bits, BN_lshift, BN_is_bit_set,
			// BN_set_bit, BN_lshift1, BN_cmp, BN_sub
		
		inline const BIGNUM* Ptr () const
			{ return fBigNumPtr; }
		
		inline BIGNUM* Ptr ()
			{ return fBigNumPtr; }
		
		inline TBigNumBuffer& operator= (const BIGNUM num)
			{ BN_copy(fBigNumPtr,&num); return *this; }
		
		inline TBigNumBuffer& operator= (const BIGNUM* numPtr)
			{ BN_copy(fBigNumPtr,numPtr); return *this; }
		
		inline TBigNumBuffer& operator= (unsigned long integer)
			{ BN_set_word(fBigNumPtr,integer); return *this; }
		
		inline TBigNumBuffer& operator= (const TBigNumBuffer& numObj)
			{ BN_copy(fBigNumPtr,numObj.fBigNumPtr); return *this; }
		
		inline operator const BIGNUM () const
			{ return *fBigNumPtr; }
		
		inline operator BIGNUM ()
			{ return *fBigNumPtr; }
		
		inline operator const BIGNUM* () const
			{ return fBigNumPtr; }
		
		inline operator BIGNUM* ()
			{ return fBigNumPtr; }
	
	protected:
		
		BIGNUM*									fBigNumPtr;
};

//---------------------------------------------------------------------
// Class TUpdateScanMixin
//
// A simple mix-in class that loops through a file, reading chunks
// and then calling another method with those chunks.  The purpose is
// to simply scan through the chunks and perform some kind of non-
// intrusive process on them.
//
// This class should be used only as a mix-in and never instantiated
// on its own.
//---------------------------------------------------------------------
class TUpdateScanMixin
{
	public:
		
		virtual void Update (const std::string& buffer) = 0;
			// Must be overridden in subclasses.  Will process each block
			// of data read by the next method.
		
		virtual void Update (TFileObj& fileObj);
			// Walks the file referenced by the argument and calls
			// Update(const std::string&) with each block read.  If the file is not
			// open then it will be temporarily opened with read-only
			// permissions and then closed before the method returns.
			// If it is already opened then read permission must be
			// allowed; also, the current file position will be preserved.
};

//---------------------------------------------------------------------
// Class TUpdateMorphMixin
//
// A simple mix-in class that loops through a file, reading chunks
// and then calling another method with those chunks.  The purpose is
// to somehow 'morph' the chunks into something else, which helps
// explain why there are in- and out- arguments.
//
// This class should be used only as a mix-in and never instantiated
// on its own.
//---------------------------------------------------------------------
class TUpdateMorphMixin
{
	public:
		
		virtual void Update (std::string& inBuffer, std::string& outBuffer) = 0;
			// Must be overridden in subclasses.  Will process each block
			// of data read by the next method.
		
		virtual void Update (TFileObj& inFileObj, TFileObj& outFileObj);
			// Walks the file referenced by inFileObj and calls
			// Update(std::string&,std::string&) with each block read, appending
			// the results to the file referenced by outFileObj.  If inFileObj
			// is not open then it will be temporarily opened with read-only
			// permissions and then closed before the method returns.
			// If it is already opened then read permission must be
			// allowed; also, the current file position will be preserved.
			// outFileObj will be created if it doesn't already exist.
			// outFileObj will be left open so further file additions
			// can take place
};

//---------------------------------------------------------------------
// Class TSSLErrorObj
//
// All OpenSSL-specific errors are thrown through this class.  With all
// errors, the class attempts to find the appropriate error description
// through the OpenSSL library and append that to the description provided
// by the function throwing the exception.  If the OpenSSL library did
// not generate the error then only the provided descriptions will be
// returned (obviously).
//---------------------------------------------------------------------
class TSSLErrorObj : public TSymLibErrorObj
{
	private:
		
		typedef		TSymLibErrorObj			Inherited;
	
	public:
		
		TSSLErrorObj (const long errNum, const std::string& description = "");
			// Constructor
			// OpenSSL functions:  ERR_get_error, SSL_load_error_strings,
			// ERR_error_string, ERR_free_strings
		
		inline unsigned long GetSSLErrorCode ()
			{ return fSSLErrorCode; }
		
		inline int GetSSLErrorLib ()
			{ return ERR_GET_LIB(fSSLErrorCode); }
		
		inline int GetSSLErrorFunction ()
			{ return ERR_GET_FUNC(fSSLErrorCode); }
		
		inline int GetSSLErrorReason ()
			{ return ERR_GET_REASON(fSSLErrorCode); }
		
	protected:
		
		void MakeDescription ();
			// Override.
	
	protected:
		
		unsigned long							fSSLErrorCode;
};

//*********************************************************************
// Global Function Declarations
//*********************************************************************

TSSLEnvironment* SSLEnvironmentObjPtr ();
	// Singleton access to a module global.

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif

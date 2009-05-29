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
#include "symlib-ssl-util.h"

#include "symlib-utils.h"

#include <algorithm>
#include <map>
#include <vector>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Module Definitions
//---------------------------------------------------------------------
#if defined(SYMLIB_SSL_THREADS)
	typedef std::map<int,TPthreadMutexObj*,std::less<int> >	LockMap;
	typedef LockMap::iterator								LockMap_iter;
	typedef LockMap::const_iterator							LockMap_const_iter;
	
	typedef std::vector<CRYPTO_dynlock_value*>				DynLockList;
	typedef DynLockList::iterator							DynLockList_iter;
	typedef DynLockList::const_iterator						DynLockList_const_iter;
#endif

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
TSSLEnvironment*				gSSLEnvironmentObjPtr = NULL;
static	TPthreadMutexObj		gSSLEnvironmentObjPtrMutex;


//*********************************************************************
// Class TSSLEnvironment
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLEnvironment::TSSLEnvironment ()
	:	fDigestAlgosLoaded(false),
		fCipherAlgosLoaded(false)
{
	#if defined(SYMLIB_SSL_THREADS)
		// Set callbacks for SSL thread management
		CRYPTO_set_locking_callback(LockFunction);
		CRYPTO_set_id_callback(IDFunction);
		CRYPTO_set_dynlock_create_callback(CreateDynamicLock);
		CRYPTO_set_dynlock_lock_callback(SetDynamicLock);
		CRYPTO_set_dynlock_destroy_callback(DestroyDynamicLock);
	#endif
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSSLEnvironment::~TSSLEnvironment ()
{
	EVP_cleanup();
	
	#if defined(SYMLIB_SSL_THREADS)
		// Make sure our 'standard' locks are destroyed
		for (LockMap_iter x = fLockMap.begin(); x != fLockMap.end(); x++)
		{
			if (x->second != NULL)
				delete(x->second);
		}
		fLockMap.clear();
		
		// Make sure that all dynamic locks are destroyed
		while (!fDynLockList.empty())
		{
			if (fDynLockList.back())
			{
				if (fDynLockList.back()->mutexObjPtr != NULL)
					delete(fDynLockList.back()->mutexObjPtr);
				if (fDynLockList.back() != NULL)
					delete(fDynLockList.back());
			}
			fDynLockList.pop_back();
		}
	#endif
}

//---------------------------------------------------------------------
// TSSLEnvironment::LoadAllDigestAlgorithms
//---------------------------------------------------------------------
void TSSLEnvironment::LoadAllDigestAlgorithms ()
{
	if (!fDigestAlgosLoaded)
	{
		TLockedPthreadMutexObj	lock(fAlgorithmLoadMutex);
		
		if (!fDigestAlgosLoaded)
		{
			OpenSSL_add_all_digests();
			fDigestAlgosLoaded = true;
		}
	}
}

//---------------------------------------------------------------------
// TSSLEnvironment::LoadAllCipherAlgorithms
//---------------------------------------------------------------------
void TSSLEnvironment::LoadAllCipherAlgorithms ()
{
	if (!fCipherAlgosLoaded)
	{
		TLockedPthreadMutexObj	lock(fAlgorithmLoadMutex);
		
		if (!fCipherAlgosLoaded)
		{
			#if (OPENSSL_VERSION_NUMBER > 0x0090800aL)
				SSL_library_init();
			#endif
			OpenSSL_add_all_ciphers();
			fCipherAlgosLoaded = true;
		}
	}
}

//---------------------------------------------------------------------
// TSSLEnvironment::LoadAllSSLAlgorithms
//---------------------------------------------------------------------
void TSSLEnvironment::LoadAllSSLAlgorithms ()
{
	if (!fDigestAlgosLoaded || !fCipherAlgosLoaded)
	{
		TLockedPthreadMutexObj	lock(fAlgorithmLoadMutex);
		
		if (!fDigestAlgosLoaded)
		{
			#if (OPENSSL_VERSION_NUMBER > 0x0090800aL)
				SSL_library_init();
			#endif
			OpenSSL_add_all_digests();
			fDigestAlgosLoaded = true;
		}
		
		if (!fCipherAlgosLoaded)
		{
			#if (OPENSSL_VERSION_NUMBER > 0x0090800aL)
				SSL_library_init();
			#endif
			OpenSSL_add_all_ciphers();
			fCipherAlgosLoaded = true;
		}
	}
}

//---------------------------------------------------------------------
// TSSLEnvironment::GetVersionString (static)
//---------------------------------------------------------------------
std::string TSSLEnvironment::GetVersionString ()
{
	return std::string(SSLeay_version(SSLEAY_VERSION));
}

//---------------------------------------------------------------------
// TSSLEnvironment::GetMajorVersion (static)
//---------------------------------------------------------------------
unsigned long TSSLEnvironment::GetMajorVersion ()
{
	unsigned long			version = 0;
	const unsigned long		kVersion = SSLeay();
	const unsigned long		kMask = 0xF0000000L;
	const unsigned long		kBitPos = 28;
	
	version = ((kVersion & kMask) >> kBitPos);
	
	return version;
}

//---------------------------------------------------------------------
// TSSLEnvironment::GetMinorVersion (static)
//---------------------------------------------------------------------
unsigned long TSSLEnvironment::GetMinorVersion ()
{
	unsigned long			version = 0;
	const unsigned long		kVersion = SSLeay();
	const unsigned long		kMask = 0x0FF00000L;
	const unsigned long		kBitPos = 20;
	
	version = ((kVersion & kMask) >> kBitPos);
	
	return version;
}

//---------------------------------------------------------------------
// TSSLEnvironment::GetFixVersion (static)
//---------------------------------------------------------------------
unsigned long TSSLEnvironment::GetFixVersion ()
{
	unsigned long			version = 0;
	const unsigned long		kVersion = SSLeay();
	const unsigned long		kMask = 0x000FF000L;
	const unsigned long		kBitPos = 12;
	
	version = ((kVersion & kMask) >> kBitPos);
	
	return version;
}

//---------------------------------------------------------------------
// TSSLEnvironment::GetPatchVersion (static)
//---------------------------------------------------------------------
unsigned long TSSLEnvironment::GetPatchVersion ()
{
	unsigned long			version = 0;
	const unsigned long		kVersion = SSLeay();
	const unsigned long		kMask = 0x00000FF0L;
	const unsigned long		kBitPos = 4;
	
	version = ((kVersion & kMask) >> kBitPos);
	
	return version;
}

//---------------------------------------------------------------------
// TSSLEnvironment::GetStatusVersion (static)
//---------------------------------------------------------------------
unsigned long TSSLEnvironment::GetStatusVersion ()
{
	unsigned long			version = 0;
	const unsigned long		kVersion = SSLeay();
	const unsigned long		kMask = 0x0000000FL;
	
	version = (kVersion & kMask);
	
	return version;
}

//---------------------------------------------------------------------
// TSSLEnvironment::DefaultPasswordPrompt (static)
//---------------------------------------------------------------------
std::string TSSLEnvironment::DefaultPasswordPrompt ()
{
	return std::string(EVP_get_pw_prompt());
}

//---------------------------------------------------------------------
// TSSLEnvironment::GetPWFromSTDIN (static)
//---------------------------------------------------------------------
std::string TSSLEnvironment::GetPWFromSTDIN (const std::string& prompt, bool verify)
{
	std::string		pw1;
	std::string		pw2;
	char*			pwPtr = NULL;
	
	do
	{
		std::string		localPrompt;
		
		localPrompt += prompt + ": ";
		
		// Ask once
		pwPtr = getpass(localPrompt.c_str());
		pw1 = pwPtr;
		// Erase the static buffer
		while (*pwPtr)
		{
			*pwPtr = 0;
			++pwPtr;
		}
		
		if (verify)
		{
			// Ask again
			localPrompt = "";
			localPrompt += prompt + " (to verify): ";
			pwPtr = getpass(localPrompt.c_str());
			pw2 = pwPtr;
			// Erase the static buffer
			while (*pwPtr)
			{
				*pwPtr = 0;
				++pwPtr;
			}
			
			if (pw1 != pw2)
				throw TSymLibErrorObj(EACCES,"Entered passwords did not match");
		}
		else
			pw2 = pw1;
	}
	while (pw1 != pw2);
	
	return pw1;
}

//---------------------------------------------------------------------
// TSSLEnvironment::GetPWFromSTDINCallback (static)
//---------------------------------------------------------------------
int TSSLEnvironment::GetPWFromSTDINCallback (char* buf, int size, int rwflag, void* u)
{
	int				pwLength = 0;
	std::string		pw;
	std::string		prompt;
	
	// Make sure we have some kind of password prompt
	if (u)
		prompt = reinterpret_cast<char*>(u);
	else
		prompt = DefaultPasswordPrompt();
	
	try
	{
		// Get the password from the user
		pw = GetPWFromSTDIN(prompt,(rwflag == 1 ? true : false));
	}
	catch (TSymLibErrorObj& errObj)
	{
		// Ignore the result if the user didn't enter matching passwords
		if (errObj.GetError() != EACCES)
			throw;
	}
	
	// The password can't be longer than size bytes
	pwLength = Min(pw.length(),static_cast<unsigned int>(size));
	if (pwLength > 0)
	{
		// Copy the entered password into the result buffer
		memset(buf,0,size);
		memcpy(buf,pw.data(),pwLength);
	}
	
	return pwLength;
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGDefaultStateFileObj (static)
//---------------------------------------------------------------------
TFileObj TSSLEnvironment::PRNGDefaultStateFileObj ()
{
	TFileObj		fileObj;
	const size_t	kMaxPathSize = 2048;
	char			pathBuffer[kMaxPathSize];
	const char*		ptr = NULL;
	
	memset(pathBuffer,0,kMaxPathSize);
	
	ptr = RAND_file_name(pathBuffer,kMaxPathSize-1);
	
	if (ptr != pathBuffer)
		throw TSSLErrorObj(kSSLRANDCannotGenerateSeedFilePath);
	
	fileObj.SetPath(pathBuffer);
	
	return fileObj;
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGWriteStateToFile (static)
//---------------------------------------------------------------------
void TSSLEnvironment::PRNGWriteStateToFile (TFileObj& fileObj)
{
	// If the file doesn't exist, create it with 0600 permissions
	if (!fileObj.Exists())
		fileObj.Create(S_IRUSR|S_IWUSR,true);
	
	if (RAND_write_file(fileObj.Path().c_str()) <= 0)
		throw TSSLErrorObj(kSSLRANDCannotWriteSeedFile);
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGReadStateFromFile (static)
//---------------------------------------------------------------------
void TSSLEnvironment::PRNGReadStateFromFile (TFileObj& fileObj)
{
	if (!fileObj.Exists())
		throw TSymLibErrorObj(ENOENT);
	
	if (RAND_load_file(fileObj.Path().c_str(),-1) <= 0)
		throw TSSLErrorObj(kSSLRANDCannotReadSeedFile);
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGIsValid (static)
//---------------------------------------------------------------------
bool TSSLEnvironment::PRNGIsValid ()
{
	return (*RANDStatusFunctionPtr())() == 1;
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGCleanup (static)
//---------------------------------------------------------------------
void TSSLEnvironment::PRNGCleanup ()
{
	(*RANDCleanupFunctionPtr())();
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGSeed (static)
//---------------------------------------------------------------------
void TSSLEnvironment::PRNGSeed (const void* buffer, int bufferSize)
{
	(*RANDSeedFunctionPtr())(buffer,bufferSize);
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGSeed (static)
//---------------------------------------------------------------------
void TSSLEnvironment::PRNGSeed (const std::string& buffer)
{
	PRNGSeed(buffer.data(),buffer.length());
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGSeed (static)
//---------------------------------------------------------------------
void TSSLEnvironment::PRNGSeed (unsigned long byteCount)
{
	if (byteCount > 0)
	{
		std::string		buffer;
		
		buffer.resize(byteCount);
		
		// Get the random bytes from /dev/random
		RandomBytes(byteCount,const_cast<char*>(buffer.data()),false);
		PRNGSeed(buffer);
	}
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGAddBytes (static)
//---------------------------------------------------------------------
void TSSLEnvironment::PRNGAddBytes (const void* buffer, int bufferSize, double entropyValue)
{
	(*RANDAddBytesFunctionPtr())(buffer,bufferSize,entropyValue);
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGAddBytes (static)
//---------------------------------------------------------------------
void TSSLEnvironment::PRNGAddBytes (const std::string& buffer, double entropyValue)
{
	PRNGAddBytes(buffer,entropyValue);
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGAddBytes (static)
//---------------------------------------------------------------------
void TSSLEnvironment::PRNGAddBytes (unsigned long byteCount)
{
	if (byteCount > 0)
	{
		std::string		buffer;
		
		buffer.resize(byteCount);
		
		// Get the random bytes from /dev/random
		RandomBytes(byteCount,const_cast<char*>(buffer.data()),false);
		PRNGAddBytes(buffer,0.0);
	}
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGGetBytes (static)
//---------------------------------------------------------------------
std::string TSSLEnvironment::PRNGGetBytes (int numBytes)
{
	std::string		buffer;
	
	if (numBytes > 0)
	{
		buffer.resize(numBytes);
		
		if ((*RANDGetBytesFunctionPtr())(const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buffer.data())),numBytes) <= 0)
			throw TSSLErrorObj(kSSLRANDCannotObtainBytes);
	}
	
	return buffer;
}

//---------------------------------------------------------------------
// TSSLEnvironment::PRNGGetPseudoBytes (static)
//---------------------------------------------------------------------
std::string TSSLEnvironment::PRNGGetPseudoBytes (int numBytes)
{
	std::string		buffer;
	
	if (numBytes > 0)
	{
		buffer.resize(numBytes);
		
		if ((*RANDGetPseudoBytesFunctionPtr())(const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(buffer.data())),numBytes) == -1)
			throw TSSLErrorObj(kSSLRANDCannotObtainBytes);
	}
	
	return buffer;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDMethodStructPtr (static)
//---------------------------------------------------------------------
RAND_METHOD_TYPE* TSSLEnvironment::RANDMethodStructPtr ()
{
	return RAND_get_rand_method();
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDSetMethodStructPtr (static)
//---------------------------------------------------------------------
void TSSLEnvironment::RANDSetMethodStructPtr (RAND_METHOD_TYPE* methodStructPtr)
{
	RAND_set_rand_method(methodStructPtr);
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDSeedFunctionPtr (static)
//---------------------------------------------------------------------
RANDSeedFunc TSSLEnvironment::RANDSeedFunctionPtr ()
{
	return RANDMethodStructPtr()->seed;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDSetSeedFunctionPtr (static)
//---------------------------------------------------------------------
void TSSLEnvironment::RANDSetSeedFunctionPtr (RANDSeedFunc seedFunctionPtr)
{
	const_cast<RAND_METHOD*>(RANDMethodStructPtr())->seed = seedFunctionPtr;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDAddBytesFunctionPtr (static)
//---------------------------------------------------------------------
RANDAddBytesFunc TSSLEnvironment::RANDAddBytesFunctionPtr ()
{
	return RANDMethodStructPtr()->add;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDSetAddBytesFunctionPtr (static)
//---------------------------------------------------------------------
void TSSLEnvironment::RANDSetAddBytesFunctionPtr (RANDAddBytesFunc addBytesFunctionPtr)
{
	const_cast<RAND_METHOD*>(RANDMethodStructPtr())->add = addBytesFunctionPtr;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDSetGetBytesFunctionPtr (static)
//---------------------------------------------------------------------
RANDGetBytesFunc TSSLEnvironment::RANDGetBytesFunctionPtr ()
{
	return RANDMethodStructPtr()->bytes;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDSetGetBytesFunctionPtr (static)
//---------------------------------------------------------------------
void TSSLEnvironment::RANDSetGetBytesFunctionPtr (RANDGetBytesFunc getBytesFunctionPtr)
{
	const_cast<RAND_METHOD*>(RANDMethodStructPtr())->bytes = getBytesFunctionPtr;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDGetPseudoBytesFunctionPtr (static)
//---------------------------------------------------------------------
RANDGetPseudoBytesFunc TSSLEnvironment::RANDGetPseudoBytesFunctionPtr ()
{
	return RANDMethodStructPtr()->pseudorand;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDSetGetPseudoBytesFunctionPtr (static)
//---------------------------------------------------------------------
void TSSLEnvironment::RANDSetGetPseudoBytesFunctionPtr (RANDGetPseudoBytesFunc getPseudoBytesFunctionPtr)
{
	const_cast<RAND_METHOD*>(RANDMethodStructPtr())->pseudorand = getPseudoBytesFunctionPtr;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDStatusFunctionPtr (static)
//---------------------------------------------------------------------
RANDStatusFunc TSSLEnvironment::RANDStatusFunctionPtr ()
{
	return RANDMethodStructPtr()->status;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDSetStatusFunctionPtr (static)
//---------------------------------------------------------------------
void TSSLEnvironment::RANDSetStatusFunctionPtr (RANDStatusFunc statusFunctionPtr)
{
	const_cast<RAND_METHOD*>(RANDMethodStructPtr())->status = statusFunctionPtr;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDCleanupFunctionPtr (static)
//---------------------------------------------------------------------
RANDCleanupFunc TSSLEnvironment::RANDCleanupFunctionPtr ()
{
	return RANDMethodStructPtr()->cleanup;
}

//---------------------------------------------------------------------
// TSSLEnvironment::RANDSetCleanupFunctionPtr (static)
//---------------------------------------------------------------------
void TSSLEnvironment::RANDSetCleanupFunctionPtr (RANDCleanupFunc cleanupFunctionPtr)
{
	const_cast<RAND_METHOD*>(RANDMethodStructPtr())->cleanup = cleanupFunctionPtr;
}

#if defined(SYMLIB_SSL_THREADS)
	//---------------------------------------------------------------------
	// TSSLEnvironment::LockFunction (private static)
	//---------------------------------------------------------------------
	void TSSLEnvironment::LockFunction (int mode, int n, const char* file, int line)
	{
		TPthreadMutexObj*		mutexObjPtr = NULL;
		
		// Find or create a mutex object at that index
		if (SSLEnvironmentObjPtr()->LockMapRef().find(n) == SSLEnvironmentObjPtr()->LockMapRef().end())
		{
			TLockedPthreadMutexObj	lock(SSLEnvironmentObjPtr()->LockMapMutexRef());
			
			mutexObjPtr = new TPthreadMutexObj;
			SSLEnvironmentObjPtr()->LockMapRef()[n] = mutexObjPtr;
		}
		else
		{
			mutexObjPtr = SSLEnvironmentObjPtr()->LockMapRef()[n];
		}
		
		if ((mode & CRYPTO_LOCK) != 0)
			mutexObjPtr->Lock();
		else
			mutexObjPtr->Unlock();
	}
	
	//---------------------------------------------------------------------
	// TSSLEnvironment::IDFunction (private static)
	//---------------------------------------------------------------------
	unsigned long TSSLEnvironment::IDFunction ()
	{
		unsigned long		id = 0;
		
		#if PTHREAD_T_IS_OPAQUE
			id = reinterpret_cast<unsigned long>(reinterpret_cast<void*>(pthread_self()));
		#else
			id = pthread_self();
		#endif
		
		return id;
	}
	
	//---------------------------------------------------------------------
	// TSSLEnvironment::CreateDynamicLock (private static)
	//---------------------------------------------------------------------
	CRYPTO_dynlock_value* TSSLEnvironment::CreateDynamicLock (const char* file, int line)
	{
		TLockedPthreadMutexObj	lock(SSLEnvironmentObjPtr()->DynLockListMutexRef());
		CRYPTO_dynlock_value*	newLockPtr = new CRYPTO_dynlock_value;
		
		newLockPtr->mutexObjPtr = new TPthreadMutexObj;
		SSLEnvironmentObjPtr()->DynLockListRef().push_back(newLockPtr);
		
		return newLockPtr;
	}
	
	//---------------------------------------------------------------------
	// TSSLEnvironment::SetDynamicLock (private static)
	//---------------------------------------------------------------------
	void TSSLEnvironment::SetDynamicLock (int mode, CRYPTO_dynlock_value* lockPtr, const char* file, int line)
	{
		if ((mode & CRYPTO_LOCK) != 0)
			lockPtr->mutexObjPtr->Lock();
		else if ((mode & CRYPTO_UNLOCK) != 0)
			lockPtr->mutexObjPtr->Unlock();
	}
	
	//---------------------------------------------------------------------
	// TSSLEnvironment::DestroyDynamicLock (private static)
	//---------------------------------------------------------------------
	void TSSLEnvironment::DestroyDynamicLock (CRYPTO_dynlock_value* lockPtr, const char* file, int line)
	{
		TLockedPthreadMutexObj	lock(SSLEnvironmentObjPtr()->DynLockListMutexRef());
		
		// Find the lock in our list
		for (DynLockList_iter x = SSLEnvironmentObjPtr()->DynLockListRef().begin(); x != SSLEnvironmentObjPtr()->DynLockListRef().end(); x++)
		{
			if (*x == lockPtr)
			{
				// Found it; destroy it
				if ((*x)->mutexObjPtr)
					delete((*x)->mutexObjPtr);
				if (*x)
					delete(*x);
				break;
			}
		}
	}
#endif

//*********************************************************************
// Class TBigNumBuffer
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TBigNumBuffer::TBigNumBuffer ()
	:	fBigNumPtr(NULL)
{
	fBigNumPtr = BN_new();
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TBigNumBuffer::TBigNumBuffer (const BIGNUM& bigNum)
	:	fBigNumPtr(NULL)
{
	fBigNumPtr = BN_dup(&bigNum);
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TBigNumBuffer::TBigNumBuffer (const BIGNUM* bigNumPtr)
	:	fBigNumPtr(NULL)
{
	fBigNumPtr = BN_dup(bigNumPtr);
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TBigNumBuffer::TBigNumBuffer (unsigned long integer)
	:	fBigNumPtr(NULL)
{
	fBigNumPtr = BN_new();
	BN_set_word(fBigNumPtr,integer);
}

//---------------------------------------------------------------------
// Copy constructor
//---------------------------------------------------------------------
TBigNumBuffer::TBigNumBuffer (const TBigNumBuffer& obj)
	:	Inherited(obj),
		fBigNumPtr(NULL)
{
	fBigNumPtr = BN_dup(obj.fBigNumPtr);
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TBigNumBuffer::~TBigNumBuffer ()
{
	if (fBigNumPtr)
	{
		BN_clear_free(fBigNumPtr);
		fBigNumPtr = NULL;
	}
}

//---------------------------------------------------------------------
// TBigNumBuffer::Clear
//---------------------------------------------------------------------
void TBigNumBuffer::Clear ()
{
	BN_clear(fBigNumPtr);
}

//---------------------------------------------------------------------
// TBigNumBuffer::AsBinary
//---------------------------------------------------------------------
std::string TBigNumBuffer::AsBinary () const
{
	std::string		binary;
	int				finalSize = 0;
	
	binary.resize(BN_num_bytes(fBigNumPtr));
	finalSize = BN_bn2bin(fBigNumPtr,const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(binary.data())));
	binary.resize(finalSize);
	
	return binary;
}

//---------------------------------------------------------------------
// TBigNumBuffer::FromBinary
//---------------------------------------------------------------------
void TBigNumBuffer::FromBinary (const std::string& binary)
{
	BN_bin2bn(reinterpret_cast<const unsigned char*>(binary.data()),binary.length(),fBigNumPtr);
}

//---------------------------------------------------------------------
// TBigNumBuffer::AsHex
//---------------------------------------------------------------------
std::string TBigNumBuffer::AsHex () const
{
	std::string		hex;
	char*			hexStr = BN_bn2hex(fBigNumPtr);
	
	if (hexStr)
	{
		hex = hexStr;
		OPENSSL_free(hexStr);
	}
	
	return hex;
}

//---------------------------------------------------------------------
// TBigNumBuffer::FromHex
//---------------------------------------------------------------------
void TBigNumBuffer::FromHex (const std::string& hex)
{
	BN_hex2bn(&fBigNumPtr,hex.c_str());
}

//---------------------------------------------------------------------
// TBigNumBuffer::AsDecimal
//---------------------------------------------------------------------
std::string TBigNumBuffer::AsDecimal () const
{
	std::string		decimal;
	char*			decStr = BN_bn2dec(fBigNumPtr);
	
	if (decStr)
	{
		decimal = decStr;
		OPENSSL_free(decStr);
	}
	
	return decimal;
}

//---------------------------------------------------------------------
// TBigNumBuffer::FromDecimal
//---------------------------------------------------------------------
void TBigNumBuffer::FromDecimal (const std::string& decimal)
{
	BN_dec2bn(&fBigNumPtr,decimal.c_str());
}

//---------------------------------------------------------------------
// TBigNumBuffer::Sqrt
//---------------------------------------------------------------------
TBigNumBuffer TBigNumBuffer::Sqrt ()
{
	TBigNumBuffer	root;
	TBigNumBuffer	r;
	TBigNumBuffer	e;
	int				bitCount,currBit;
	
	// Count the number of bits in our number
	bitCount = BN_num_bits(fBigNumPtr);
	
	// Setup the index into the bit stream; the index will be
	// one past the last/highest bit.  If there are an odd number
	// of bits then increment the index
	currBit = bitCount;
	if ((currBit & 1) != 0)
		++currBit;
	
	while (currBit > 0)
	{
		// Make space in the remainder
		BN_lshift(r,r.fBigNumPtr,2);
		
		// Move the two 'highest' bits from our number into the remainder
		--currBit;
		if (currBit < bitCount && BN_is_bit_set(fBigNumPtr,currBit))
			BN_set_bit(r,1);
		--currBit;
		if (BN_is_bit_set(fBigNumPtr,currBit))
			BN_set_bit(r,0);
		
		// Do the hokey-pokey
		BN_lshift1(root,root.fBigNumPtr);
		BN_lshift1(e,root.fBigNumPtr);
		BN_set_bit(e,0);
		
		switch (BN_cmp(r.fBigNumPtr,e.fBigNumPtr))
		{
			case 0:
			case 1:
				BN_sub(r,r.fBigNumPtr,e.fBigNumPtr);
				BN_set_bit(root,0);
				break;
		}
	}
	
	return root;
}

//*********************************************************************
// Class TUpdateScanMixin
//*********************************************************************

//---------------------------------------------------------------------
// TUpdateScanMixin::Update
//---------------------------------------------------------------------
void TUpdateScanMixin::Update (TFileObj& fileObj)
{
	bool			wasOpen = fileObj.IsOpen();
	unsigned long	oldFilePos = 0;
	std::string		buffer;
	size_t			kBufferSize = 4096;
	
	if (wasOpen)
	{
		// Remember the old file position
		oldFilePos = fileObj.GetFilePosition();
		
		// Rewind to the beginning of the file
		fileObj.SetFilePosition(0);
	}
	else
	{
		// Open the file in read-only mode
		fileObj.Open(O_RDONLY);
	}
	
	// Loop through the file, calling the update method as we go
	while (!fileObj.IsEOF())
	{
		buffer = "";
		fileObj.Read(buffer,kBufferSize);
		if (!buffer.empty())
			Update(buffer);
	}
	
	if (wasOpen)
	{
		// Reset file position
		fileObj.SetFilePosition(oldFilePos);
	}
	else
	{
		fileObj.Close();
	}
}

//*********************************************************************
// Class TUpdateMorphMixin
//*********************************************************************

//---------------------------------------------------------------------
// TUpdateMorphMixin::Update
//---------------------------------------------------------------------
void TUpdateMorphMixin::Update (TFileObj& inFileObj, TFileObj& outFileObj)
{
	bool			inWasOpen = inFileObj.IsOpen();
	unsigned long	oldInFilePos = 0;
	std::string		inBuffer;
	std::string		outBuffer;
	size_t			kBufferSize = 4096;
	
	if (inWasOpen)
	{
		// Remember the old file position
		oldInFilePos = inFileObj.GetFilePosition();
		
		// Rewind to the beginning of the file
		inFileObj.SetFilePosition(0);
	}
	else
	{
		// Open the file in read-only mode
		inFileObj.Open(O_RDONLY);
	}
	
	if (!outFileObj.IsOpen())
	{
		// Open the output file in append-only mode, creating
		// it if needed with 0600 permissions
		outFileObj.Open(static_cast<OS_Flags>(O_WRONLY|O_CREAT|O_APPEND),static_cast<OS_Mode>(S_IRUSR|S_IWUSR));
	}
	
	// Loop through the file, calling the update method as we go
	while (!inFileObj.IsEOF())
	{
		inBuffer = "";
		outBuffer = "";
		inFileObj.Read(inBuffer,kBufferSize);
		if (!inBuffer.empty())
		{
			Update(inBuffer,outBuffer);
			if (!outBuffer.empty())
				outFileObj.Write(outBuffer);
		}
	}
	
	if (inWasOpen)
	{
		// Reset file position
		inFileObj.SetFilePosition(oldInFilePos);
	}
	else
	{
		inFileObj.Close();
	}
}

//*********************************************************************
// Class TSSLErrorObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLErrorObj::TSSLErrorObj (const long errNum, const std::string& description)
	:	Inherited(errNum,description),
		fSSLErrorCode(0)
{
	char			sslErrorStr[256];
	const char*		kSeparatorStr = " - ";
	
	fSSLErrorCode = ERR_get_error();
	
	if (fSSLErrorCode != 0)
	{
		// Get the SSL error description
		SSL_load_error_strings();
		memset(sslErrorStr,0,sizeof(sslErrorStr));
		ERR_error_string(fSSLErrorCode,sslErrorStr);
		
		if (!fDescription.empty())
			fDescription += kSeparatorStr;
		
		// Concatenate SSL's description of the error
		fDescription += sslErrorStr;
		
		ERR_free_strings();
	}
}

//---------------------------------------------------------------------
// TSSLErrorObj::MakeDescription (protected)
//---------------------------------------------------------------------
void TSSLErrorObj::MakeDescription ()
{
	switch (fError)
	{
		case kSSLMessageDigestAlgoUnknown:
			fDescription = "SSL: Unknown message digest algorithm ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLMessageDigestAlgoNotSet:
			fDescription = "SSL: Message digest algorithm not set ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLMessageDigestNotInited:
			fDescription = "SSL: Message digest not initialized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLMessageDigestNotCopied:
			fDescription = "SSL: Message digest not copied ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCipherAlgoUnknown:
			fDescription = "SSL: Unknown cipher algorithm ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCipherAlgoNotSet:
			fDescription = "SSL: Cipher algorithm not set ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCipherNotInited:
			fDescription = "SSL: Cipher not initialized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCipherInitFailure:
			fDescription = "SSL: Cipher cannot be initialized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCipherUpdateFailure:
			fDescription = "SSL: Cipher cannot be updated ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCipherFinalFailure:
			fDescription = "SSL: Cipher cannot be finalized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCipherSetKeyLengthFailure:
			fDescription = "SSL: Cipher key length cannot be set ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCipherCleanupFailure:
			fDescription = "SSL: Cipher cannot be cleaned up ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLPKeyAlgoUnknown:
			fDescription = "SSL: Unknown public key algorithm ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLPKeyAlgoNotSet:
			fDescription = "SSL: Public key algorithm not set ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLPKeyNotInited:
			fDescription = "SSL: Public key cannot be initialized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLPKeyCannotDecrypt:
			fDescription = "SSL: Cannot decrypt with current public key ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLPKeyCannotEncrypt:
			fDescription = "SSL: Cannot encrypt with current public key ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLDHGeneratorInvalid:
			fDescription = "SSL: Diffie-Hellman generator value invalid ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLDHGeneratorNotSuitable:
			fDescription = "SSL: Diffie-Hellman generator value not suitable ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLDHSharedSecretNotSet:
			fDescription = "SSL: Diffie-Hellman shared secret not set ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLSigningContextNotInited:
			fDescription = "SSL: Signing context not initialized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLSigningContextSignatureFailure:
			fDescription = "SSL: Signing context public key/signature failure ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLEnvelopeContextNotInited:
			fDescription = "SSL: Envelope context not initialized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLEnvelopeInitFailure:
			fDescription = "SSL: Envelope context cannot be initialized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLEnvelopeUpdateFailure:
			fDescription = "SSL: Envelope cannot be updated ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLEnvelopeInvalidKeyIndex:
			fDescription = "SSL: Envelope key index out of bounds ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLPKeyCannotWriteToFile:
			fDescription = "SSL: Cannot write key to file ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLPKeyCannotReadFromFile:
			fDescription = "SSL: Cannot read key from file ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLRANDCannotWriteSeedFile:
			fDescription = "SSL: Cannot write/create PRNG seed file ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLRANDCannotGenerateSeedFilePath:
			fDescription = "SSL: Cannot generate PRNG seed file path ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLRANDCannotReadSeedFile:
			fDescription = "SSL: Cannot read PRNG seed file ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLRANDCannotObtainBytes:
			fDescription = "SSL: Cannot obtain bytes from PRNG ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLX509NotInited:
			fDescription = "SSL: X509 context is not initialized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLX509InitFailure:
			fDescription = "SSL: Cannot initialize the X509 context ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLX509CopyFailure:
			fDescription = "SSL: Cannot copy the X509 context ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLX509UnableToSetVersion:
			fDescription = "SSL: Unable to set version within certificate ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLX509UnableToSetSerialNumber:
			fDescription = "SSL: Unable to set the serial number within certificate ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLSSLContextSetMethodFailure:
			fDescription = "SSL: Unable to set the SSL context connection method ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLSSLInitializeFailure:
			fDescription = "SSL: Unable to initialize SSL connection from context ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLSSLNotInited:
			fDescription = "SSL: SSL object has not been initialized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLUnableToSetNetworkSocket:
			fDescription = "SSL: Cannot attach file descriptor to SSL object ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLUnableToShutdownConnection:
			fDescription = "SSL: Error while attempting to shutdown communication ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLAlreadyConnected:
			fDescription = "SSL: Cannot perform operation because there is an active connection ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLNotConnected:
			fDescription = "SSL: No connection with remote system ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLConnectionTerminated:
			fDescription = "SSL: Connection to remote system terminated unexpectedly ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLNoDataToReadOrWrite:
			fDescription = "SSL: There is no data to read or write on network connection ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLNoValidCiphers:
			fDescription = "SSL: No ciphers in list were valid ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCannotSetPrivateKey:
			fDescription = "SSL: Cannot set private key ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCannotSetCertificate:
			fDescription = "SSL: Cannot set certificate ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCannotSetCertificateAuthority:
			fDescription = "SSL: Cannot set certificate authority ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLPrivateKeyFailedVerification:
			fDescription = "SSL: Private key failed verification ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLSessionNotInited:
			fDescription = "SSL: Session not initialized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCannotSetSessionTime:
			fDescription = "SSL: Unable to change session time ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCannotSetSessionTimeout:
			fDescription = "SSL: Unable to change session timeout ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLCannotAddSession:
			fDescription = "SSL: Error while attempting to add session ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLContextNotInited:
			fDescription = "SSL: Context not initialized ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLContextIDCannotBeSet:
			fDescription = "SSL: Context ID cannot be set ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLSessionIsInvalidError:
			fDescription = "SSL: Session is invalid ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLPeerCertificateMissing:
			fDescription = "SSL: Remote system did not supply a certificate ";
			fDescription += NumToString(fError);
			break;
		
		case kSSLPeerCertificateVerificationFailure:
			fDescription = "SSL: Remote system's certificate failed verification ";
			fDescription += NumToString(fError);
			break;
		
		default:
			fDescription = "SSL: Unknown error ";
			fDescription += NumToString(fError);
			break;
	}
}

//*********************************************************************
// Global Functions
//*********************************************************************

TSSLEnvironment* SSLEnvironmentObjPtr ()
{
	if (!gSSLEnvironmentObjPtr)
	{
		TLockedPthreadMutexObj	lock(gSSLEnvironmentObjPtrMutex);
		
		if (!gSSLEnvironmentObjPtr)
		{
			gSSLEnvironmentObjPtr = new TSSLEnvironment;
		}
	}
	
	return gSSLEnvironmentObjPtr;
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

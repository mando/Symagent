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
#		Last Modified:				08 Dec 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-ssl-tls.h"

#include "symlib-utils.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
static	TPthreadMutexObj		gSSLLibInitedMutex;
static	bool					gSSLLibInited					= false;

//*********************************************************************
// Class TSSLContext
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLContext::TSSLContext ()
	:	fContextPtr(NULL)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLContext::TSSLContext (SSL_CTX* sslContextPtr)
	:	fContextPtr(sslContextPtr)
{
	if (fContextPtr)
		++fContextPtr->references;
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLContext::TSSLContext (const TSSLContext& obj)
	:	fContextPtr(NULL)
{
	if (obj.fContextPtr)
	{
		fContextPtr = const_cast<SSL_CTX*>(obj.fContextPtr);
		++fContextPtr->references;
	}
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSSLContext::~TSSLContext ()
{
	_Free();
}

//---------------------------------------------------------------------
// TSSLContext::Initialize
//---------------------------------------------------------------------
void TSSLContext::Initialize (SSL_METHOD* method)
{
	// Make sure the library is initialized properly
	_IniTSSLConnectionLib();
	
	// First free any existing context we might have
	_Free();
	
	// Attempt to set the connection
	fContextPtr = SSL_CTX_new(method);
	if (!fContextPtr)
		throw TSSLErrorObj(kSSLSSLInitializeFailure);
}

//---------------------------------------------------------------------
// TSSLContext::Initialize
//---------------------------------------------------------------------
void TSSLContext::Initialize (SSLConnectionMode connectionType, SSLProtocolType protocolType)
{
	switch (connectionType)
	{
		case kSSLClientMode:
			{
				switch (protocolType)
				{
					case kSSLv2Protocol:
						Initialize(SSLv2_client_method());
						break;
					
					case kSSLv3Protocol:
						Initialize(SSLv3_client_method());
						break;
					
					case kTLSv1Protocol:
						Initialize(TLSv1_client_method());
						break;
					
					case kSSLv23Protocol:
						Initialize(SSLv23_client_method());
						break;
				}
			}
			break;
		
		case kSSLServerMode:
			{
				switch (protocolType)
				{
					case kSSLv2Protocol:
						Initialize(SSLv2_server_method());
						break;
					
					case kSSLv3Protocol:
						Initialize(SSLv3_server_method());
						break;
					
					case kTLSv1Protocol:
						Initialize(TLSv1_server_method());
						break;
					
					case kSSLv23Protocol:
						Initialize(SSLv23_server_method());
						break;
				}
			}
			break;
		
		case kSSLClientServerMode:
			{
				switch (protocolType)
				{
					case kSSLv2Protocol:
						Initialize(SSLv2_method());
						break;
					
					case kSSLv3Protocol:
						Initialize(SSLv3_method());
						break;
					
					case kTLSv1Protocol:
						Initialize(TLSv1_method());
						break;
					
					case kSSLv23Protocol:
						Initialize(SSLv23_method());
						break;
				}
			}
			break;
	}
}

//---------------------------------------------------------------------
// TSSLContext::GetMode
//---------------------------------------------------------------------
long TSSLContext::GetMode ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_get_mode(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SetMode
//---------------------------------------------------------------------
long TSSLContext::SetMode (long modeMask)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_set_mode(fContextPtr,modeMask);
}

//---------------------------------------------------------------------
// TSSLContext::GetOptions
//---------------------------------------------------------------------
long TSSLContext::GetOptions ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_get_options(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SetOptions
//---------------------------------------------------------------------
long TSSLContext::SetOptions (long optionsMask)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_set_options(fContextPtr,optionsMask);
}

//---------------------------------------------------------------------
// TSSLContext::GetTimeout
//---------------------------------------------------------------------
long TSSLContext::GetTimeout ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_get_timeout(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SetTimeout
//---------------------------------------------------------------------
long TSSLContext::SetTimeout (long newTimeout)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_set_timeout(fContextPtr,newTimeout);
}

//---------------------------------------------------------------------
// TSSLContext::SetCertificate
//---------------------------------------------------------------------
void TSSLContext::SetCertificate (TX509Obj& certObj)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (SSL_CTX_use_certificate(fContextPtr,certObj) != 1)
		throw TSSLErrorObj(kSSLCannotSetCertificate);
}

//---------------------------------------------------------------------
// TSSLContext::SetCertificate
//---------------------------------------------------------------------
void TSSLContext::SetCertificate (const TFileObj& certFileObj, int formatType)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (!certFileObj.Exists())
		throw TSymLibErrorObj(ENOENT,"Certificate file does not exist");
	
	if (SSL_CTX_use_certificate_file(fContextPtr,certFileObj.Path().c_str(),formatType) != 1)
		throw TSSLErrorObj(kSSLCannotSetCertificate);
}

//---------------------------------------------------------------------
// TSSLContext::SetCertificateChainFile
//---------------------------------------------------------------------
void TSSLContext::SetCertificateChainFile (const TFileObj& certChainFileObj)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (!certChainFileObj.Exists())
		throw TSymLibErrorObj(ENOENT,"Certificate chain file does not exist");
	
	if (SSL_CTX_use_certificate_chain_file(fContextPtr,certChainFileObj.Path().c_str()) != 1)
		throw TSSLErrorObj(kSSLCannotSetCertificate);
}

//---------------------------------------------------------------------
// TSSLContext::SetCertificateAuthorityFile
//---------------------------------------------------------------------
void TSSLContext::SetCertificateAuthorityFile (const TFileObj& certAuthFile)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (!certAuthFile.Exists())
		throw TSymLibErrorObj(ENOENT,"Certificate authority file does not exist");
	
	if (SSL_CTX_load_verify_locations(fContextPtr,certAuthFile.Path().c_str(),NULL) != 1)
		throw TSSLErrorObj(kSSLCannotSetCertificateAuthority);
}

//---------------------------------------------------------------------
// TSSLContext::SetCertificateAuthorityDirectory
//---------------------------------------------------------------------
void TSSLContext::SetCertificateAuthorityDirectory (const TDirObj& certAuthDir)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (!certAuthDir.Exists())
		throw TSymLibErrorObj(ENOENT,"Certificate authority directory does not exist");
	
	if (SSL_CTX_load_verify_locations(fContextPtr,NULL,certAuthDir.Path().c_str()) != 1)
		throw TSSLErrorObj(kSSLCannotSetCertificateAuthority);
}

//---------------------------------------------------------------------
// TSSLContext::SetPrivateKey
//---------------------------------------------------------------------
void TSSLContext::SetPrivateKey (TPKeyObj& privateKeyObj)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (SSL_CTX_use_PrivateKey(fContextPtr,privateKeyObj) != 1)
		throw TSSLErrorObj(kSSLCannotSetPrivateKey);
}

//---------------------------------------------------------------------
// TSSLContext::SetPrivateKey
//---------------------------------------------------------------------
void TSSLContext::SetPrivateKey (const TFileObj& privateKeyFileObj, int formatType)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (!privateKeyFileObj.Exists())
		throw TSymLibErrorObj(ENOENT,"Private key file does not exist");
	
	if (SSL_CTX_use_PrivateKey_file(fContextPtr,privateKeyFileObj.Path().c_str(),formatType) != 1)
		throw TSSLErrorObj(kSSLCannotSetPrivateKey);
}

//---------------------------------------------------------------------
// TSSLContext::CheckPrivateKey
//---------------------------------------------------------------------
bool TSSLContext::CheckPrivateKey ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (SSL_CTX_check_private_key(fContextPtr) != 1)
		throw TSSLErrorObj(kSSLPrivateKeyFailedVerification);
	
	return true;
}

//---------------------------------------------------------------------
// TSSLContext::SetCipherList
//---------------------------------------------------------------------
void TSSLContext::SetCipherList (const std::string& cipherNameList)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (SSL_CTX_set_cipher_list(fContextPtr,cipherNameList.c_str()) == 0)
		throw TSSLErrorObj(kSSLNoValidCiphers);
}

//---------------------------------------------------------------------
// TSSLContext::SetCipherList
//---------------------------------------------------------------------
void TSSLContext::SetCipherList (const StdStringList& cipherNameList)
{
	if (!cipherNameList.empty())
	{
		std::string		cipherString;
		
		cipherString = JoinStdStringList(':',cipherNameList);
		SetCipherList(cipherString);
	}
}

//---------------------------------------------------------------------
// TSSLContext::GetVerificationMode
//---------------------------------------------------------------------
int TSSLContext::GetVerificationMode ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_get_verify_mode(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::GetVerificationDepth
//---------------------------------------------------------------------
int TSSLContext::GetVerificationDepth ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_get_verify_depth(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::GetVerificationCallbackFunctionPtr
//---------------------------------------------------------------------
SSLVerifyCallback TSSLContext::GetVerificationCallbackFunctionPtr ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_get_verify_callback(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SetVerificationParams
//---------------------------------------------------------------------
void TSSLContext::SetVerificationParams (int mode, SSLVerifyCallback callback, int depth)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	SSL_CTX_set_verify(fContextPtr,mode,callback);
	SSL_CTX_set_verify_depth(fContextPtr,depth);
}

//---------------------------------------------------------------------
// TSSLContext::GetInfoCallback
//---------------------------------------------------------------------
SSLInfoCallback TSSLContext::GetInfoCallback ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return reinterpret_cast<SSLInfoCallback>(SSL_CTX_get_info_callback(fContextPtr));
}

//---------------------------------------------------------------------
// TSSLContext::SetInfoCallback
//---------------------------------------------------------------------
void TSSLContext::SetInfoCallback (SSLInfoCallback functionPtr)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	SSL_CTX_set_info_callback(fContextPtr,reinterpret_cast<SSLCTXInfoCallbackAsArgument>(functionPtr));
}

//---------------------------------------------------------------------
// TSSLContext::GetNewSessionCallback
//---------------------------------------------------------------------
SSLNewSessionCallback TSSLContext::GetNewSessionCallback ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_get_new_cb(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SetNewSessionCallback
//---------------------------------------------------------------------
void TSSLContext::SetNewSessionCallback (SSLNewSessionCallback functionPtr)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	SSL_CTX_sess_set_new_cb(fContextPtr,functionPtr);
}

//---------------------------------------------------------------------
// TSSLContext::GetRemoveSessionCallback
//---------------------------------------------------------------------
SSLRemoveSessionCallback TSSLContext::GetRemoveSessionCallback ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_get_remove_cb(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SetRemoveSessionCallback
//---------------------------------------------------------------------
void TSSLContext::SetRemoveSessionCallback (SSLRemoveSessionCallback functionPtr)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	SSL_CTX_sess_set_remove_cb(fContextPtr,functionPtr);
}

//---------------------------------------------------------------------
// TSSLContext::GetResumeSessionCallback
//---------------------------------------------------------------------
SSLResumeSessionCallback TSSLContext::GetResumeSessionCallback ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_get_get_cb(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SetResumeSessionCallback
//---------------------------------------------------------------------
void TSSLContext::SetResumeSessionCallback (SSLResumeSessionCallback functionPtr)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	SSL_CTX_sess_set_get_cb(fContextPtr,functionPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SetSessionIDContext
//---------------------------------------------------------------------
void TSSLContext::SetSessionIDContext (const unsigned char* contextPtr, unsigned int contextSize)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (SSL_CTX_set_session_id_context(fContextPtr,contextPtr,contextSize) != 1)
		throw TSSLErrorObj(kSSLContextIDCannotBeSet);
}

//---------------------------------------------------------------------
// TSSLContext::SetSessionIDContext
//---------------------------------------------------------------------
void TSSLContext::SetSessionIDContext (const std::string& context)
{
	SetSessionIDContext(reinterpret_cast<const unsigned char*>(context.data()),context.length());
}

//---------------------------------------------------------------------
// TSSLContext::GetSessionCacheSize
//---------------------------------------------------------------------
long TSSLContext::GetSessionCacheSize ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_get_cache_size(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SetSessionCacheSize
//---------------------------------------------------------------------
void TSSLContext::SetSessionCacheSize (long newCacheSize)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	SSL_CTX_sess_set_cache_size(fContextPtr,newCacheSize);
}

//---------------------------------------------------------------------
// TSSLContext::GetSessionCacheMode
//---------------------------------------------------------------------
long TSSLContext::GetSessionCacheMode ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_get_session_cache_mode(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SetSessionCacheMode
//---------------------------------------------------------------------
void TSSLContext::SetSessionCacheMode (long newCacheMode)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	SSL_CTX_set_session_cache_mode(fContextPtr,newCacheMode);
}

//---------------------------------------------------------------------
// TSSLContext::AddSession
//---------------------------------------------------------------------
void TSSLContext::AddSession (TSSLSession& sessionObj)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (SSL_CTX_add_session(fContextPtr,sessionObj) != 1)
		throw TSSLErrorObj(kSSLCannotAddSession);
}

//---------------------------------------------------------------------
// TSSLContext::RemoveSession
//---------------------------------------------------------------------
void TSSLContext::RemoveSession (TSSLSession& sessionObj)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	SSL_CTX_remove_session(fContextPtr,sessionObj);
}

//---------------------------------------------------------------------
// TSSLContext::FlushSessions
//---------------------------------------------------------------------
void TSSLContext::FlushSessions (time_t expireTime)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	if (expireTime == 0)
		expireTime = time(NULL);
	
	SSL_CTX_flush_sessions(fContextPtr,expireTime);
}

//---------------------------------------------------------------------
// TSSLContext::SessionCount
//---------------------------------------------------------------------
long TSSLContext::SessionCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_number(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SessionOverloadCount
//---------------------------------------------------------------------
long TSSLContext::SessionOverloadCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_cache_full(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SessionCacheHitCount
//---------------------------------------------------------------------
long TSSLContext::SessionCacheHitCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_hits(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SessionCacheMissCount
//---------------------------------------------------------------------
long TSSLContext::SessionCacheMissCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_misses(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SessionExternalCacheHitCount
//---------------------------------------------------------------------
long TSSLContext::SessionExternalCacheHitCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_cb_hits(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::SessionTimeoutCount
//---------------------------------------------------------------------
long TSSLContext::SessionTimeoutCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_timeouts(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::ConnectStartedCount
//---------------------------------------------------------------------
long TSSLContext::ConnectStartedCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_connect(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::ConnectSucceededCount
//---------------------------------------------------------------------
long TSSLContext::ConnectSucceededCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_connect_good(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::ConnectRenegotiationsCount
//---------------------------------------------------------------------
long TSSLContext::ConnectRenegotiationsCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_connect_renegotiate(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::AcceptStartedCount
//---------------------------------------------------------------------
long TSSLContext::AcceptStartedCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_accept(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::AcceptSucceededCount
//---------------------------------------------------------------------
long TSSLContext::AcceptSucceededCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_accept_good(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::AcceptRenegotiationsCount
//---------------------------------------------------------------------
long TSSLContext::AcceptRenegotiationsCount ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLContextNotInited);
	
	return SSL_CTX_sess_accept_renegotiate(fContextPtr);
}

//---------------------------------------------------------------------
// TSSLContext::_IniTSSLConnectionLib (protected)
//---------------------------------------------------------------------
void TSSLContext::_IniTSSLConnectionLib ()
{
	if (!gSSLLibInited)
	{
		TLockedPthreadMutexObj	lock(gSSLLibInitedMutex);
		
		if (!gSSLLibInited)
		{
			SSLEnvironmentObjPtr()->LoadAllSSLAlgorithms();
			
			if (!TSSLEnvironment::PRNGIsValid())
			{
				TSSLEnvironment::PRNGSeed(2048);
				
				while (!TSSLEnvironment::PRNGIsValid())
					TSSLEnvironment::PRNGAddBytes(2048);
			}
			
			gSSLLibInited = true;
		}
	}
}

//---------------------------------------------------------------------
// TSSLContext::_Free (protected)
//---------------------------------------------------------------------
void TSSLContext::_Free ()
{
	if (IsInited())
	{
		SSL_CTX_free(fContextPtr);
		fContextPtr = NULL;
	}
}

//*********************************************************************
// Class TSSLSession
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLSession::TSSLSession ()
	:	fSessionPtr(NULL)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLSession::TSSLSession (SSL_SESSION* sslSessionPtr)
	:	fSessionPtr(sslSessionPtr)
{
	if (fSessionPtr)
		++fSessionPtr->references;
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLSession::TSSLSession (const TSSLSession& obj)
	:	fSessionPtr(NULL)
{
	if (obj.fSessionPtr)
	{
		fSessionPtr = const_cast<SSL_SESSION*>(obj.fSessionPtr);
		++fSessionPtr->references;
	}
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSSLSession::~TSSLSession ()
{
	_Free();
}

//---------------------------------------------------------------------
// TSSLSession::GetTimeStarted
//---------------------------------------------------------------------
time_t TSSLSession::GetTimeStarted ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSessionNotInited);
	
	return SSL_SESSION_get_time(fSessionPtr);
}

//---------------------------------------------------------------------
// TSSLSession::SetTimeStarted
//---------------------------------------------------------------------
void TSSLSession::SetTimeStarted (time_t newTime)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSessionNotInited);
	
	if (SSL_SESSION_set_time(fSessionPtr,newTime) != 1)
		throw TSSLErrorObj(kSSLCannotSetSessionTime);
}

//---------------------------------------------------------------------
// TSSLSession::GetTimeout
//---------------------------------------------------------------------
long TSSLSession::GetTimeout ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSessionNotInited);
	
	return SSL_SESSION_get_timeout(fSessionPtr);
}

//---------------------------------------------------------------------
// TSSLSession::SetTimeout
//---------------------------------------------------------------------
void TSSLSession::SetTimeout (long newTimeout)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSessionNotInited);
	
	if (SSL_SESSION_set_timeout(fSessionPtr,newTimeout) != 1)
		throw TSSLErrorObj(kSSLCannotSetSessionTimeout);
}

//---------------------------------------------------------------------
// TSSLSession::Serialize
//---------------------------------------------------------------------
std::string TSSLSession::Serialize ()
{
	std::string		sessionData;
	unsigned char*	sessionPtr = NULL;
	int				sessionSize = 0;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSessionNotInited);
	
	// First compute the size we need
	sessionSize = i2d_SSL_SESSION(fSessionPtr,NULL);
	if (sessionSize == 0)
		throw TSSLErrorObj(kSSLSessionIsInvalidError);
	
	// Allocate the buffer space
	sessionData.resize(sessionSize);
	sessionPtr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(sessionData.data()));
	
	// Now actually get the data
	i2d_SSL_SESSION(fSessionPtr,&sessionPtr);
	
	return sessionData;
}

//---------------------------------------------------------------------
// TSSLSession::Deserialize
//---------------------------------------------------------------------
#if (1 == 1)
void TSSLSession::Deserialize (const unsigned char* sessionDataPtr, unsigned int sessionDataSize)
#else
void TSSLSession::Deserialize (unsigned char* sessionDataPtr, unsigned int sessionDataSize)
#endif

{
	// Free anything we might already have
	_Free();
	
	// Translate the given data
	fSessionPtr = d2i_SSL_SESSION(NULL,&sessionDataPtr,sessionDataSize);
	if (!fSessionPtr)
		throw TSSLErrorObj(kSSLSessionIsInvalidError);
}

//---------------------------------------------------------------------
// TSSLSession::Deserialize
//---------------------------------------------------------------------
void TSSLSession::Deserialize (std::string& sessionData)
{
	Deserialize(const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(sessionData.data())),sessionData.length());
}

//---------------------------------------------------------------------
// TSSLSession::_Free (protected)
//---------------------------------------------------------------------
void TSSLSession::_Free ()
{
	if (IsInited())
	{
		SSL_SESSION_free(fSessionPtr);
		fSessionPtr = NULL;
	}
}

//*********************************************************************
// Class TSSLConnection
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLConnection::TSSLConnection ()
	:	fSSLPtr(NULL),
		fIsConnected(false),
		fIOTimeout(0)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLConnection::TSSLConnection (SSL* sslPtr)
	:	fSSLPtr(sslPtr),
		fIsConnected(false),
		fIOTimeout(0)
{
	if (fSSLPtr)
	{
		++fSSLPtr->references;
		if (SSL_is_init_finished(fSSLPtr))
			fIsConnected = true;
	}
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSSLConnection::TSSLConnection (const TSSLConnection& obj)
	:	fSSLPtr(NULL),
		fIsConnected(false),
		fIOTimeout(obj.fIOTimeout)
{
	if (obj.fSSLPtr)
	{
		fSSLPtr = const_cast<SSL*>(obj.fSSLPtr);
		++fSSLPtr->references;
		if (SSL_is_init_finished(fSSLPtr))
			fIsConnected = true;
	}
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSSLConnection::~TSSLConnection ()
{
	_Free();
}

//---------------------------------------------------------------------
// TSSLConnection::Initialize
//---------------------------------------------------------------------
void TSSLConnection::Initialize (TSSLContext& sslContextObj)
{
	if (IsConnected())
		throw TSSLErrorObj(kSSLAlreadyConnected);
	
	// First free any existing context we might have
	_Free();
	
	fSSLPtr = SSL_new(sslContextObj);
	if (!fSSLPtr)
		throw TSSLErrorObj(kSSLSSLInitializeFailure);
}

//---------------------------------------------------------------------
// TSSLConnection::GetInputSocket
//---------------------------------------------------------------------
int TSSLConnection::GetInputSocket ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return (SSL_get_rfd(fSSLPtr));
}

//---------------------------------------------------------------------
// TSSLConnection::SetInputSocket
//---------------------------------------------------------------------
void TSSLConnection::SetInputSocket (int socketNum)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (IsConnected())
		throw TSSLErrorObj(kSSLAlreadyConnected);
	
	if (SSL_set_rfd(fSSLPtr,socketNum) != 1)
		throw TSSLErrorObj(kSSLUnableToSetNetworkSocket);
}

//---------------------------------------------------------------------
// TSSLConnection::GetOutputSocket
//---------------------------------------------------------------------
int TSSLConnection::GetOutputSocket ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return (SSL_get_wfd(fSSLPtr));
}

//---------------------------------------------------------------------
// TSSLConnection::SetOutputSocket
//---------------------------------------------------------------------
void TSSLConnection::SetOutputSocket (int socketNum)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (IsConnected())
		throw TSSLErrorObj(kSSLAlreadyConnected);
	
	if (SSL_set_wfd(fSSLPtr,socketNum) != 1)
		throw TSSLErrorObj(kSSLUnableToSetNetworkSocket);
}

//---------------------------------------------------------------------
// TSSLConnection::GetInputOutputSocket
//---------------------------------------------------------------------
int TSSLConnection::GetInputOutputSocket ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return (SSL_get_fd(fSSLPtr));
}

//---------------------------------------------------------------------
// TSSLConnection::SetInputOutputSocket
//---------------------------------------------------------------------
void TSSLConnection::SetInputOutputSocket (int socketNum)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (IsConnected())
		throw TSSLErrorObj(kSSLAlreadyConnected);
	
	if (SSL_set_fd(fSSLPtr,socketNum) != 1)
		throw TSSLErrorObj(kSSLUnableToSetNetworkSocket);
}

//---------------------------------------------------------------------
// TSSLConnection::GetMode
//---------------------------------------------------------------------
long TSSLConnection::GetMode ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return SSL_get_mode(fSSLPtr);
}

//---------------------------------------------------------------------
// TSSLConnection::SetMode
//---------------------------------------------------------------------
long TSSLConnection::SetMode (long modeMask)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return SSL_set_mode(fSSLPtr,modeMask);
}

//---------------------------------------------------------------------
// TSSLConnection::GetOptions
//---------------------------------------------------------------------
long TSSLConnection::GetOptions ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return SSL_get_options(fSSLPtr);
}

//---------------------------------------------------------------------
// TSSLConnection::SetOptions
//---------------------------------------------------------------------
long TSSLConnection::SetOptions (long optionsMask)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return SSL_set_options(fSSLPtr,optionsMask);
}

//---------------------------------------------------------------------
// TSSLConnection::GetDefaultTimeout
//---------------------------------------------------------------------
long TSSLConnection::GetDefaultTimeout ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return SSL_get_default_timeout(fSSLPtr);
}

//---------------------------------------------------------------------
// TSSLConnection::SetCertificate
//---------------------------------------------------------------------
void TSSLConnection::SetCertificate (TX509Obj& certObj)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (SSL_use_certificate(fSSLPtr,certObj) != 1)
		throw TSSLErrorObj(kSSLCannotSetCertificate);
}

//---------------------------------------------------------------------
// TSSLConnection::SetCertificate
//---------------------------------------------------------------------
void TSSLConnection::SetCertificate (const TFileObj& certFileObj, int formatType)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (!certFileObj.Exists())
		throw TSymLibErrorObj(ENOENT,"Certificate file does not exist");
	
	if (SSL_use_certificate_file(fSSLPtr,certFileObj.Path().c_str(),formatType) != 1)
		throw TSSLErrorObj(kSSLCannotSetCertificate);
}

//---------------------------------------------------------------------
// TSSLConnection::SetPrivateKey
//---------------------------------------------------------------------
void TSSLConnection::SetPrivateKey (TPKeyObj& privateKeyObj)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (SSL_use_PrivateKey(fSSLPtr,privateKeyObj) != 1)
		throw TSSLErrorObj(kSSLCannotSetPrivateKey);
}

//---------------------------------------------------------------------
// TSSLConnection::SetPrivateKey
//---------------------------------------------------------------------
void TSSLConnection::SetPrivateKey (const TFileObj& privateKeyFileObj, int formatType)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (!privateKeyFileObj.Exists())
		throw TSymLibErrorObj(ENOENT,"Private key file does not exist");
	
	if (SSL_use_PrivateKey_file(fSSLPtr,privateKeyFileObj.Path().c_str(),formatType) != 1)
		throw TSSLErrorObj(kSSLCannotSetPrivateKey);
}

//---------------------------------------------------------------------
// TSSLConnection::CheckPrivateKey
//---------------------------------------------------------------------
bool TSSLConnection::CheckPrivateKey ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (SSL_check_private_key(fSSLPtr) != 1)
		throw TSSLErrorObj(kSSLPrivateKeyFailedVerification);
	
	return true;
}

//---------------------------------------------------------------------
// TSSLConnection::GetCipherList
//---------------------------------------------------------------------
void TSSLConnection::GetCipherList (StdStringList& cipherNameList)
{
	int		cipherPriority = 0;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	// Clear the argument
	cipherNameList.clear();
	
	// Loop through the available ciphers
	while (true)
	{
		const char*		namePtr = SSL_get_cipher_list(fSSLPtr,cipherPriority);
		
		if (namePtr)
		{
			cipherNameList.push_back(namePtr);
			++cipherPriority;
		}
		else
		{
			break;
		}
	}
}

//---------------------------------------------------------------------
// TSSLConnection::GetCipherList
//---------------------------------------------------------------------
void TSSLConnection::GetCipherList (TCipherList& cipherObjList)
{
	StdStringList		nameList;
	
	// Get the list of names
	GetCipherList(nameList);
	
	// Clear the argument
	cipherObjList.clear();
	
	// Translate the names into cipher objects
	for (StdStringList_const_iter x = nameList.begin(); x != nameList.end(); x++)
		cipherObjList.push_back(TCipher(*x));
}

//---------------------------------------------------------------------
// TSSLConnection::SetCipherList
//---------------------------------------------------------------------
void TSSLConnection::SetCipherList (const std::string& cipherNameList)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (SSL_set_cipher_list(fSSLPtr,cipherNameList.c_str()) == 0)
		throw TSSLErrorObj(kSSLNoValidCiphers);
}

//---------------------------------------------------------------------
// TSSLConnection::SetCipherList
//---------------------------------------------------------------------
void TSSLConnection::SetCipherList (const StdStringList& cipherNameList)
{
	if (!cipherNameList.empty())
	{
		std::string		cipherString;
		
		cipherString = JoinStdStringList(':',cipherNameList);
		SetCipherList(cipherString);
	}
}

//---------------------------------------------------------------------
// TSSLConnection::SetCipherList
//---------------------------------------------------------------------
void TSSLConnection::SetCipherList (const TCipherList& cipherObjList)
{
	if (!cipherObjList.empty())
	{
		std::string		cipherString;
		
		for (TCipherList_const_iter x = cipherObjList.begin(); x != cipherObjList.end(); x++)
		{
			if (!cipherString.empty())
				cipherString += ":";
			cipherString += x->Name();
		}
		
		SetCipherList(cipherString);
	}
}

//---------------------------------------------------------------------
// TSSLConnection::GetVerificationMode
//---------------------------------------------------------------------
int TSSLConnection::GetVerificationMode ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return SSL_get_verify_mode(fSSLPtr);
}

//---------------------------------------------------------------------
// TSSLConnection::GetVerificationDepth
//---------------------------------------------------------------------
int TSSLConnection::GetVerificationDepth ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return SSL_get_verify_depth(fSSLPtr);
}

//---------------------------------------------------------------------
// TSSLConnection::GetVerificationCallbackFunctionPtr
//---------------------------------------------------------------------
SSLVerifyCallback TSSLConnection::GetVerificationCallbackFunctionPtr ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return SSL_get_verify_callback(fSSLPtr);
}

//---------------------------------------------------------------------
// TSSLConnection::SetVerificationParams
//---------------------------------------------------------------------
void TSSLConnection::SetVerificationParams (int mode, SSLVerifyCallback callback, int depth)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	SSL_set_verify(fSSLPtr,mode,callback);
	SSL_set_verify_depth(fSSLPtr,depth);
}

//---------------------------------------------------------------------
// TSSLConnection::GetCurrentCipher
//---------------------------------------------------------------------
SSL_CIPHER* TSSLConnection::GetCurrentCipher ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return SSL_get_current_cipher(fSSLPtr);
}

//---------------------------------------------------------------------
// TSSLConnection::GetCurrentCipherName
//---------------------------------------------------------------------
std::string TSSLConnection::GetCurrentCipherName ()
{
	std::string		cipherName;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	cipherName = SSL_get_cipher_name(fSSLPtr);
	
	return cipherName;
}

//---------------------------------------------------------------------
// TSSLConnection::GetCurrentCipherVersion
//---------------------------------------------------------------------
std::string TSSLConnection::GetCurrentCipherVersion ()
{
	std::string		version;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	version = SSL_get_cipher_version(fSSLPtr);
	
	return version;
}

//---------------------------------------------------------------------
// TSSLConnection::GetCurrentCipherDescription
//---------------------------------------------------------------------
std::string TSSLConnection::GetCurrentCipherDescription ()
{
	std::string		description;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	description.resize(256);
	SSL_CIPHER_description(GetCurrentCipher(),const_cast<char*>(description.data()),description.capacity());
	description.resize(strlen(description.c_str()));
	
	return description;
}

//---------------------------------------------------------------------
// TSSLConnection::GetCurrentCipherBits
//---------------------------------------------------------------------
int TSSLConnection::GetCurrentCipherBits ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return SSL_get_cipher_bits(fSSLPtr,NULL);
}

//---------------------------------------------------------------------
// TSSLConnection::SetSessionIDContext
//---------------------------------------------------------------------
void TSSLConnection::SetSessionIDContext (const unsigned char* contextPtr, unsigned int contextSize)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (SSL_set_session_id_context(fSSLPtr,contextPtr,contextSize) != 1)
		throw TSSLErrorObj(kSSLContextIDCannotBeSet);
}

//---------------------------------------------------------------------
// TSSLConnection::SetSessionIDContext
//---------------------------------------------------------------------
void TSSLConnection::SetSessionIDContext (const std::string& context)
{
	SetSessionIDContext(reinterpret_cast<const unsigned char*>(context.data()),context.length());
}

//---------------------------------------------------------------------
// TSSLConnection::GetCurrentSession
//---------------------------------------------------------------------
TSSLSession TSSLConnection::GetCurrentSession ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (!IsConnected())
		throw TSSLErrorObj(kSSLNotConnected);
	
	return TSSLSession(SSL_get_session(fSSLPtr));
}

//---------------------------------------------------------------------
// TSSLConnection::SetCurrentSession
//---------------------------------------------------------------------
void TSSLConnection::SetCurrentSession (TSSLSession& sessionObj)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (SSL_set_session(fSSLPtr,sessionObj) != 1)
		throw TSSLErrorObj(kSSLCannotAddSession);
}

//---------------------------------------------------------------------
// TSSLConnection::CurrentSessionReused
//---------------------------------------------------------------------
bool TSSLConnection::CurrentSessionReused ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (!IsConnected())
		throw TSSLErrorObj(kSSLNotConnected);
	
	return (SSL_session_reused(fSSLPtr) == 1);
}

//---------------------------------------------------------------------
// TSSLConnection::GetInfoCallback
//---------------------------------------------------------------------
SSLInfoCallback TSSLConnection::GetInfoCallback ()
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	return reinterpret_cast<SSLInfoCallback>(SSL_get_info_callback(fSSLPtr));
}

//---------------------------------------------------------------------
// TSSLConnection::SetInfoCallback
//---------------------------------------------------------------------
void TSSLConnection::SetInfoCallback (SSLInfoCallback functionPtr)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	SSL_set_info_callback(fSSLPtr,reinterpret_cast<SSLInfoCallbackAsArgument>(functionPtr));
}

//---------------------------------------------------------------------
// TSSLConnection::Accept
//---------------------------------------------------------------------
void TSSLConnection::Accept ()
{
	int						acceptResult = 0;
	TLockedPthreadMutexObj	lock(fIOMutex);
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (IsConnected())
		throw TSSLErrorObj(kSSLAlreadyConnected);
	
	// Force the network socket(s) to blocking mode
	_ForceBlockingMode(true);
	
	// Enable auto-retry in the context so invisible negotiations
	// don't affect us
	SSL_set_mode(fSSLPtr,SSL_MODE_AUTO_RETRY);
	
	SSL_set_accept_state(fSSLPtr);
	
	acceptResult = SSL_accept(fSSLPtr);
	if (acceptResult == 1)
	{
		// Successful
		fIsConnected = true;
	}
	else
	{
		int		errResult = SSL_get_error(fSSLPtr,acceptResult);
		
		switch (errResult)
		{
			case SSL_ERROR_NONE:
			case SSL_ERROR_ZERO_RETURN:
				{
					// Everything is okay.
					fIsConnected = true;
				}
				break;
			
			case SSL_ERROR_SYSCALL:
				{
					if (errno == 0)
					{
						// It was apparently successful after all, even
						// though there appeared to be an error
						fIsConnected = true;
					}
					else
					{
						// System-level error occurred
						throw TSymLibErrorObj(errno,"While attempting to make an SSL connection");
					}
				}
				break;
			
			case SSL_ERROR_SSL:
				{
					// SSL-specific error occurred
					throw TSSLErrorObj(kSSLConnectionTerminated,"While attempting to make an SSL connection");
				}
				break;
		}
	}
}

//---------------------------------------------------------------------
// TSSLConnection::Connect
//---------------------------------------------------------------------
void TSSLConnection::Connect ()
{
	int						connectResult = 0;
	TLockedPthreadMutexObj	lock(fIOMutex);
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (IsConnected())
		throw TSSLErrorObj(kSSLAlreadyConnected);
	
	// Force the network socket(s) to blocking mode
	_ForceBlockingMode(true);
	
	// Enable auto-retry in the context so invisible negotiations
	// don't affect us
	SSL_set_mode(fSSLPtr,SSL_MODE_AUTO_RETRY);
	
	SSL_set_connect_state(fSSLPtr);
	
	connectResult = SSL_connect(fSSLPtr);
	if (connectResult == 1)
	{
		// Successful connection
		fIsConnected = true;
	}
	else
	{
		int		errResult = SSL_get_error(fSSLPtr,connectResult);
		
		switch (errResult)
		{
			case SSL_ERROR_NONE:
			case SSL_ERROR_ZERO_RETURN:
				{
					// Everything is okay.
					fIsConnected = true;
				}
				break;
			
			case SSL_ERROR_SYSCALL:
				{
					if (errno == 0)
					{
						// It was apparently successful after all, even
						// though there appeared to be an error
						fIsConnected = true;
					}
					else
					{
						// System-level error occurred
						throw TSymLibErrorObj(errno,"While attempting to make an SSL connection");
					}
				}
				break;
			
			case SSL_ERROR_SSL:
				{
					// SSL-specific error occurred
					throw TSSLErrorObj(kSSLConnectionTerminated,"While attempting to make an SSL connection");
				}
				break;
		}
	}
}

//---------------------------------------------------------------------
// TSSLConnection::GetPeerCertificate
//---------------------------------------------------------------------
TX509Obj TSSLConnection::GetPeerCertificate (bool requireCertificate)
{
	TX509Obj	x509Obj;
	X509*		x509Ptr = NULL;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (!IsConnected())
		throw TSSLErrorObj(kSSLNotConnected);
	
	x509Ptr = SSL_get_peer_certificate(fSSLPtr);
	
	if (x509Ptr)
	{
		// We have a certificate.  Assign it to the object to make a copy.
		x509Obj = x509Ptr;
		
		// Explicitly free the pointer we received.
		X509_free(x509Ptr);
	}
	else if (requireCertificate)
	{
		// The caller really wants a certificate and we didn't get one.
		throw TSSLErrorObj(kSSLPeerCertificateMissing);
	}
	
	return x509Obj;
}

//---------------------------------------------------------------------
// TSSLConnection::VerifyPeerCertificate
//---------------------------------------------------------------------
bool TSSLConnection::VerifyPeerCertificate (bool requireCertificate)
{
	X509*		x509Ptr = NULL;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (!IsConnected())
		throw TSSLErrorObj(kSSLNotConnected);
	
	x509Ptr = SSL_get_peer_certificate(fSSLPtr);
	
	if (x509Ptr != NULL)
	{
		// The remote system supplied some kind of certificate.  Verify it.
		if (SSL_get_verify_result(fSSLPtr) != X509_V_OK)
		{
			// It failed.  Before throwing an exception, free the certificate
			X509_free(x509Ptr);
			x509Ptr = NULL;
			
			throw TSSLErrorObj(kSSLPeerCertificateVerificationFailure);
		}
	}
	else if (requireCertificate)
	{
		// Our caller says that we must have a certificate.
		throw TSSLErrorObj(kSSLPeerCertificateMissing);
	}
	
	if (x509Ptr)
		X509_free(x509Ptr);
	
	return true;
}

//---------------------------------------------------------------------
// TSSLConnection::BytesInBuffer
//---------------------------------------------------------------------
unsigned long TSSLConnection::BytesInBuffer ()
{
	unsigned long		bytesAvail = 0;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (IsConnected())
		bytesAvail = SSL_pending(fSSLPtr);
	
	return bytesAvail;
}

//---------------------------------------------------------------------
// TSSLConnection::Read
//---------------------------------------------------------------------
std::string TSSLConnection::Read (unsigned long maxByteCount)
{
	std::string				buffer;
    std::string             peek_buffer;
	
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (!IsConnected())
		throw TSSLErrorObj(kSSLNotConnected);
	
	if (maxByteCount > 0)
	{
		time_t					expireTime = 0;
		bool					hasTimeout = (fIOTimeout > 0);
		bool					doLoop = true;
		unsigned long			bytesRead = 0;
		TLockedPthreadMutexObj	lock(fIOMutex);
		
		// Setup the receive buffer
		buffer.resize(maxByteCount);
		peek_buffer.resize(maxByteCount);
		
		// Force the network socket(s) to non-blocking mode
		_ForceBlockingMode(false);
		
		// Set the global timeout expiration time
		if (hasTimeout)
			expireTime = time(NULL) + fIOTimeout;
            
		while (doLoop)
		{
			int		readResult = 0;
	        int     peekResult = 0;

			if (hasTimeout && time(NULL) >= expireTime)
				throw TSymLibErrorObj(kErrorServerCommunicationTimeout,"Communication timeout while reading data from server");
		   

			readResult = SSL_read(fSSLPtr,const_cast<char*>(buffer.data() + bytesRead),buffer.capacity() - bytesRead);
            
            peekResult = SSL_peek(fSSLPtr,const_cast<char*>(peek_buffer.data() + bytesRead), peek_buffer.capacity() - bytesRead);
            
			if (readResult > 0)
			{
				bytesRead += readResult;
                
                peekResult = SSL_peek(fSSLPtr,const_cast<char*>(peek_buffer.data() + bytesRead), peek_buffer.capacity() - bytesRead);
				
                if (peekResult > 0) 
                {
                    doLoop = true;
                } 
                else 
                {
                    doLoop = false;
                }
			}
			else
			{
				int	errResult = SSL_get_error(fSSLPtr,readResult);
				
				switch (errResult)
				{
					case SSL_ERROR_WANT_READ:
						{
							fd_set 			fds;
							int				fd = SSL_get_rfd(fSSLPtr);
							struct timeval	timeoutParam;
							struct timeval*	timeoutParamPtr = NULL;
							
							FD_ZERO(&fds);
							FD_SET(fd,&fds);
							
							if (hasTimeout)
							{
								// Setup the timeout
								timeoutParam.tv_sec = expireTime - time(NULL);
								timeoutParam.tv_usec = 0;
								timeoutParamPtr = &timeoutParam;
							}
							
							if (select(fd+1,&fds,NULL,NULL,timeoutParamPtr) < 0)
							{
								// Error condition
								throw TSymLibErrorObj(errno,"While attempting to read from an SSL connection");
							}
						}
						break;
					
					case SSL_ERROR_WANT_WRITE:
						{
							fd_set 		fds;
							int			fd = SSL_get_wfd(fSSLPtr);
							struct timeval	timeoutParam;
							struct timeval*	timeoutParamPtr = NULL;
							
							FD_ZERO(&fds);
							FD_SET(fd,&fds);
							
							if (hasTimeout)
							{
								// Setup the timeout
								timeoutParam.tv_sec = expireTime - time(NULL);
								timeoutParam.tv_usec = 0;
								timeoutParamPtr = &timeoutParam;
							}
							
							if (select(fd+1,NULL,&fds,NULL,timeoutParamPtr) < 0)
							{
								// Error condition
								throw TSymLibErrorObj(errno,"While attempting to read from an SSL connection");
							}
						}
						break;
					
					case SSL_ERROR_NONE:
						{
							// Everything is okay.  Really.
							buffer = "";
							bytesRead = 0;
							doLoop = false;
						}
						break;
					
					case SSL_ERROR_ZERO_RETURN:
						{
							// There was a clean shutdown.  Mark our connection as disconnected
							fIsConnected = false;
							
							// Throw an error to indicate the read failure
							throw TSSLErrorObj(kSSLConnectionTerminated,"Connection terminated");
						}
						break;
					
					case SSL_ERROR_SYSCALL:
						{
							if (readResult == 0)
							{
								// An EOF was observed that violates the protocol
								fIsConnected = false;
								throw TSSLErrorObj(kSSLConnectionTerminated,"Connection terminated (EOF)");
							}
							else
							{
								if (errno == 0)
								{
									// This is indicative of an underlying network problem.
									fIsConnected = false;
									throw TSSLErrorObj(kSSLConnectionTerminated,"Connection terminated");
								}
								else
								{
									// System-level error occurred
									throw TSymLibErrorObj(errno,"While attempting to read from an SSL connection");
								}
							}
						}
						break;
					
					case SSL_ERROR_SSL:
						{
							// SSL-specific error occurred
							throw TSSLErrorObj(kSSLConnectionTerminated,"While attempting to read from an SSL connection");
						}
						break;
				}
			}
		}
		
		buffer.resize(bytesRead);
	}
        
	return buffer;
}

//---------------------------------------------------------------------
// TSSLConnection::Write
//---------------------------------------------------------------------
void TSSLConnection::Write (const std::string& buffer)
{
	if (!IsInited())
		throw TSSLErrorObj(kSSLSSLNotInited);
	
	if (!IsConnected())
		throw TSSLErrorObj(kSSLNotConnected);
	
	if (!buffer.empty())
	{
		time_t					expireTime = 0;
		bool					hasTimeout = (fIOTimeout > 0);
		char*					ptr = const_cast<char*>(buffer.data());
		int						bytesRemaining = buffer.length();
		TLockedPthreadMutexObj	lock(fIOMutex);
		
		// Force the network socket(s) to non-blocking mode
		_ForceBlockingMode(false);
		
		// Set the global timeout expiration time
		if (hasTimeout)
			expireTime = time(NULL) + fIOTimeout;
		
		while (bytesRemaining > 0)
		{
			int		writeResult = 0;
			
			if (hasTimeout && time(NULL) >= expireTime)
				throw TSymLibErrorObj(kErrorServerCommunicationTimeout,"Communication timeout while sending data to server");
			
			writeResult = SSL_write(fSSLPtr,ptr,bytesRemaining);
			
			if (writeResult > 0)
			{
				// writeResult in this case indicates the number of bytes
				// actually written.  Modify our pointers so we can send
				// the rest of the buffer, if necessary
				bytesRemaining -= writeResult;
				ptr += writeResult;
			}
			else
			{
				int	errResult = SSL_get_error(fSSLPtr,writeResult);
				
				switch (errResult)
				{
					case SSL_ERROR_WANT_READ:
						{
							fd_set 			fds;
							int				fd = SSL_get_rfd(fSSLPtr);
							struct timeval	timeoutParam;
							struct timeval*	timeoutParamPtr = NULL;
							
							FD_ZERO(&fds);
							FD_SET(fd,&fds);
							
							if (hasTimeout)
							{
								// Setup the timeout
								timeoutParam.tv_sec = expireTime - time(NULL);
								timeoutParam.tv_usec = 0;
								timeoutParamPtr = &timeoutParam;
							}
							
							if (select(fd+1,&fds,NULL,NULL,timeoutParamPtr) < 0)
							{
								// Error condition
								throw TSymLibErrorObj(errno,"While attempting to write to an SSL connection");
							}
						}
						break;
					
					case SSL_ERROR_WANT_WRITE:
						{
							fd_set 			fds;
							int				fd = SSL_get_wfd(fSSLPtr);
							struct timeval	timeoutParam;
							struct timeval*	timeoutParamPtr = NULL;
							
							FD_ZERO(&fds);
							FD_SET(fd,&fds);
							
							if (hasTimeout)
							{
								// Setup the timeout
								timeoutParam.tv_sec = expireTime - time(NULL);
								timeoutParam.tv_usec = 0;
								timeoutParamPtr = &timeoutParam;
							}
							
							if (select(fd+1,NULL,&fds,NULL,timeoutParamPtr) < 0)
							{
								// Error condition
								throw TSymLibErrorObj(errno,"While attempting to write to an SSL connection");
							}
						}
						break;
					
					case SSL_ERROR_NONE:
						break;
					
					case SSL_ERROR_ZERO_RETURN:
						{
							// There was a clean shutdown.  Mark our connection as disconnected
							fIsConnected = false;
							
							// Throw an error to indicate the read failure
							throw TSSLErrorObj(kSSLConnectionTerminated,"Connection terminated");
						}
						break;
					
					case SSL_ERROR_SYSCALL:
						{
							if (writeResult == 0)
							{
								// An EOF was observed that violates the protocol
								fIsConnected = false;
								throw TSSLErrorObj(kSSLConnectionTerminated,"Connection terminated (EOF)");
							}
							else
							{
								if (errno == 0)
								{
									// This is indicative of an underlying network problem.
									fIsConnected = false;
									throw TSSLErrorObj(kSSLConnectionTerminated,"Connection terminated");
								}
								else
								{
									// System-level error occurred
									throw TSymLibErrorObj(errno,"While attempting to write to an SSL connection");
								}
							}
						}
						break;
					
					case SSL_ERROR_SSL:
						{
							// SSL-specific error occurred
							throw TSSLErrorObj(kSSLConnectionTerminated,"While attempting to write to an SSL connection");
						}
						break;
				}
			}
		}
	}
}

//---------------------------------------------------------------------
// TSSLConnection::ShutdownConnection
//---------------------------------------------------------------------
void TSSLConnection::ShutdownConnection ()
{
	int						shutdownResult = 0;
	TLockedPthreadMutexObj	lock(fIOMutex);
	
	if (IsConnected())
	{
		// Force the network socket(s) to blocking mode
		_ForceBlockingMode(true);
		
		shutdownResult = SSL_shutdown(fSSLPtr);
		if (shutdownResult == 0)
		{
			// Call it again to handle bi-directional shutdowns
			shutdownResult = SSL_shutdown(fSSLPtr);
		}
		
		// Regardless of what happens, assume we've shutdown communication.
		// This should be safe, since we're in blocking mode
		fIsConnected = false;
		
		if (shutdownResult != 1)
		{
			int		errResult = SSL_get_error(fSSLPtr,shutdownResult);
			
			switch (errResult)
			{
				case SSL_ERROR_NONE:
				case SSL_ERROR_ZERO_RETURN:
					{
						// Everything is okay.
					}
					break;
				
				case SSL_ERROR_SYSCALL:
					{
						// System-level error occurred
						if (errno != 0)
						{
							throw TSymLibErrorObj(errno,"While attempting to shutdown an SSL connection");
						}
						else
						{
							// The shutdown really did succeed, the library is just confused
						}
					}
					break;
				
				case SSL_ERROR_SSL:
					{
						// SSL-specific error occurred
						throw TSSLErrorObj(kSSLConnectionTerminated,"While attempting to shutdown an SSL connection");
					}
					break;
			}
		}
	}
}

//---------------------------------------------------------------------
// TSSLConnection::_Free (protected)
//---------------------------------------------------------------------
void TSSLConnection::_Free ()
{
	if (IsInited())
	{
		SSL_free(fSSLPtr);
		fSSLPtr = NULL;
	}
}

//---------------------------------------------------------------------
// TSSLConnection::_ForceBlockingMode (protected)
//---------------------------------------------------------------------
void TSSLConnection::_ForceBlockingMode (bool blocking)
{
	int		readSocket = SSL_get_rfd(fSSLPtr);
	int		writeSocket = SSL_get_wfd(fSSLPtr);
	int		oldFlags = 0;
	bool	isBlockingNow = false;
	
	// Set the read socket
	oldFlags = fcntl(readSocket,F_GETFL);
	isBlockingNow = ((oldFlags & O_NONBLOCK) == 0);
	if (blocking != isBlockingNow)
	{
		if (blocking)
			fcntl(readSocket,F_SETFL,oldFlags & ~O_NONBLOCK);
		else
			fcntl(readSocket,F_SETFL,oldFlags|O_NONBLOCK);
	}
	
	// Set the write socket if it's different
	if (readSocket != writeSocket)
	{
		oldFlags = fcntl(writeSocket,F_GETFL);
		isBlockingNow = ((oldFlags & O_NONBLOCK) == 0);
		if (blocking != isBlockingNow)
		{
			if (blocking)
				fcntl(writeSocket,F_SETFL,oldFlags & ~O_NONBLOCK);
			else
				fcntl(writeSocket,F_SETFL,oldFlags|O_NONBLOCK);
		}
	}
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

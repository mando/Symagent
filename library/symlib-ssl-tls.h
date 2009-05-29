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
#		Last Modified:				16 Mar 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_SSL_TLS)
#define SYMLIB_SSL_TLS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-ssl-util.h"
#include "symlib-ssl-cert.h"
#include "symlib-ssl-pkey.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef	enum	{
					kSSLClientMode,
					kSSLServerMode,
					kSSLClientServerMode
				}	SSLConnectionMode;

typedef	enum	{
					kSSLv2Protocol,
					kSSLv3Protocol,
					kTLSv1Protocol,
					kSSLv23Protocol
				}	SSLProtocolType;

typedef			int (*SSLVerifyCallback)(int, X509_STORE_CTX*);
typedef			void (*SSLInfoCallback)(const SSL* ssl, int where, int ret);
typedef			int (*SSLNewSessionCallback)(SSL* ssl, SSL_SESSION* ssl);
typedef			void (*SSLRemoveSessionCallback)(SSL_CTX* context, SSL_SESSION* ssl);
typedef			SSL_SESSION* (*SSLResumeSessionCallback)(SSL* ssl, unsigned char *data, int len, int* copy);

#if SSL_INFO_CALLBACK_ARG_WITH_ARGS
	typedef		SSLInfoCallback		SSLInfoCallbackAsArgument;
	typedef		SSLInfoCallback		SSLCTXInfoCallbackAsArgument;
#else
	typedef		void (*SSLCTXInfoCallbackAsArgument)();
	#if SSL_INFO_CALLBACK_ARG_ELIDED
		typedef		void (*SSLInfoCallbackAsArgument)(...);
	#else
		typedef		void (*SSLInfoCallbackAsArgument)();
	#endif
#endif

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TSSLContext;
class TSSLSession;
class TSSLConnection;

//---------------------------------------------------------------------
// Class TSSLContext
//---------------------------------------------------------------------
class TSSLContext
{
	public:
		
		TSSLContext ();
			// Constructor
		
		TSSLContext (SSL_CTX* sslContextPtr);
			// Constructor
		
		TSSLContext (const TSSLContext& obj);
			// Copy constructor
		
		virtual ~TSSLContext ();
			// Destructor
		
		virtual void Initialize (SSL_METHOD* method);
			// Sets the connection method for this object.  The
			// existing context, if any, will be destroyed.
			// OpenSSL functions:  SSL_CTX_new
		
		virtual void Initialize (SSLConnectionMode connectionType, SSLProtocolType protocolType);
			// An alternate way of setting the context's connection
			// method, using values instead.  Calls the previous
			// Initialize() member function with the appropriate
			// argument.
		
		virtual long GetMode ();
			// Returns the current object's mode settings.
			// OpenSSL functions:  SSL_CTX_get_mode
		
		virtual long SetMode (long modeMask);
			// Adds the given modeMask to the current mode settings.
			// Options that were previously set are not cleared.  Returns
			// the new mode value after modeMask has been added.
			// OpenSSL functions:  SSL_CTX_set_mode
		
		virtual long GetOptions ();
			// Returns the current object's option settings.
			// OpenSSL functions:  SSL_CTX_get_options
		
		virtual long SetOptions (long optionsMask);
			// Adds the given optionsMask to the current options settings.
			// Options that were previously set are not cleared.  Returns
			// the new options value after optionsMask has been added.
			// OpenSSL functions:  SSL_CTX_set_options
		
		virtual long GetTimeout ();
			// Returns the current timeout value in seconds.
			// OpenSSL functions:  SSL_CTX_get_timeout
		
		virtual long SetTimeout (long newTimeout);
			// Sets the timeout (in seconds) for the current context.
			// Returns the previous timeout value.
			// OpenSSL functions:  SSL_CTX_set_timeout
		
		virtual void SetCertificate (TX509Obj& certObj);
			// Sets the certificate associated with this object.
			// OpenSSL functions:  SSL_CTX_use_certificate
		
		virtual void SetCertificate (const TFileObj& certFileObj, int formatType);
			// Sets the certificate associated with this object.  The
			// formatType argument must be one of SSL_FILETYPE_PEM or
			// SSL_FILETYPE_ASN1.
			// OpenSSL functions:  SSL_CTX_use_certificate_file
		
		virtual void SetCertificateChainFile (const TFileObj& certChainFileObj);
			// Loads a certificate chain from the indicated file. The certificates
			// must be in PEM format and must be sorted starting with the
			// certificate to the highest level (root CA).
			// OpenSSL functions:  SSL_CTX_use_certificate_chain_file
		
		virtual void SetCertificateAuthorityFile (const TFileObj& certAuthFile);
			// Specifies the file which CA certificates for verification
			// purposes are located.
			// OpenSSL functions:  SSL_CTX_load_verify_locations
		
		virtual void SetCertificateAuthorityDirectory (const TDirObj& certAuthDir);
			// Specifies the directory which CA certificates for verification
			// purposes are located.
			// OpenSSL functions:  SSL_CTX_load_verify_locations
		
		virtual void SetPrivateKey (TPKeyObj& privateKeyObj);
			// Sets the private key associated with this object.
			// OpenSSL functions:  SSL_CTX_use_PrivateKey
		
		virtual void SetPrivateKey (const TFileObj& privateKeyFileObj, int formatType);
			// Sets the private key associated with this object.  The
			// formatType argument must be one of SSL_FILETYPE_PEM or
			// SSL_FILETYPE_ASN1.
			// OpenSSL functions:  SSL_CTX_use_PrivateKey_file
		
		virtual bool CheckPrivateKey ();
			// Checks the consistency of the private key previously set with
			// SetPrivateKey() with the corresponding certificate set with
			// SetCertificate().  An exception is thrown if verification fails;
			// otherwise true is returned.
			// OpenSSL functions:  SSL_CTX_check_private_key
		
		virtual void SetCipherList (const std::string& cipherNameList);
			// Sets the ciphers available to the current context, in the
			// given priority order.  The argument must be in the accepted
			// cipher list format; see ciphers(1)
			// OpenSSL functions:  SSL_CTX_set_cipher_list
		
		virtual void SetCipherList (const StdStringList& cipherNameList);
			// Sets the ciphers available to the current context, in the
			// given priority order.
		
		virtual int GetVerificationMode ();
			// Returns the verification mode of the current object.
			// OpenSSL functions:  SSL_CTX_get_verify_mode
		
		virtual int GetVerificationDepth ();
			// Returns the maximum depth certificate chain verification will
			// travel.
			// OpenSSL functions:  SSL_CTX_get_verify_depth
		
		virtual SSLVerifyCallback GetVerificationCallbackFunctionPtr ();
			// Returns a function pointer to the current verification
			// callback function or NULL if no custom callback has been
			// set.
			// OpenSSL functions:  SSL_CTX_get_verify_callback
		
		virtual void SetVerificationParams (int mode, SSLVerifyCallback callback = NULL, int depth = 9);
			// Sets the verification settings for the current object.  mode can
			// be OR'd values of SSL_VERIFY_NONE, SSL_VERIFY_PEER,
			// SSL_VERIFY_FAIL_IF_NO_PEER_CERT or SSL_VERIFY_CLIENT_ONCE
			// (with limitations -- see the SSL documentation).  The callback
			// provides a hook for an external verification procedure; pass NULL
			// to use the default procedure.  depth sets the maximum depth for the
			// certificate chain verification that shall be allowed.
			// OpenSSL functions:  SSL_CTX_set_verify, SSL_CTX_set_verify_depth
		
		virtual SSLInfoCallback GetInfoCallback ();
			// Returns the callback function ptr previously set via SetInfoCallback()
			// or NULL if no callback has been set.
			// OpenSSL functions:  SSL_CTX_get_info_callback
		
		virtual void SetInfoCallback (SSLInfoCallback functionPtr);
			// Sets the callback function that can be used to obtain state information
			// from the current context as it's being used.
			// OpenSSL functions:  SSL_CTX_set_info_callback
		
		virtual SSLNewSessionCallback GetNewSessionCallback ();
			// Returns the callback function ptr previously set via SetNewSessionCallback()
			// or NULL if no callback has been set.
			// OpenSSL functions:  SSL_CTX_sess_get_new_cb
		
		virtual void SetNewSessionCallback (SSLNewSessionCallback functionPtr);
			// Sets the callback function that is automatically called whenever a new
			// session was negotiated and session caching is enabled.
			// OpenSSL functions:  SSL_CTX_sess_set_new_cb
		
		virtual SSLRemoveSessionCallback GetRemoveSessionCallback ();
			// Returns the callback function ptr previously set via SetRemoveSessionCallback()
			// or NULL if no callback has been set.
			// OpenSSL functions:  SSL_CTX_sess_get_remove_cb
		
		virtual void SetRemoveSessionCallback (SSLRemoveSessionCallback functionPtr);
			// Sets the callback function, which is automatically called whenever a
			// session is removed by the SSL engine, because it is considered faulty
			// or the session has become obsolete because of exceeding the timeout value.
			// OpenSSL functions:  SSL_CTX_sess_set_remove_cb
		
		virtual SSLResumeSessionCallback GetResumeSessionCallback ();
			// Returns the callback function ptr previously set via SetResumeSessionCallback()
			// or NULL if no callback has been set.
			// OpenSSL functions:  SSL_CTX_sess_get_get_cb
		
		virtual void SetResumeSessionCallback (SSLResumeSessionCallback functionPtr);
			// Sets the callback function which is called whenever a SSL/TLS client
			// proposed to resume a session but the session could not be found in the
			// internal session cache.  SSL/TLS server mode only.
			// OpenSSL functions:  SSL_CTX_sess_set_get_cb
		
		virtual void SetSessionIDContext (const unsigned char* contextPtr, unsigned int contextSize);
			// Sets the session ID context to the binary data pointed to be contextPtr
			// and of length contextSize.  This is applicable to only server (connect)
			// mode.
			// OpenSSL functions:  SSL_CTX_set_session_id_context
		
		virtual void SetSessionIDContext (const std::string& context);
			// Sets the session ID context to the binary data given as the argument.
		
		virtual long GetSessionCacheSize ();
			// Returns the size of the internal session cache.  A return value of zero
			// indicates unlimited size.
			// OpenSSL functions:  SSL_CTX_sess_get_cache_size
		
		virtual void SetSessionCacheSize (long newCacheSize);
			// Changes the size of the internal session cache.  A size of zero indicates
			// an unlimited cache size.
			// OpenSSL functions:  SSL_CTX_sess_set_cache_size
		
		virtual long GetSessionCacheMode ();
			// Returns the cache mode currently in use.
			// OpenSSL functions:  SSL_CTX_get_session_cache_mode
		
		virtual void SetSessionCacheMode (long newCacheMode);
			// Sets the cache mode.  See SSL_CTX_set_session_cache_mode(3)
			// for a list of acceptable cache modes.
			// OpenSSL functions:  SSL_CTX_set_session_cache_mode
		
		virtual void AddSession (TSSLSession& sessionObj);
			// Adds the given session to the current context.  If an already loaded
			// session contains the same ID as the argument then it is replaced.
			// OpenSSL functions:  SSL_CTX_add_session
		
		virtual void RemoveSession (TSSLSession& sessionObj);
			// Removes the given session to the current context if it exists.
			// OpenSSL functions:  SSL_CTX_remove_session
		
		virtual void FlushSessions (time_t expireTime = 0);
			// Removes all sessions from the internal cache that are expired as of
			// the time indicated by the argument.  If expireTime is zero then
			// the current time is used.
			// OpenSSL functions:  SSL_CTX_flush_sessions
		
		virtual long SessionCount ();
			// Returns the number of sessions in the internal session cache.
			// OpenSSL functions:  SSL_CTX_sess_number
		
		virtual long SessionOverloadCount ();
			// Returns the number of sessions removed from the internal cache because
			// the cache became full.
			// OpenSSL functions:  SSL_CTX_sess_cache_full
		
		virtual long SessionCacheHitCount ();
			// Returns the total number of successful session reuse attempts.  When
			// in server (connect) mode this number includes both internal and
			// external cache hits.
			// OpenSSL functions:  SSL_CTX_sess_hits
		
		virtual long SessionCacheMissCount ();
			// Returns the number of failed session reuse attempts proposed by
			// clients.  Number reflects misses against the internal cache only,
			// and is applicable only to server (connect) contexts.
			// OpenSSL functions:  SSL_CTX_sess_misses
		
		virtual long SessionExternalCacheHitCount ();
			// Returns the number of successful  session reuse attempts using an
			// external session cache.  Only used by server (connect) mode.
			// OpenSSL functions:  SSL_CTX_sess_cb_hits
		
		virtual long SessionTimeoutCount ();
			// Returns the number of proposed session reuse attempts that would have
			// succeeded except that they had timed out.  This number is not reflected
			// in the value returned by SessionCacheHitCount().
			// OpenSSL functions:  SSL_CTX_sess_timeouts
		
		virtual long ConnectStartedCount ();
			// Returns the number of connection attempts started by this context.
			// OpenSSL functions:  SSL_CTX_sess_connect
		
		virtual long ConnectSucceededCount ();
			// Returns the number of successful connections made by this context.
			// OpenSSL functions:  SSL_CTX_sess_connect_good
		
		virtual long ConnectRenegotiationsCount ();
			// Returns the number of renegotiations started by this context when
			// in client (connect) mode.
			// OpenSSL functions:  SSL_CTX_sess_connect_renegotiate
		
		virtual long AcceptStartedCount ();
			// Returns the number of accept attempts started by this context.
			// OpenSSL functions:  SSL_CTX_sess_accept
		
		virtual long AcceptSucceededCount ();
			// Returns the number of successful accepts made by this context.
			// OpenSSL functions:  SSL_CTX_sess_accept_good
		
		virtual long AcceptRenegotiationsCount ();
			// Returns the number of renegotiations started by this context when
			// in server (accept) mode.
			// OpenSSL functions:  SSL_CTX_sess_accept_renegotiate
		
		// Accessors
		
		inline bool IsInited () const
			{ return (fContextPtr != NULL); }
		
		inline operator const SSL_CTX* () const
			{ return fContextPtr; }
		
		inline operator SSL_CTX* ()
			{ return fContextPtr; }
	
	protected:
		
		virtual void _IniTSSLConnectionLib ();
			// Ensures that the SSL library is properly initialized.
			// This method is thread-aware.
		
		virtual void _Free ();
			// Frees our context and resets this object
			// to an initialized state.
			// OpenSSL functions:  SSL_CTX_free
	
	protected:
		
		SSL_CTX*								fContextPtr;
};

//---------------------------------------------------------------------
// Class TSSLSession
//---------------------------------------------------------------------
class TSSLSession
{
	public:
		
		TSSLSession ();
			// Constructor
		
		TSSLSession (SSL_SESSION* sslSessionPtr);
			// Constructor
		
		TSSLSession (const TSSLSession& obj);
			// Copy constructor
		
		virtual ~TSSLSession ();
			// Destructor
		
		virtual time_t GetTimeStarted ();
			// Returns the time the current session was started, in Unix seconds.
			// OpenSSL functions:  SSL_SESSION_get_time
		
		virtual void SetTimeStarted (time_t newTime);
			// Changes the timestamp representing when the current session
			// started.
			// OpenSSL functions:  SSL_SESSION_set_time
		
		virtual long GetTimeout ();
			// Returns the current timeout value in seconds.
			// OpenSSL functions:  SSL_SESSION_get_timeout
		
		virtual void SetTimeout (long newTimeout);
			// Sets the timeout (in seconds) for the current session.
			// OpenSSL functions:  SSL_SESSION_set_timeout
		
		virtual std::string Serialize ();
			// Returns an ASN1 representation of the current session.
			// OpenSSL functions:  i2d_SSL_SESSION
		
		#if (1 == 1)
		virtual void Deserialize (const unsigned char* sessionDataPtr, unsigned int sessionDataSize);
		#else
		virtual void Deserialize (unsigned char* sessionDataPtr, unsigned int sessionDataSize);
		#endif
			// Transforms the external ASN1 representation of a session (as if
			// generated by Serialize()), stored at the given memory location and
			// of the given size, into a valid session.  Destructively modifies
			// this object to contain that session.
			// OpenSSL functions:  d2i_SSL_SESSION
		
		virtual void Deserialize (std::string& sessionData);
			// Transforms the external ASN1 representation of a session (as if
			// generated by Serialize()), stored in the argument, into a valid
			// session.  Destructively modifies this object to contain that session.
		
		// Accessors
		
		inline bool IsInited () const
			{ return (fSessionPtr != NULL); }
		
		inline operator const SSL_SESSION* () const
			{ return fSessionPtr; }
		
		inline operator SSL_SESSION* ()
			{ return fSessionPtr; }
	
	protected:
		
		virtual void _Free ();
			// Frees our session and resets this object
			// to an initialized state.
			// OpenSSL functions:  SSL_SESSION_free
	
	protected:
		
		SSL_SESSION*							fSessionPtr;
};

//---------------------------------------------------------------------
// Class TSSLConnection
//---------------------------------------------------------------------
class TSSLConnection
{
	public:
		
		TSSLConnection ();
			// Constructor
		
		TSSLConnection (SSL* sslPtr);
			// Constructor
			// OpenSSL functions:  SSL_is_init_finished
		
		TSSLConnection (const TSSLConnection& obj);
			// Copy constructor
			// OpenSSL functions:  SSL_is_init_finished
		
		virtual ~TSSLConnection ();
			// Destructor
		
		virtual void Initialize (TSSLContext& sslContextObj);
			// Sets the connection method for this object.  The
			// existing context, if any, will be destroyed.
			// OpenSSL functions:  SSL_new
		
		virtual int GetInputSocket ();
			// Returns the network socket number currently used as the
			// read channel.
			// OpenSSL functions:  SSL_get_rfd
		
		virtual void SetInputSocket (int socketNum);
			// Attaches the given socket to the current object
			// as the read channel for input.  You should probably also
			// call SetOutputSocket() to set the write channel.
			// Initialize() must have already been called.
			// OpenSSL functions:  SSL_set_rfd
		
		virtual int GetOutputSocket ();
			// Returns the network socket number currently used as the
			// write channel.
			// OpenSSL functions:  SSL_get_wfd
		
		virtual void SetOutputSocket (int socketNum);
			// Attaches the given socket to the current object
			// as the write channel for output.  You should probably also
			// call SetInputSocket() to set the write channel.
			// Initialize() must have already been called.
			// OpenSSL functions:  SSL_set_wfd
		
		virtual int GetInputOutputSocket ();
			// Returns the network socket number set by a call to
			// SetInputOutputSocket().
			// OpenSSL functions:  SSL_get_fd
		
		virtual void SetInputOutputSocket (int socketNum);
			// Attaches the given socket to the current object.
			// Initialize() must have already been called.
			// OpenSSL functions:  SSL_set_fd
		
		virtual long GetMode ();
			// Returns the current object's mode settings.
			// OpenSSL functions:  SSL_get_mode
		
		virtual long SetMode (long modeMask);
			// Adds the given modeMask to the current mode settings.
			// Options that were previously set are not cleared.
			// OpenSSL functions:  SSL_set_mode
		
		virtual long GetOptions ();
			// Returns the current object's option settings.
			// OpenSSL functions:  SSL_get_options
		
		virtual long SetOptions (long optionsMask);
			// Adds the given optionsMask to the current options settings.
			// Options that were previously set are not cleared.
			// OpenSSL functions:  SSL_set_options
		
		virtual long GetDefaultTimeout ();
			// Returns the default timeout value assigned to new session objects
			// negotiated for this connection.
			// OpenSSL functions:  SSL_get_default_timeout
		
		virtual void SetCertificate (TX509Obj& certObj);
			// Sets the certificate associated with this object.
			// OpenSSL functions:  SSL_use_certificate
		
		virtual void SetCertificate (const TFileObj& certFileObj, int formatType);
			// Sets the certificate associated with this object.  The
			// formatType argument must be one of SSL_FILETYPE_PEM or
			// SSL_FILETYPE_ASN1.
			// OpenSSL functions:  SSL_use_certificate_file
		
		virtual void SetPrivateKey (TPKeyObj& privateKeyObj);
			// Sets the private key associated with this object.
			// OpenSSL functions:  SSL_use_PrivateKey
		
		virtual void SetPrivateKey (const TFileObj& privateKeyFileObj, int formatType);
			// Sets the private key associated with this object.  The
			// formatType argument must be one of SSL_FILETYPE_PEM or
			// SSL_FILETYPE_ASN1.
			// OpenSSL functions:  SSL_use_PrivateKey_file
		
		virtual bool CheckPrivateKey ();
			// Checks the consistency of the private key previously set with
			// SetPrivateKey() with the corresponding certificate set with
			// SetCertificate().  An exception is thrown if verification fails;
			// otherwise true is returned.
			// OpenSSL functions:  SSL_check_private_key
		
		virtual void GetCipherList (StdStringList& cipherNameList);
			// Destructively modifies the argument to contain the names
			// of the ciphers available to the current connection, sorted in
			// order of priority.
			// OpenSSL functions:  SSL_get_cipher_list
		
		virtual void GetCipherList (TCipherList& cipherObjList);
			// Destructively modifies the argument to contain a list
			// of cipher objects representing the ciphers available
			// to the current connection, sorted in order of priority.
		
		virtual void SetCipherList (const std::string& cipherNameList);
			// Sets the ciphers available to the current context, in the
			// given priority order.  The argument must be in the accepted
			// cipher list format; see ciphers(1)
			// OpenSSL functions:  SSL_set_cipher_list
		
		virtual void SetCipherList (const StdStringList& cipherNameList);
			// Sets the ciphers available to the current connection, in the
			// given priority order.
		
		virtual void SetCipherList (const TCipherList& cipherObjList);
			// Sets the ciphers available to the current connection, in the
			// given priority order.
		
		virtual int GetVerificationMode ();
			// Returns the verification mode of the current object.
			// OpenSSL functions:  SSL_get_verify_mode
		
		virtual int GetVerificationDepth ();
			// Returns the maximum depth certificate chain verification will
			// travel.
			// OpenSSL functions:  SSL_get_verify_depth
		
		virtual SSLVerifyCallback GetVerificationCallbackFunctionPtr ();
			// Returns a function pointer to the current verification
			// callback function or NULL if no custom callback has been
			// set.
			// OpenSSL functions:  SSL_get_verify_callback
		
		virtual void SetVerificationParams (int mode, SSLVerifyCallback callback = NULL, int depth = 9);
			// Sets the verification settings for the current object.  mode can
			// be OR'd values of SSL_VERIFY_NONE, SSL_VERIFY_PEER,
			// SSL_VERIFY_FAIL_IF_NO_PEER_CERT or SSL_VERIFY_CLIENT_ONCE
			// (with limitations -- see the SSL documentation).  The callback
			// provides a hook for an external verification procedure; pass NULL
			// to use the default procedure.  depth sets the maximum depth for the
			// certificate chain verification that shall be allowed.
			// OpenSSL functions:  SSL_set_verify, SSL_set_verify_depth
		
		virtual SSL_CIPHER* GetCurrentCipher ();
			// Returns a pointer to an SSL_CIPHER object containing the description
			// of the cipher used in the current connection.
			// OpenSSL functions:  SSL_get_current_cipher
		
		virtual std::string GetCurrentCipherName ();
			// Returns the name of the cipher used in the current connection.
			// OpenSSL functions:  SSL_get_cipher_name
		
		virtual std::string GetCurrentCipherVersion ();
			// Returns the protocol version of the cipher used in the current connection.
			// OpenSSL functions:  SSL_get_cipher_version
		
		virtual std::string GetCurrentCipherDescription ();
			// Returns a textual description of the cipher used in the current connection.
			// OpenSSL functions:  SSL_CIPHER_description
		
		virtual int GetCurrentCipherBits ();
			// Returns the number of secret bits used by the cipher governing the
			// current connection.
			// OpenSSL functions:  SSL_get_cipher_bits
		
		virtual void SetSessionIDContext (const unsigned char* contextPtr, unsigned int contextSize);
			// Sets the session ID context to the binary data pointed to be contextPtr
			// and of length contextSize.  This is applicable to only server (connect)
			// mode.
			// OpenSSL functions:  SSL_set_session_id_context
		
		virtual void SetSessionIDContext (const std::string& context);
			// Sets the session ID context to the binary data given as the argument.
		
		virtual TSSLSession GetCurrentSession ();
			// Returns a session object referencing the current connection.
			// OpenSSL functions:  SSL_get_session
		
		virtual void SetCurrentSession (TSSLSession& sessionObj);
			// Sets the session that will be used for a future connection.  It
			// may or may not actually be reused during that connection; see
			// CurrentSessionReused().
			// OpenSSL functions:  SSL_set_session
		
		virtual SSLInfoCallback GetInfoCallback ();
			// Returns the callback function ptr previously set via SetInfoCallback()
			// or NULL if no callback has been set.
			// OpenSSL functions:  SSL_get_info_callback
		
		virtual void SetInfoCallback (SSLInfoCallback functionPtr);
			// Sets the callback function that can be used to obtain state information
			// from the current connection as it's being used.
			// OpenSSL functions:  SSL_set_info_callback
		
		virtual bool CurrentSessionReused ();
			// Returns a boolean indicating whether the session for the current
			// connection was reused or not.
			// OpenSSL functions:  SSL_session_reused
		
		virtual void Accept ();
			// Waits for a TLS/SSL client to initiate the TLS/SSL handshake.
			// The object must have been initialized with a server-aware
			// method prior to calling this member function.
			// OpenSSL functions:  SSL_accept, SSL_set_mode
		
		virtual void Connect ();
			// Initiate the TLS/SSL handshake with an TLS/SSL server.
			// The object must have been initialized with a client-aware
			// method prior to calling this member function.  This method
			// will always succeed or fail, even if the network connection
			// is in non-blocking mode.
			// OpenSSL functions:  SSL_connect, SSL_set_mode
		
		virtual TX509Obj GetPeerCertificate (bool requireCertificate = false);
			// Returns a certificate object obtained from the remote system.
			// If the remote system refused to supply a certificate then the
			// returned object's IsSet() method will return false.
			// OpenSSL functions:  SSL_get_peer_certificate
		
		virtual bool VerifyPeerCertificate (bool requireCertificate = false);
			// This method requests a certificate from the remote system and,
			// if one is supplied, verifies it.  If the remote system did not
			// supply a certificate and requireCertificate is true then an
			// exception is thrown; otherwise the method will return true.
			// If the remote system does supply a certificate and a verification
			// fails then an exception is thrown; otherwise the method will
			// return true.
			// OpenSSL functions:  SSL_get_peer_certificate, SSL_get_verify_result
		
		virtual unsigned long BytesInBuffer ();
			// Returns the number of bytes sitting in SSL's internal buffer,
			// available to the Read() command.  Note that this does not
			// include any data sitting on the network connection.
			// OpenSSL functions:  SSL_pending
		
		virtual std::string Read (unsigned long maxByteCount);
			// Reads up to maxByteCount bytes from the connection and returns
			// the result in a temporary buffer.  Will return an empty buffer
			// if nothing is available to read.
			// OpenSSL functions:  SSL_read
		
		virtual void Write (const std::string& buffer);
			// Writes the buffer to the current network connection.
			// OpenSSL functions:  SSL_write
		
		virtual void ShutdownConnection ();
			// Performs the shutdown protocol over the current network
			// connection.  Does nothing if there is no connection.
			// OpenSSL functions:  SSL_shutdown, ERR_peek_error
		
		// Accessors
		
		inline bool IsInited () const
			{ return (fSSLPtr != NULL); }
		
		inline bool IsConnected () const
			{ return fIsConnected; }
		
		inline operator const SSL* () const
			{ return fSSLPtr; }
		
		inline operator SSL* ()
			{ return fSSLPtr; }
		
		inline time_t GetIOTimeout () const
			{ return fIOTimeout; }
		
		inline void SetIOTimeout (time_t timeoutInSeconds)
			{ fIOTimeout = timeoutInSeconds; }
	
	protected:
		
		virtual void _Free ();
			// Frees our SSL object and resets this object
			// to an initialized state.
			// OpenSSL functions:  SSL_free
		
		virtual void _ForceBlockingMode (bool blocking);
			// Forces the underlying network socket(s) to blocking or non-blocking
			// mode, depending on the argument.
			// OpenSSL functions:  SSL_get_wfd, SSL_get_rfd
	
	protected:
		
		SSL*								fSSLPtr;
		bool								fIsConnected;
		TPthreadMutexObj					fIOMutex;
		time_t								fIOTimeout;
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif

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

#if !defined(SYMLIB_SSL_ENCODE)
#define SYMLIB_SSL_ENCODE

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
class TSSLBase64;
class TEncodeContext;
class TDecodeContext;

//---------------------------------------------------------------------
// Class TSSLBase64
//
// This is a base class implementing the algorithms surrounding the
// EVP_EncodeXXX and EVP_DecodeXXX routines.  Since virtually everything
// works the same, it makes sense to combine the logic into one class
// and implement only the differences in subclasses.
//
// Users should not directly instantiate this class.  Instead, use
// TEncodeContext or TDecodeContext.
//---------------------------------------------------------------------
class TSSLBase64 : public TUpdateMorphMixin
{
	public:
		
		TSSLBase64 ();
			// Constructor
	
	private:
		
		TSSLBase64 (const TSSLBase64& obj);
			// Copy constructor illegal
	
	public:
		
		virtual ~TSSLBase64 ();
			// Destructor
		
		virtual void Initialize ();
			// Initializes the context.  Automatically called by Update() if
			// needed.
			// OpenSSL functions: EVP_EncodeInit
		
		virtual void Update (unsigned char* inBufferPtr, int inBufferSize, std::string& outBuffer);
			// Encodes the memory pointed to by inBufferPtr, which is
			// inBufferSize bytes in size.  The results of the encoding
			// are concatenated to outBuffer.
			// OpenSSL functions:  EVP_EncryptUpdate
		
		virtual void Update (std::string& inBuffer, std::string& outBuffer);
			// Encodes the contents of inBuffer, concatenating the results
			// to outBuffer.
		
		virtual void Update (TFileObj& inFileObj, TFileObj& outFileObj);
			// Encodes the file cited by the inFileObj argument, concatenating
			// the results into outFileObj.  outFileObj will be created if it
			// doesn't already exist.  outFileObj will be left open when this method
			// completes.  Note:  You must call Final() on the output file to
			// finish the process.
		
		virtual void Final (std::string& outBuffer);
			// The last stage of encoding.  The final bits of data are
			// concatenated to outBuffer.  After this method completes,
			// you must call Initialize() again before reusing this context.
			// OpenSSL functions:  EVP_EncodeFinal
		
		virtual void Final (TFileObj& outFileObj);
			// The last stage of encoding.  The final bits of data are
			// concatenated to the file pointed to by outFileObj.  After
			// this method completes, you must call Initialized() again
			// before reusing this context.  outFileObj must already be open
			// and writable, and this method leaves the file open for future
			// writing if necessary.
		
		// Accessors
		
		inline bool IsInited () const
			{ return fIsInited; }
		
		inline EVP_ENCODE_CTX* Ptr ()
			{ return &fContext; }
		
		inline const EVP_ENCODE_CTX* Ptr () const
			{ return &fContext; }
		
		inline operator EVP_ENCODE_CTX* ()
			{ return Ptr(); }
		
		inline operator const EVP_ENCODE_CTX* () const
			{ return Ptr(); }
	
	protected:
		
		virtual void _Init () = 0;
			// Perform whatever actions are necessary to initialize the
			// context.  Subclasses must override.
		
		virtual int _CodedSize (int inSize) = 0;
			// Returns the number of bytes necessary to hold the 'morphed'
			// version of the given number of bytes.  Subclasses must override.
		
		virtual int _Update (unsigned char* outPtr, unsigned char* inPtr, int inSize) = 0;
			// Perform whatever actions are necessary to update the context
			// and write the result to outPtr.  Returns the number of bytes
			// actually written to outPtr.  Subclasses must override.
		
		virtual int _Final (unsigned char* outPtr) = 0;
			// Perform the final coding steps and place the result into the
			// outPtr argument.  Returns the number of bytes actually written
			// to outPtr.  Subclasses must override.
	
	protected:
		
		bool									fIsInited;
		EVP_ENCODE_CTX							fContext;
};

//---------------------------------------------------------------------
// Class TEncodeContext
//
// This is a specialization of TSSLBase64 that supplies only encoding
// methods.  It inherits the EVP_ENCODE_CTX* conversions so can be
// used in function calls that require EVP_ENCODE_CTX* arguments.
//
// In addition to supplying the same functionality as the original
// EVP_ENCODE_CTX environment, this class supports encoding of entire
// files -- see the Update() methods.
/* Example Usage:

		TEncodeContext			encodingContextObj;
		std::string				message("This is a test message");
		std::string				encodedMessage;
		
		// Initialize the context for encryption
		encodingContextObj.Initialize();
		
		// Encode the message
		encodingContextObj.Update(message,encodedMessage);
		
		// Call final to complete the encoding
		encodingContextObj.Final(encodedMessage);
		
		// Echo the message and the encoded version
		cout << "Original message: " << message << endl;
		cout << "Encoded: " << encodedMessage << endl;
*/
//---------------------------------------------------------------------
class TEncodeContext : public TSSLBase64
{
	private:
		
		typedef		TSSLBase64					Inherited;
		
	public:
		
		TEncodeContext ();
			// Constructor
	
	private:
		
		TEncodeContext (const TEncodeContext& obj);
			// Copy constructor illegal
	
	public:
		
		virtual ~TEncodeContext ();
			// Destructor
		
		virtual std::string Encode (const unsigned char* inBufferPtr, int inBufferSize);
			// Encodes the contents of the memory pointed to by inBufferPtr,
			// which is inBufferSize bytes in length, and returns the result
			// in a temporary std::string object.  Note that the context is
			// unaffected by this operation.  It's basically a single-shot
			// version of Initialize()->Update()->Final().
			// OpenSSL functions:  EVP_EncodeBlock
		
		virtual std::string Encode (const std::string& inBuffer);
			// Encodes the contents of inBuffer and returns the result
			// in a temporary std::string object.  Note that the context is
			// unaffected by this operation.  It's basically a single-shot
			// version of Initialize()->Update()->Final().
	
	protected:
		
		virtual void _Init ();
			// Override.
			// OpenSSL functions:  EVP_EncodeInit
		
		virtual int _CodedSize (int inSize);
			// Override.
			// OpenSSL functions:  EVP_ENCODE_LENGTH
		
		virtual int _Update (unsigned char* outPtr, unsigned char* inPtr, int inSize);
			// Override.
			// OpenSSL functions:  EVP_EncodeUpdate
		
		virtual int _Final (unsigned char* outPtr);
			// Override.
			// OpenSSL functions:  EVP_EncodeFinal
};

//---------------------------------------------------------------------
// Class TDecodeContext
//
// This is a specialization of TSSLBase64 that supplies only decoding
// methods.  It inherits the EVP_ENCODE_CTX* conversions so can be
// used in function calls that require EVP_ENCODE_CTX* arguments.
//
// In addition to supplying the same functionality as the original
// EVP_ENCODE_CTX environment, this class supports decoding of entire
// files -- see the Update() methods.
/* Example Usage:

		TDecodeContext			decodingContextObj;
		std::string				encodedMessage("VGhpcyBpcyBhIHRlc3QgbWVzc2FnZQ==");
		std::string				decodedMessage;
		
		// Initialize the context for encryption
		decodingContextObj.Initialize();
		
		// Decode the message
		decodingContextObj.Update(encodedMessage,decodedMessage);
		
		// Call final to complete the decoding
		decodingContextObj.Final(decodedMessage);
		
		// Echo the message and the decoded version
		cout << "Encoded: " << encodedMessage << endl;
		cout << "Decoded: " << decodedMessage << endl;
*/
//---------------------------------------------------------------------
class TDecodeContext : public TSSLBase64
{
	private:
		
		typedef		TSSLBase64					Inherited;
		
	public:
		
		TDecodeContext ();
			// Constructor
	
	private:
		
		TDecodeContext (const TDecodeContext& obj);
			// Copy constructor illegal
	
	public:
		
		virtual ~TDecodeContext ();
			// Destructor
		
		virtual std::string Decode (unsigned char* inBufferPtr, int inBufferSize);
			// Decodes the contents of the memory pointed to by inBufferPtr,
			// which is inBufferSize bytes in length, and returns the result
			// in a temporary std::string object.  Note that the context is
			// unaffected by this operation.  It's basically a single-shot
			// version of Initialize()->Update()->Final().
			// OpenSSL functions:  EVP_DecodeBlock
		
		virtual std::string Decode (std::string& inBuffer);
			// Decodes the contents of inBuffer and returns the result
			// in a temporary std::string object.  Note that the context is
			// unaffected by this operation.  It's basically a single-shot
			// version of Initialize()->Update()->Final().
	
	protected:
		
		virtual void _Init ();
			// Override.
			// OpenSSL functions:  EVP_DecodeInit
		
		virtual int _CodedSize (int inSize);
			// Override.
			// OpenSSL functions:  EVP_DECODE_LENGTH
		
		virtual int _Update (unsigned char* outPtr, unsigned char* inPtr, int inSize);
			// Override.
			// OpenSSL functions:  EVP_DecodeUpdate
		
		virtual int _Final (unsigned char* outPtr);
			// Override.
			// OpenSSL functions:  EVP_DecodeFinal
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif

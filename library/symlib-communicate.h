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
#		Created:					27 Aug 2003
#		Last Modified:				21 Jul 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_COMMUNICATE)
#define SYMLIB_COMMUNICATE

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-utils.h"

#include "symlib-ssl-tls.h"
#include "symlib-tcp.h"
#include "symlib-threads.h"

#include <deque>
#include <queue>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef	std::queue<std::string>						ServerCommandQueue;

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TServerObj;

//---------------------------------------------------------------------
// Class TServerObj
//---------------------------------------------------------------------
class TServerObj : public TTCPConnectionObj
{
	private:
		
		typedef		TTCPConnectionObj			Inherited;
	
	public:
		
		TServerObj ();
			// Constructor
	
	private:
		
		TServerObj (const TServerObj& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TServerObj ();
			// Destructor
		
		virtual TServerObj* New () const;
			// Override
		
		virtual void Connect ();
			// Opens a secured connection with the server defined in
			// the local configuration file.
		
		virtual void Disconnect (bool hardDisconnect = false);
			// Disconnects an open connection with the server.  If hardDisconnect is
			// true then the connection is simply slammed down.
		
		virtual bool Send (const std::string& stuffToSend, CompressionMode compressionMode = kCompressionModeUnspecified);
			// Sends the concatenation of the internal send buffer and
			// the argument to the server.
		
		virtual std::string Receive ();
			// Reads data from the server.  Note that this is an intentional override
			// of the parent class' method; the parent wants an end-of-transmission
			// pattern or character, which we won't use here.
		
		virtual bool HaveServerCommands ();
			// Returns true if there are any pending server commands.
		
		virtual std::string GetServerCommand ();
			// Returns the least-recent server command.  Will return an empty string
			// if no commands are in the queue.
		
		virtual void SaveServerCommand (const std::string& serverCommand);
			// Puts the server command on the queue.
		
		// ----------------------------------
		// Accessors
		// ----------------------------------
		
		inline TPthreadMutexObj& IOLock ()
			{ return fIOLock; }
		
		inline bool IsInitialized () const
			{ return !fHost.empty(); }
		
		inline TDirObj CertificateDirectory () const
			{ return fCertDirObj; }
		
		inline std::string HostName () const
			{ return fHost; }
		
		inline unsigned long HostAddress () const
			{ return fHostAddress; }
		
		inline unsigned int HostPort () const
			{ return fHostPort; }
		
		inline std::string MyMACAddress () const
			{ return fMACAddress; }
		
		inline bool IsConnected () const
			{ return (Inherited::IsConnected() && fSSLConnection.IsConnected()); }
		
		inline std::string LineDelimiter () const
			{ return fLineDelimiter; }
		
		inline std::string SectionDelimiter () const
			{ return fSectionDelimiter; }
		
		inline CompressionMode GetCompressionMode () const
			{ return fCompressionMode; }
		
		inline void SetCompressionMode (CompressionMode newMode)
			{ fCompressionMode = newMode; }
	
	protected:
		
		virtual void _Initialize ();
			// Initializes our internal slots from the environment,
			// mostly the local preferences file.
		
		virtual bool _Send (const std::string& stuffToSend, CompressionMode compressionMode);
			// Sends the concatenation of the internal send buffer and
			// the argument to the server.
		
		virtual std::string _Receive ();
			// Reads data from the server and returns it in a temporary buffer object.
		
		virtual void _LogCommunication (const std::string& data, const std::string prompt) const;
			// Debugging method that writes communication to the current log file.
	
	protected:
		
		TPthreadMutexObj						fIOLock;
		TPthreadMutexObj						fServerCommandQueueLock;
		std::string								fAgentID;
		std::string								fMACAddress;
		TDirObj									fCertDirObj;
		TFileObj								fCACertFileObj;
		TFileObj								fAgentCertFileObj;
		std::string								fHost;
		std::string								fServerPath;
		unsigned long							fHostAddress;
		unsigned int							fHostPort;
		unsigned int							fHostSSLPort;
		TSSLContext								fSSLContext;
		TSSLConnection							fSSLConnection;
		std::string								fLineDelimiter;
		std::string								fSectionDelimiter;
		ServerCommandQueue						fServerCommandQueue;
		CompressionMode							fCompressionMode;
};

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

#endif // SYMLIB_COMMUNICATE

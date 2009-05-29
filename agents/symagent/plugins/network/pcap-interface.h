/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Plugin to report network activity in realtime
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					05 Nov 2003
#		Last Modified:				14 Jan 2004
#		
#######################################################################
*/

#if !defined(PCAP_INTERFACE)
#define PCAP_INTERFACE

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"

#include "pcap.h"

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TPCAPObj;
class TCapturedPacket;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define		kErrorPCAPLibraryError						-24501
#define		kErrorPCAPInterfaceNotOpen					-24502
#define		kErrorExternalPacketListNotProvided			-24503

#define		kPacketBufferRingSize						5000

struct PCAPNetworkInfo
{
	bpf_u_int32				netNumber;
	bpf_u_int32				netMask;
	PCAPNetworkInfo() : netNumber(0),netMask(0) {}
};

typedef	vector<TCapturedPacket>				RawPacketList;
typedef RawPacketList::iterator				RawPacketList_iter;
typedef RawPacketList::const_iterator		RawPacketList_const_iter;

//---------------------------------------------------------------------
// Class TCapturedPacket
//---------------------------------------------------------------------
class TCapturedPacket
{
	public:
		
		TCapturedPacket ();
			// Constructor
		
		TCapturedPacket (const TCapturedPacket& obj);
			// Copy constructor
		
		~TCapturedPacket ();
			// Destructor
		
		void Set (const struct pcap_pkthdr* headerPtr, const u_char* dataPtr);
			// Copies the arguments to the internal store.
		
		void Clear ();
			// Clears the internal store.
		
		// ------------------------------
		// Accessors
		// ------------------------------
		
		inline bpf_u_int32 CapturedSize () const
			{ return fHeader.caplen; }
		
		inline bpf_u_int32 ActualSize () const
			{ return fHeader.len; }
		
		inline struct timeval Timestamp () const
			{ return fHeader.ts; }
		
		inline u_char* Data () const
			{ return fData; }
	
	private:
		
		struct pcap_pkthdr					fHeader;
		u_char*								fData;
};

//---------------------------------------------------------------------
// Class TPCAPObj
//---------------------------------------------------------------------
class TPCAPObj
{
	protected:
		
		typedef	char						PCAPErrBuffer[PCAP_ERRBUF_SIZE];
	
	public:
		
		TPCAPObj ();
			// Constructor
	
	private:
		
		TPCAPObj (const TPCAPObj& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TPCAPObj ();
			// Destructor
		
		virtual void OpenInterface (const string& device, bool promiscuous = false);
			// Opens an interface to the PCAP library to the device indicated
			// by the first argument.  Under some operating systems, the device
			// may be 'any' to capture network packets from any suitable interface.
			// The promiscuous argument, if true, puts the network interface into
			// promiscuous mode (if supported).
		
		virtual void CloseInterface ();
			// Closes the interface to the PCAP library.
		
		virtual void SetFilter (const string& filterCommand, bool optimize = true);
			// Sets the packet capture filter for the currently-open interface.
			// An exception will be thrown if the interface is not open.
		
		virtual unsigned long CaptureNPackets (unsigned long packetCount = 1);
			// Captures the number of packets indicated by the argument on the
			// currently-open interface.  An exception will be thrown if the
			// interface is not open.  Returns the number of packets actually
			// captured.
		
		virtual unsigned long CapturePackets (unsigned long durationInSeconds,
											  bool allowRingOverfill = true);
			// Like CaptureNPackets() except this function captures packets until
			// durationInSeconds seconds of elapsed.  Note that this is the
			// minimum amount of time that the function will wait; the actual time
			// may be greater while the function waits for that last packet to
			// arrive....  Also, if allowRingOverfill is true then the method will
			// continue to capture packets until at least durationInSeconds has
			// passed, even if it means overwriting previously-captured packets.
			// If allowRingOverfill is false then the method will always return
			// before overwriting packets.
		
		virtual unsigned long CapturePackets (unsigned long durationInSeconds,
											  RawPacketList* externalPacketList);
			// Just like the previous versin of CapturePackets except that
			// the raw packets are stored in the packet list pointed to by the
			// externalPacketList argument.  This version will not overflow the
			// packet ring.
		
		virtual unsigned long GetCapturedPackets (RawPacketList& packetList, bool clearPacketRing = false);
			// Destructively modifies the argument to contain raw captured packets.
			// If the number of packets is smaller then the ring size then all
			// packets will be returned.  Otherwise, only the last n packets
			// (where n is the ring size) will be returned.  The order is always
			// least-recent to most-recent.  Returns the number of packets.
		
		virtual void ClearPacketRing ();
			// Resets our internal statistics so subsequent packet captures can
			// start fresh.
		
		virtual int FileDescriptor () const;
			// Returns the file descriptor associated with the currently-open
			// interface.  An exception will be thrown if the interface is not open.
		
		virtual int DataLinkType () const;
			// Returns the data link type code for the currently-open interface.
			// An exception will be thrown if the interface is not open.
		
		virtual struct pcap_stat CurrentStats () const;
			// Returns packet statistics on the currently-open interface, if
			// statistics are supported.  An exception will be thrown if the
			// interface is not open.
		
		// ------------------------------
		// Accessors
		// ------------------------------
		
		inline string CurrentDevice () const
			{ return fDevice; }
		
		inline unsigned long MaxCaptureSize () const
			{ return fCaptureSize; }
		
		inline void SetMaxCaptureSize (unsigned long sizeInBytes)
			{ fCaptureSize = std::min(static_cast<unsigned long>(BUFSIZ),sizeInBytes); }
		
		inline bool IsInterfaceOpen () const
			{ return (fPCAPHandle != NULL); }
		
		inline bool IsCapturing () const
			{ return fIsCapturing; }
		
		inline pcap_t* PCAPHandle () const
			{ return fPCAPHandle; }
		
		inline unsigned long PacketsCapturedCount () const
			{ return fPacketsCapturedCount; }
		
		inline unsigned long AvailablePacketCount () const
			{ return std::min(fPacketsCapturedCount,static_cast<unsigned long>(fRawPacketRing.size())); }
		
		// ------------------------------
		// Static methods
		// ------------------------------
		
		static unsigned long GetInterfaceList (StdStringList& interfaceList);
			// Examines the local system and finds network interfaces.
			// Destructively modifies the argument to contain a list of
			// those interfaces.  Returns the number of interfaces found.
		
		static string LookupDevice ();
			// Returns a string describing a network device suitable for
			// for analysis.
		
		static PCAPNetworkInfo LookupNetworkInfo (const string& device);
			// Given a network device name (as if found by either GetInterfaceList()
			// or LookupDevice()), returns a PCAPNetworkInfo structure
			// containing the network number and mask associated with
			// the device.
		
		static string DataLinkDescription (int dataLinkType);
			// Given a data link type code (as from DataLinkType()) this method
			// returns a corresponding description.
	
	protected:
		
		virtual void _HandlePacket (const struct pcap_pkthdr* header, const u_char* packet);
			// Processes an incoming network packet.
		
		static void _DispatchCallback (u_char* args, const struct pcap_pkthdr* header, const u_char* packet);
			// Callback function used by PCAP.  This version interprets the args
			// value as a pointer to the 'owning' TPCAPObj for the original call then
			// calls that object's _HandlePacket() method with the rest of the arguments.
	
	protected:
		
		pcap_t*											fPCAPHandle;
		string											fDevice;
		unsigned long									fCaptureSize;
		RawPacketList									fRawPacketRing;
		unsigned long									fRawPacketRingNextPos;
		unsigned long									fPacketsCapturedCount;
		RawPacketList*									fExternalPacketRing;
		int												fFileDescriptor;
		bool											fIsCapturing;
};

//---------------------------------------------------------------------
#endif // PCAP_INTERFACE

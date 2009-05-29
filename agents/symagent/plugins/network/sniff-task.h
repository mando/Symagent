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
#		Created:					10 Nov 2003
#		Last Modified:				22 Mar 2004
#		
#######################################################################
*/

#if !defined(SNIFF_TASK)
#define SNIFF_TASK

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"
#include "plugin-utils.h"
#include "packet-objs.h"
#include "pcap-interface.h"

//---------------------------------------------------------------------
// Import namespace symbols
//---------------------------------------------------------------------
using symbiot::TTaskBase;
using symbiot::TServerMessage;
using symbiot::TMessageNode;

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TSniffTask;
class TSendInfoTask;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define	kDefaultExecutionInterval					10

typedef		enum	{
						kReportingModeNormal = 0,
						kReportingModeSummary
					}	ReportingMode;

typedef		vector<TSniffTask*>						SniffTaskPtrList;
typedef		SniffTaskPtrList::iterator				SniffTaskPtrList_iter;
typedef		SniffTaskPtrList::const_iterator		SniffTaskPtrList_const_iter;

//---------------------------------------------------------------------
// Class TSniffTask
//---------------------------------------------------------------------
class TSniffTask : public TTaskBase
{
	private:
		
		typedef	TTaskBase							Inherited;
	
	public:
		
		TSniffTask (time_t intervalInSeconds = kDefaultExecutionInterval,
					bool rerun = false);
			// Constructor
	
	private:
		
		TSniffTask (const TSniffTask& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TSniffTask ();
			// Destructor
		
		virtual void SetupTask (std::string deviceName,
								bool promiscuous = true,
								time_t captureDuration = 0,
								const std::string& programFilter = "",
								unsigned long packetCaptureSize = 96);
		
		virtual void RunTask ();
			// Thread entry point for the task.  Really just wraps Main().
		
		virtual void Main ();
			// Entry point for the task.
		
		// ------------------------------
		// Accessors
		// ------------------------------
		
		inline TPCAPObj* PCAPObjPtr ()
			{ return &fPCAPObj; }
		
		inline time_t CaptureDuration () const
			{ return fCaptureDuration; }
		
		inline void SetCaptureDuration (time_t duration)
			{ fCaptureDuration = duration; }
		
		inline ReportingMode GetReportingMode () const
			{ return fReportingMode; }
		
		inline void SetReportingMode (ReportingMode reportingMode)
			{ fReportingMode = reportingMode; }
		
		inline unsigned long PacketsCaptured () const
			{ return fPacketsCaptured; }
		
		inline bool IsBusy () const
			{ return fPCAPObj.IsCapturing(); }
		
		inline void IncrementTaskCount ()
			{
				TLockedPthreadMutexObj	lock(fTaskCountLock);
				
				++fSendInfoTaskCount;
			}
		
		inline void DecrementTaskCount ()
			{
				TLockedPthreadMutexObj	lock(fTaskCountLock);
				
				--fSendInfoTaskCount;
			}
		
		inline void ResetParentThreadEnviron (ModEnviron* parentEnvironPtr)
			{ fParentEnvironPtr = parentEnvironPtr; }
	
	protected:
		
		TPCAPObj								fPCAPObj;
		time_t									fCaptureDuration;
		unsigned long							fPacketsCaptured;
		ReportingMode							fReportingMode;
		ModEnviron*								fParentEnvironPtr;
	
	private:
		
		TPthreadMutexObj						fTaskCountLock;
		unsigned long							fSendInfoTaskCount;
};

//---------------------------------------------------------------------
// Class TSendInfoTask
//---------------------------------------------------------------------
class TSendInfoTask : public TTaskBase
{
	private:
		
		typedef	TTaskBase						Inherited;
	
	public:
		
		TSendInfoTask (ReportingMode reportingMode,
					   const string& deviceName,
					   TSniffTask* parentSniffTaskPtr);
			// Constructor
	
	private:
		
		TSendInfoTask (const TSendInfoTask& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TSendInfoTask ();
			// Destructor
		
		virtual void RunTask ();
			// Thread entry point for the task.  Really just wraps Main().
		
		virtual unsigned long CreateTrafficeMessage (TServerMessage& parentMessage);
			// еее
	
	protected:
		
		virtual unsigned long _NormalTrafficeMessage (TServerMessage& parentMessage);
			// еее
		
		virtual unsigned long _SummaryTrafficeMessage (TServerMessage& parentMessage);
			// еее
		
		static string _LookupServiceName (const string& protocol, unsigned int srcPort, unsigned int destPort);
			// Given the source and destination ports of a communication,
			// this method returns the well-known service name for that
			// type of connection.
	
	public:
		
		RawPacketList							fRawPacketList;
	
	protected:
		
		ReportingMode							fReportingMode;
		string									fDeviceName;
		ModEnviron*								fParentEnvironPtr;
		TSniffTask*								fParentSniffTaskPtr;
};

#endif // SNIFF_TASK

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
#		Created:					27 Oct 2003
#		Last Modified:				11 Dec 2003
#		
#######################################################################
*/

#if !defined(SYMLIB_TIME)
#define SYMLIB_TIME

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-config.h"

#include "symlib-defs.h"
#include "symlib-exception.h"

#if TIME_WITH_SYS_TIME
	#include <sys/time.h>
	#include <ctime>
#elif HAVE_SYS_TIME_H
	#include <sys/time.h>
#else
	#include <ctime>
#endif

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
class TTimeObj;

//---------------------------------------------------------------------
// Class TTimeObj
//---------------------------------------------------------------------
class TTimeObj
{
	public:
		TTimeObj ();
			// Constructor
		
		TTimeObj (const TTimeObj& obj);
			// Constructor
		
		TTimeObj (const struct tm* timeStructPtr);
			// Constructor
		
		TTimeObj (time_t unixSeconds);
			// Constructor
		
		virtual ~TTimeObj ();
			// Destructor
		
		virtual void Clear ();
			// Resets the internal slots.
		
		virtual void SetNow ();
			// Sets the internal date/time information to right now.
		
		virtual void SetDateTime ();
			// Sets the internal date/time information to right now.
		
		virtual void SetDateTime (const TTimeObj& timeObj);
			// Sets the internal date/time information.
		
		virtual void SetDateTime (const struct tm* timeStructPtr);
			// Sets the internal date/time information.
		
		virtual void SetDateTime (time_t unixSeconds);
			// Sets the internal date/time information.
		
		virtual void SetDateTimeFromString (const std::string& dateTime, const std::string& format);
			// Sets the internal date information based on the textual
			// representation given by dateTime, formatted according to the
			// format argument.  Uses the strptime() function; see that function's
			// man page for details.
		
		virtual void ZeroTimePart ();
			// Resets the time portion of the internal date information
			// to midnight.
		
		virtual void AdjustDate (int dayDelta, int monthDelta, int yearDelta);
			// Adjusts the date portion of the current value by the
			// indicated arguments.
		
		virtual void AdjustTime (int hourDelta, int minuteDelta, int secondDelta);
			// Adjusts the time portion of the current value by the
			// indicated arguments.
		
		virtual struct tm* GetTimeStruct ();
			// Returns a pointer to the time structure stored within
			// this object.
		
		virtual time_t GetUnixSeconds () const;
			// Returns the time information currently stored in the
			// object in Unix seconds format.
		
		virtual std::string GetFormattedDateTime (const std::string& formatString) const;
			// Method returns a string version of the current object value
			// formatted through strftime().  The argument is passed through
			// to strftime() and used to determine the final format.  Up to
			// 256 characters will be returned.
		
		// Read Accessors
		inline int Month () const
			{return (fTimeInfo.tm_year ? fTimeInfo.tm_mon + 1 : 0);}
		inline int Day () const
			{return fTimeInfo.tm_mday;}
		inline int Year () const
			{return fTimeInfo.tm_year + 1900;}
		inline int Hour () const
			{return fTimeInfo.tm_hour;}
		inline int Minute () const
			{return fTimeInfo.tm_min;}
		inline int Second () const
			{return fTimeInfo.tm_sec;}
		inline bool DaylightSavingsTime () const
			{return (fTimeInfo.tm_isdst > 0);}
		
		// Write Accessors
		inline void SetMonth (int month)
			{fTimeInfo.tm_mon = month - 1;}
		inline void SetDay (int day)
			{fTimeInfo.tm_mday = day;}
		inline void SetYear (int year)
			{fTimeInfo.tm_year = year - 1900;}
		inline void SetHour (int hour)
			{fTimeInfo.tm_hour = hour;}
		inline void SetMinute (int minute)
			{fTimeInfo.tm_min = minute;}
		inline void SetSecond (int second)
			{fTimeInfo.tm_sec = second;}
		inline void SetDaylightSavingsTime (bool isDST)
			{fTimeInfo.tm_isdst = (isDST ? 1 : 0);}
		
		// Comparison Operators
		inline bool operator== (const TTimeObj& timeObj) const
			{return GetUnixSeconds() == timeObj.GetUnixSeconds();}
		inline bool operator== (time_t unixSeconds) const
			{return GetUnixSeconds() == unixSeconds;}
		inline bool operator== (struct tm* timeStructPtr) const
			{return GetUnixSeconds() == mktime(timeStructPtr);}
		
		inline bool operator< (const TTimeObj& timeObj) const
			{return GetUnixSeconds() < timeObj.GetUnixSeconds();}
		inline bool operator< (time_t unixSeconds) const
			{return GetUnixSeconds() < unixSeconds;}
		inline bool operator< (struct tm* timeStructPtr) const
			{return GetUnixSeconds() < mktime(timeStructPtr);}
		
		template <class T>
		inline bool operator!= (T& value)
			{return !(*this == value);}
		
		template <class T>
		inline bool operator<= (T& value)
			{return (*this < value) || (*this == value);}
		
		template <class T>
		inline bool operator> (T& value)
			{return !(*this <= value);}
		
		template <class T>
		inline bool operator>= (T& value)
			{return !(*this < value);}
		
		// Arithmetic Operators
		inline TTimeObj operator+ (const TTimeObj& timeObj) const
			{return TTimeObj(GetUnixSeconds() + timeObj.GetUnixSeconds());}
		inline TTimeObj operator+ (time_t unixSeconds) const
			{return TTimeObj(GetUnixSeconds() + unixSeconds);}
		inline TTimeObj operator+ (struct tm* timeStructPtr) const
			{return TTimeObj(GetUnixSeconds() + mktime(timeStructPtr));}
		
		inline TTimeObj operator- (const TTimeObj& timeObj) const
			{return TTimeObj(GetUnixSeconds() - timeObj.GetUnixSeconds());}
		inline TTimeObj operator- (time_t unixSeconds) const
			{return TTimeObj(GetUnixSeconds() - unixSeconds);}
		inline TTimeObj operator- (struct tm* timeStructPtr) const
			{return TTimeObj(GetUnixSeconds() - mktime(timeStructPtr));}
		
		// Assignment Operators
		inline TTimeObj& operator= (const TTimeObj& timeObj)
			{SetDateTime(timeObj); return *this;}
		inline TTimeObj& operator= (time_t seconds)
			{SetDateTime(seconds); return *this;}
		inline TTimeObj& operator= (const struct tm* timeStructPtr)
			{SetDateTime(timeStructPtr); return *this;}
		
		inline TTimeObj& operator+= (const TTimeObj& timeObj)
			{SetDateTime(GetUnixSeconds() + timeObj.GetUnixSeconds()); return *this;}
		inline TTimeObj& operator+= (time_t seconds)
			{SetDateTime(GetUnixSeconds() + seconds); return *this;}
		inline TTimeObj& operator+= (struct tm* timeStructPtr)
			{SetDateTime(GetUnixSeconds() + mktime(timeStructPtr)); return *this;}
		
		inline TTimeObj& operator-= (const TTimeObj& timeObj)
			{SetDateTime(GetUnixSeconds() - timeObj.GetUnixSeconds()); return *this;}
		inline TTimeObj& operator-= (time_t seconds)
			{SetDateTime(GetUnixSeconds() - seconds); return *this;}
		inline TTimeObj& operator-= (struct tm* timeStructPtr)
			{SetDateTime(GetUnixSeconds() - mktime(timeStructPtr)); return *this;}
		
		// Casting operators
		inline operator struct tm* ()
			{return &fTimeInfo;}
		inline operator const struct tm* () const
			{return &fTimeInfo;}
	
	protected:
		
		struct tm								fTimeInfo;
};

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

unsigned long MinutesWestOfGMT ();
	// Returns the number of minutes west of GMT the local time zone is.

double CurrentMilliseconds (int precision = -1);
	// The current time in millisecond accuracy, to the given level of
	// decimal precision (a -1 indicates full precision).

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif // SYMLIB_TIME

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

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-time.h"

#include <cmath>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TTimeObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TTimeObj::TTimeObj ()
{
	Clear();
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TTimeObj::TTimeObj (const TTimeObj& obj)
	:	fTimeInfo(obj.fTimeInfo)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TTimeObj::TTimeObj (const struct tm* timeStructPtr)
{
	SetDateTime(timeStructPtr);
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TTimeObj::TTimeObj (time_t unixSeconds)
{
	SetDateTime(unixSeconds);
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TTimeObj::~TTimeObj ()
{
}

//---------------------------------------------------------------------
// TTimeObj::Clear
//---------------------------------------------------------------------
void TTimeObj::Clear ()
{
	memset(&fTimeInfo,0,sizeof(fTimeInfo));
}

//---------------------------------------------------------------------
// TTimeObj::SetNow
//---------------------------------------------------------------------
void TTimeObj::SetNow ()
{
	SetDateTime(time(NULL));
}

//---------------------------------------------------------------------
// TTimeObj::SetDateTime
//---------------------------------------------------------------------
void TTimeObj::SetDateTime ()
{
	SetNow();
}

//---------------------------------------------------------------------
// TTimeObj::SetDateTime
//---------------------------------------------------------------------
void TTimeObj::SetDateTime (const TTimeObj& timeObj)
{
	fTimeInfo = timeObj.fTimeInfo;
}

//---------------------------------------------------------------------
// TTimeObj::SetDateTime
//---------------------------------------------------------------------
void TTimeObj::SetDateTime (const struct tm* timeStructPtr)
{
	if (timeStructPtr)
	{
		memcpy(&fTimeInfo,timeStructPtr,sizeof(fTimeInfo));
		mktime(&fTimeInfo);
	}
	else
		Clear();
}

//---------------------------------------------------------------------
// TTimeObj::SetDateTime
//---------------------------------------------------------------------
void TTimeObj::SetDateTime (time_t unixSeconds)
{
	#if defined(_PTHREADS) && HAVE_LOCALTIME_R
		localtime_r(&unixSeconds,&fTimeInfo);
	#else
		memcpy(&fTimeInfo,localtime(&unixSeconds),sizeof(fTimeInfo));
	#endif
}

//---------------------------------------------------------------------
// TTimeObj::SetDateTimeFromString
//---------------------------------------------------------------------
void TTimeObj::SetDateTimeFromString (const std::string& dateTime, const std::string& format)
{
	// Reset time structure
	Clear();
	
	if (!dateTime.empty() && !format.empty())
		strptime(dateTime.c_str(),format.c_str(),&fTimeInfo);
}

//---------------------------------------------------------------------
// TTimeObj::ZeroTimePart
//---------------------------------------------------------------------
void TTimeObj::ZeroTimePart ()
{
	fTimeInfo.tm_hour = 0;
	fTimeInfo.tm_min = 0;
	fTimeInfo.tm_sec = 0;
}

//---------------------------------------------------------------------
// TTimeObj::AdjustDate
//---------------------------------------------------------------------
void TTimeObj::AdjustDate (int dayDelta, int monthDelta, int yearDelta)
{
	fTimeInfo.tm_mday += dayDelta;
	fTimeInfo.tm_mon += monthDelta;
	fTimeInfo.tm_year += yearDelta;
	
	mktime(&fTimeInfo);
}

//---------------------------------------------------------------------
// TTimeObj::AdjustTime
//---------------------------------------------------------------------
void TTimeObj::AdjustTime (int hourDelta, int minuteDelta, int secondDelta)
{
	fTimeInfo.tm_hour += hourDelta;
	fTimeInfo.tm_min += minuteDelta;
	fTimeInfo.tm_sec += secondDelta;
	
	mktime(&fTimeInfo);
}

//---------------------------------------------------------------------
// TTimeObj::GetTimeStruct
//---------------------------------------------------------------------
struct tm* TTimeObj::GetTimeStruct ()
{
	mktime(&fTimeInfo);
	
	return &fTimeInfo;
}

//---------------------------------------------------------------------
// TTimeObj::GetUnixSeconds
//---------------------------------------------------------------------
time_t TTimeObj::GetUnixSeconds () const
{
	struct tm	timeInfoCopy(fTimeInfo);
	
	return mktime(&timeInfoCopy);
}

//---------------------------------------------------------------------
// TTimeObj::GetFormattedDateTime
//---------------------------------------------------------------------
std::string TTimeObj::GetFormattedDateTime (const std::string& formatString) const
{
	std::string		formattedTime;
	const int		kBufferSize = 256;
	char			tempBuffer[kBufferSize];
	
	strftime(tempBuffer,kBufferSize-1,formatString.c_str(),&fTimeInfo);
	formattedTime = tempBuffer;
	
	return formattedTime;
}

//*********************************************************************
// Global Functions
//*********************************************************************

//---------------------------------------------------------------------
// MinutesWestOfGMT
//---------------------------------------------------------------------
unsigned long MinutesWestOfGMT ()
{
	unsigned long		minutesWest = 0;
	struct timeval		tv;
	struct timezone		tz;
	
	if (gettimeofday(&tv,&tz) == 0)
		minutesWest = tz.tz_minuteswest;
	
	return minutesWest;
}

//---------------------------------------------------------------------
// CurrentMilliseconds
//---------------------------------------------------------------------
double CurrentMilliseconds (int precision)
{
	struct timeval	timeNow;
	double			millisecondTime;
	
	gettimeofday(&timeNow,NULL);
	
	millisecondTime = timeNow.tv_usec;
	millisecondTime /= 1000000;
	millisecondTime += timeNow.tv_sec;
	
	if (precision > -1)
	{
		double		newNum = millisecondTime;
		double		factor = 0.0;
		bool		isNegative = false;
		
		// First, create the factor
		if (precision > 0)
		{
			factor = 10.0;
			for (int x = 1; x < precision; x++)
				factor *= 10.0;
		}
		
		// Check for negative
		if (newNum < 0)
		{
			newNum *= -1.0;
			isNegative = true;
		}
		
		// Now actually perform the rounding
		newNum = (floor((newNum * factor) + 0.5) / factor);
		
		// Reinstate the sign if necessary
		if (isNegative)
			newNum *= -1.0;
		
		millisecondTime = newNum;
	}
	
	return millisecondTime;
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

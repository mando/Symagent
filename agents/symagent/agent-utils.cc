/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		UberAgent file
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					18 Dec 2003
#		Last Modified:				17 Aug 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "agent-utils.h"

#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

#if HAVE_SYSINFO && HAVE_SYS_SYSINFO_H
	#define kLoadAvgViaSysinfo 1
	#include <sys/sysinfo.h>
#elif HAVE_GETLOADAVG
	#define kLoadAvgViaLoadAvg 1
#endif

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
static	AgentRunState							gRunState = kRunStateRun;

//---------------------------------------------------------------------
// DoMainEventLoop
//---------------------------------------------------------------------
bool DoMainEventLoop ()
{
	return (gRunState == kRunStateRun);
}

//---------------------------------------------------------------------
// CurrentRunState
//---------------------------------------------------------------------
AgentRunState CurrentRunState ()
{
	return gRunState;
}

//---------------------------------------------------------------------
// SetRunState
//---------------------------------------------------------------------
void SetRunState (AgentRunState newRunState)
{
	gRunState = newRunState;
}

//---------------------------------------------------------------------
// StringToNumber
//---------------------------------------------------------------------
double StringToNumber (const string& s)
{
	double				num = 0.0;
	std::istringstream	tempStringStream(s);
	
	tempStringStream >> num;
	
	return num;
}

//--------------------------------------------------------------------
// LogSignalAndReraise
//--------------------------------------------------------------------
void LogSignalAndReraise (int sigNum)
{
	string				logString;
	struct sigaction	mySigAction;
	
	logString += "Received signal " + NumberToString(sigNum);
	
	// If we're being killed try to shutdown the library
	switch (sigNum)
	{
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
		case SIGABRT:
			{
				if (!IsTask())
				{
					WriteToMessagesLog(logString);
					gRunState = kRunStateTerminate;
					
					#if !defined(SA_RESTART)
						// Reset the signal handler
						SetSignalHandlers(sigNum);
					#endif
				}
			}
			break;
		
		case SIGHUP:
			{
				if (!IsTask())
					WriteToMessagesLog(logString);
				gRunState = kRunStateStop;
				
				#if !defined(SA_RESTART)
					// Reset the signal handler
					SetSignalHandlers(sigNum);
				#endif
			}
			break;
		
		default:
			{
				// Log the signal
				WriteToErrorLog(logString);
				
				// Ensure that the signal is now set to its default action
				mySigAction.sa_handler = SIG_DFL;
				mySigAction.sa_flags = 0;
				sigemptyset(&mySigAction.sa_mask);
				sigaction(sigNum,&mySigAction,NULL);
				
				// Re-raise the signal
				raise(sigNum);
			}
			break;
	}
}

//--------------------------------------------------------------------
// SetSignalHandlers
//--------------------------------------------------------------------
void SetSignalHandlers (int oneSigNum)
{
	struct sigaction		mySigAction;
	
	mySigAction.sa_handler = LogSignalAndReraise;
	mySigAction.sa_flags = 0;
	
	#if defined(SA_RESTART)
		mySigAction.sa_flags |= SA_RESTART;
	#endif
	#if defined(SA_INTERRUPT)
		mySigAction.sa_flags &= ~(SA_INTERRUPT);
	#endif

	sigemptyset(&mySigAction.sa_mask);
	
	if (oneSigNum == 0 || oneSigNum == SIGHUP)
		sigaction(SIGHUP,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGINT)
		sigaction(SIGINT,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGQUIT)
		sigaction(SIGQUIT,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGILL)
		sigaction(SIGILL,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGTRAP)
		sigaction(SIGTRAP,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGABRT)
		sigaction(SIGABRT,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGFPE)
		sigaction(SIGFPE,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGKILL)
		sigaction(SIGKILL,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGTERM)
		sigaction(SIGTERM,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGWINCH)
		sigaction(SIGWINCH,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGURG)
		sigaction(SIGURG,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGTSTP)
		sigaction(SIGTSTP,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGTTIN)
		sigaction(SIGTTIN,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGTTOU)
		sigaction(SIGTTOU,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGVTALRM)
		sigaction(SIGVTALRM,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGPROF)
		sigaction(SIGPROF,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGXCPU)
		sigaction(SIGXCPU,&mySigAction,NULL);
	if (oneSigNum == 0 || oneSigNum == SIGXFSZ)
		sigaction(SIGXFSZ,&mySigAction,NULL);
	
	signal(SIGPIPE,SIG_IGN);
}

//---------------------------------------------------------------------
// GetLoadInformation
//---------------------------------------------------------------------
void GetLoadInformation (double& oneMin, double& fiveMin, double& fifteenMin)
{
	// Initialize the outbound arguments
	oneMin = 0.0;
	fiveMin = 0.0;
	fifteenMin = 0.0;
	
	#if defined(kLoadAvgViaSysinfo)
		struct sysinfo			systemInfo;
		
		if (sysinfo(&systemInfo) != 0)
			throw TSymLibErrorObj(errno,"While calling sysinfo()");
		
		oneMin = static_cast<double>(systemInfo.loads[0]) / static_cast<double>(1<<SI_LOAD_SHIFT);
		fiveMin = static_cast<double>(systemInfo.loads[1]) / static_cast<double>(1<<SI_LOAD_SHIFT);
		fifteenMin = static_cast<double>(systemInfo.loads[2]) / static_cast<double>(1<<SI_LOAD_SHIFT);
	#elif defined(kLoadAvgViaLoadAvg)
		double					averages[3];
		
		if (getloadavg(averages,3) <= 0)
			throw TSymLibErrorObj(errno,"While calling getloadavg()");
		
		oneMin = averages[0];
		fiveMin = averages[1];
		fifteenMin = averages[2];
	#endif
}

//---------------------------------------------------------------------
// VerifyExactFilePerms
//---------------------------------------------------------------------
bool VerifyExactFilePerms (const string& filePath, mode_t exactPerms, uid_t ownerID)
{
	struct stat		fileInfo;
	mode_t			filePerm;
	
	// Get the file's stat info
	if (stat(filePath.c_str(),&fileInfo) < 0)
	{
		string		errString;
		
		errString = "Unable to stat file '" + filePath + "'";
		throw TSymLibErrorObj(errno,errString);
	}
	
	filePerm = fileInfo.st_mode & (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO);
	
	return ((filePerm == exactPerms) && (fileInfo.st_uid == ownerID));
}

//---------------------------------------------------------------------
// GetSystemLimit
//---------------------------------------------------------------------
int GetSystemLimit (RESOURCE_LIMIT_TYPE resource)
{
	int				value = 0;
	struct rlimit	sysLimits;
	
	if (getrlimit(resource,&sysLimits) == 0)
		value = sysLimits.rlim_cur;
	
	return value;
}

//---------------------------------------------------------------------
// MaxSystemLimit
//---------------------------------------------------------------------
void MaxSystemLimit (RESOURCE_LIMIT_TYPE resource)
{
	struct rlimit		sysLimits;
	
	if (getrlimit(resource,&sysLimits) == 0)
	{
		if (sysLimits.rlim_cur != sysLimits.rlim_max)
		{
			sysLimits.rlim_cur = sysLimits.rlim_max;
			setrlimit (resource,&sysLimits);
		}
	}
}

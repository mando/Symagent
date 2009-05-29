/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Agent to obtain system information from Linux
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					08 Dec 2003
#		Last Modified:				11 Jan 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "linux-proc.h"

#include "plugin-utils.h"

#include <sys/types.h>

#if HAVE_DIRENT_H
	#include <dirent.h>
	#define NAMLEN(dirent) strlen((dirent)->d_name)
#else
	#define dirent direct
	#define NAMLEN(dirent) (dirent)->d_namlen
	#if HAVE_SYS_NDIR_H
		#include <sys/ndir.h>
	#endif
	#if HAVE_SYS_DIR_H
		#include <sys/dir.h>
	#endif
	#if HAVE_NDIR_H
		#include <ndir.h>
	#endif
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <unistd.h>

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
static const unsigned long							kReadWriteBlockSize = 4096;

//*********************************************************************
// Class TInfoCollector
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TInfoCollector::TInfoCollector ()
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TInfoCollector::TInfoCollector (const TInfoCollector& obj)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TInfoCollector::~TInfoCollector ()
{
}

//---------------------------------------------------------------------
// TInfoCollector::Collect
//---------------------------------------------------------------------
void TInfoCollector::Collect (ProcessInfoMap& procInfoMap, NetworkConnectionMap& netConnMap)
{
	_GetNetworkConnections(netConnMap);
	_GetRunningProcessInfo(procInfoMap,netConnMap);
}

//---------------------------------------------------------------------
// TInfoCollector::_GetNetworkConnections (static protected)
//---------------------------------------------------------------------
void TInfoCollector::_GetNetworkConnections (NetworkConnectionMap& netConnMap)
{
	string			tempString;
	StdStringList	tempStringList;
	
	netConnMap.clear();
	
	// ----- TCP connection info ---------------
	
	_ReadWholeFile("/proc/net/tcp",tempString,false,false);
	SplitStdString('\n',tempString,tempStringList,false);
	if (!tempStringList.empty())
	{
		for (StdStringList_const_iter x = tempStringList.begin(); x != tempStringList.end(); x++)
		{
			if (x->length() > 90 && x->find("local_address") == string::npos)
			{
				NetworkConnection		connectInfo;
				string					inodeStr;
				int						inodeIndex = 0;
				int						inode = 0;
				
				// Each line is one connection
				connectInfo.protoID = IPPROTO_TCP;
				connectInfo.protoFamily = AF_INET;
				connectInfo.sourceAddr = _HexEthernetToIPv4Addr(x->substr(6,8));
				connectInfo.sourcePort = ntohs(_HexEthernetToUInt(x->substr(15,4)));
				connectInfo.destAddr = _HexEthernetToIPv4Addr(x->substr(20,8));
				connectInfo.destPort = ntohs(_HexEthernetToUInt(x->substr(29,4)));
				
				inodeIndex = 91;
				while (isdigit((*x)[inodeIndex]))
					inodeStr += (*x)[inodeIndex++];
				inode = static_cast<int>(StringToNum(inodeStr));
				
				netConnMap[inode] = connectInfo;
			}
		}
	}
	
	// ----- UDP connection info ---------------
	
	_ReadWholeFile("/proc/net/udp",tempString,false,false);
	SplitStdString('\n',tempString,tempStringList,false);
	if (!tempStringList.empty())
	{
		for (StdStringList_const_iter x = tempStringList.begin(); x != tempStringList.end(); x++)
		{
			if (x->length() > 90 && x->find("local_address") == string::npos)
			{
				NetworkConnection		connectInfo;
				string					inodeStr;
				int						inodeIndex = 0;
				int						inode = 0;
				
				// Each line is one connection
				connectInfo.protoID = IPPROTO_UDP;
				connectInfo.protoFamily = AF_INET;
				connectInfo.sourceAddr = _HexEthernetToIPv4Addr(x->substr(6,8));
				connectInfo.sourcePort = ntohs(_HexEthernetToUInt(x->substr(15,4)));
				connectInfo.destAddr = _HexEthernetToIPv4Addr(x->substr(20,8));
				connectInfo.destPort = ntohs(_HexEthernetToUInt(x->substr(29,4)));
				
				inodeIndex = 91;
				while (isdigit((*x)[inodeIndex]))
					inodeStr += (*x)[inodeIndex++];
				inode = static_cast<int>(StringToNum(inodeStr));
				
				netConnMap[inode] = connectInfo;
			}
		}
	}
	
	// ----- TCP6 connection info ---------------
	
	_ReadWholeFile("/proc/net/tcp6",tempString,false,false);
	SplitStdString('\n',tempString,tempStringList,false);
	if (!tempStringList.empty())
	{
		for (StdStringList_const_iter x = tempStringList.begin(); x != tempStringList.end(); x++)
		{
			if (x->length() > 90 && x->find("local_address") == string::npos)
			{
				NetworkConnection		connectInfo;
				string					inodeStr;
				int						inodeIndex = 0;
				int						inode = 0;
				
				// Each line is one connection
				connectInfo.protoID = IPPROTO_TCP;
				connectInfo.protoFamily = AF_INET6;
				connectInfo.sourceAddr = _HexEthernetToIPv6Addr(x->substr(6,32));
				connectInfo.sourcePort = ntohs(_HexEthernetToUInt(x->substr(39,4)));
				connectInfo.destAddr = _HexEthernetToIPv6Addr(x->substr(44,32));
				connectInfo.destPort = ntohs(_HexEthernetToUInt(x->substr(77,4)));
				
				inodeIndex = 139;
				while (isdigit((*x)[inodeIndex]))
					inodeStr += (*x)[inodeIndex++];
				inode = static_cast<int>(StringToNum(inodeStr));
				
				netConnMap[inode] = connectInfo;
			}
		}
	}
	
	// ----- UDP6 connection info ---------------
	
	_ReadWholeFile("/proc/net/udp6",tempString,false,false);
	SplitStdString('\n',tempString,tempStringList,false);
	if (!tempStringList.empty())
	{
		for (StdStringList_const_iter x = tempStringList.begin(); x != tempStringList.end(); x++)
		{
			if (x->length() > 90 && x->find("local_address") == string::npos)
			{
				NetworkConnection		connectInfo;
				string					inodeStr;
				int						inodeIndex = 0;
				int						inode = 0;
				
				// Each line is one connection
				connectInfo.protoID = IPPROTO_UDP;
				connectInfo.protoFamily = AF_INET6;
				connectInfo.sourceAddr = _HexEthernetToIPv6Addr(x->substr(6,32));
				connectInfo.sourcePort = ntohs(_HexEthernetToUInt(x->substr(39,4)));
				connectInfo.destAddr = _HexEthernetToIPv6Addr(x->substr(44,32));
				connectInfo.destPort = ntohs(_HexEthernetToUInt(x->substr(77,4)));
				
				inodeIndex = 91;
				while (isdigit((*x)[inodeIndex]))
					inodeStr += (*x)[inodeIndex++];
				inode = static_cast<int>(StringToNum(inodeStr));
				
				netConnMap[inode] = connectInfo;
			}
		}
	}
}

//---------------------------------------------------------------------
// TInfoCollector::_GetRunningProcessInfo (static protected)
//---------------------------------------------------------------------
void TInfoCollector::_GetRunningProcessInfo (ProcessInfoMap& procInfoMap, const NetworkConnectionMap& netConnMap)
{
	StdStringList		filenameList;
	
	procInfoMap.clear();
	
	// Get the subdirectories with names containing only numbers
	// (these are the process IDs of the running processes)
	_GetDirContents("/proc/",filenameList,false,false,true,true,"[0-9]*",true);
	
	for (StdStringList_const_iter x = filenameList.begin(); x != filenameList.end(); x++)
	{
		struct stat		statInfo;
		string			onePath;
		
		onePath = "/proc/" + *x;
		if (stat(onePath.c_str(),&statInfo) == 0)
		{
			ProcessInfo		procInfo;
			pid_t			procPID = static_cast<pid_t>(StringToNum(*x));
			StdStringList	netConnList;
			string			tempString;
			StdStringList	tempStringList;
			
			// Save the owner and group ID
			procInfo.ownerID = statInfo.st_uid;
			procInfo.groupID = statInfo.st_gid;
			
			// Get the real path of the process
			onePath = "/proc/" + *x + "/maps";
			_ReadWholeFile(onePath,tempString,false,false);
			SplitStdString('\n',tempString,tempStringList,false);
			if (!tempStringList.empty())
			{
				StdStringList	itemList;
				
				SplitStdString(' ',tempStringList.front(),itemList,false);
				if (!itemList.empty())
				{
					procInfo.path = itemList.back();
					if (procInfo.path == "(deleted)")
					{
						// The process is apparently not still on disk; try to find it's original name
						procInfo.path = "";
						if (itemList.size() > 1)
						{
							procInfo.path = itemList[itemList.size()-2];
						}
					}
					
					// Create the signature for that binary
					if (!procInfo.path.empty())
						procInfo.appSig = GetApplicationSignature(procInfo.path);
				}
			}
			
			if (procInfo.path.empty())
			{
				// We probably tried to read a zombie process or one that's completely
				// swapped out.  An alternative location for the name of the application
				// is in /proc/#/stat.  Note that we don't compute the signature, mainly
				// because we don't really know where the binary is.
				unsigned int	foundPos = 0;
				
				onePath = "/proc/" + *x + "/stat";
				_ReadWholeFile(onePath,tempString,false,false);
				foundPos = tempString.find("(");
				if (foundPos != string::npos)
				{
					procInfo.path = "[";
					++foundPos;
					while (foundPos < tempString.length())
					{
						if (tempString[foundPos] == ')')
						{
							procInfo.path += "]";
							break;
						}
						else
						{
							procInfo.path += tempString[foundPos];
							++foundPos;
						}
					}
				}
			}
			
			// Get the network connections
			onePath = "/proc/" + *x + "/fd/";
			_GetDirContents(onePath,netConnList,false,true,false,true,"",false);
			for (StdStringList_const_iter y = netConnList.begin(); y != netConnList.end(); y++)
			{
				unsigned int		foundPos = 0;
				
				onePath = "/proc/" + *x + "/fd/" + *y;
				_ReadSymbolicLink(onePath,tempString,false);
				foundPos = tempString.find("socket");
				if (foundPos != string::npos)
				{
					int		inode = 0;
					
					for (unsigned int i = foundPos; i < tempString.length(); i++)
					{
						if (isdigit(tempString[i]))
							inode = (inode * 10) + (tempString[i] - '0');
						else if (tempString[i] == ' ')
							break;
					}
					
					if (netConnMap.find(inode) != netConnMap.end())
					{
						if (find(procInfo.inodeList.begin(),procInfo.inodeList.end(),inode) == procInfo.inodeList.end())
							procInfo.inodeList.push_back(inode);
					}
				}
			}
			
			sort(procInfo.inodeList.begin(),procInfo.inodeList.end());
			
			procInfoMap[procPID] = procInfo;
		}
	}
}

//---------------------------------------------------------------------
// TInfoCollector::_GetDirContents (static protected)
//---------------------------------------------------------------------
void TInfoCollector::_GetDirContents (const string& dirPath,
										   StdStringList& filenameList,
										   bool includeInvisibles,
										   bool includeFiles,
										   bool includeDirs,
										   bool symLinksAsFiles,
										   const string& pattern,
										   bool throwOnError)
{
	struct dirent*		dirEntryPtr = NULL;
	struct dirent		dirEntry;
	DIR*				dirPtr = NULL;
	struct stat 		statInfo;
	string				fullPath;
	int					statResult;
	string				errString;
	
	filenameList.clear();
	
	dirPtr = opendir(dirPath.c_str());
	
	if (!dirPtr && throwOnError)
	{
		errString = "";
		errString += "While attempting to obtain contents of directory '" + dirPath + "'";
		throw TSymLibErrorObj(errno,errString);
	}
	
	if (dirPtr)
	{
		try
		{
			do
			{
				#if defined(_PTHREADS) && HAVE_READDIR_R
					// Use the reentrant version
					if (readdir_r(dirPtr,&dirEntry,&dirEntryPtr) != 0)
					{
						errString = "";
						errString += "While attempting to obtain contents of directory '" + dirPath + "'";
						throw TSymLibErrorObj(errno,errString);
					}
				#else
					dirEntryPtr = readdir(dirPtr);
					// Get a copy so other processes don't trip us up
					if (dirEntryPtr)
						memcpy(&dirEntry,dirEntryPtr,sizeof(dirEntry));
				#endif
				
				if (dirEntryPtr)
				{
					if (strcmp(dirEntry.d_name,".") != 0 & strcmp(dirEntry.d_name,"..") != 0)
					{
						if (dirEntry.d_name[0] != '.' || includeInvisibles)
						{
							// Check the file type to determine what the user wants
							fullPath = dirPath;
							fullPath += dirEntry.d_name;
							
							if (symLinksAsFiles)
								statResult = lstat(fullPath.c_str(),&statInfo);
							else
								statResult = stat(fullPath.c_str(),&statInfo);
							
							if (statResult == 0)
							{
								// Figure out what it is and if we want it
								bool includeThisFile = (includeFiles && S_ISREG(statInfo.st_mode));
								bool includeThisDir = (includeDirs && S_ISDIR(statInfo.st_mode));
								bool includeThisSymLink = (symLinksAsFiles && S_ISLNK(statInfo.st_mode) && includeFiles);
								
								if (includeThisFile || includeThisDir || includeThisSymLink)
								{
									// See if the entry's name passes the regular expression filter
									if (pattern.empty() || fnmatch(pattern.c_str(),dirEntry.d_name,FNM_PERIOD) == 0)
									{
										// Now we need to create the appropriate object pointer and push it
										if (includeThisFile || includeThisSymLink)
										{
											filenameList.push_back(dirEntry.d_name);
										}
										else if (includeThisDir)
										{
											filenameList.push_back(dirEntry.d_name);
										}
									}
								}
							}
						}
					}
				}
			}
			while (dirEntryPtr);
		}
		catch (...)
		{
			// Make sure the directory pointer is closed
			if (dirPtr)
				closedir(dirPtr);
			dirPtr = NULL;
			throw;
		}
	}
	
	// Make sure the directory pointer is closed
	if (dirPtr)
		closedir(dirPtr);
	dirPtr = NULL;
}

//---------------------------------------------------------------------
// TInfoCollector::_ReadWholeFile (static protected)
//---------------------------------------------------------------------
void TInfoCollector::_ReadWholeFile (const string& filePath,
										  string& bufferObj,
										  bool followSymLinks,
										  bool throwOnError)
{
	int		openFlags = O_RDONLY;
	int		fd = 0;
	
	if (!followSymLinks)
		openFlags |= O_NOFOLLOW;
	
	// Zero out the buffer argument
	bufferObj = "";
	
	fd = open(filePath.c_str(),openFlags);
	if (fd == -1 && throwOnError)
	{
		string		errString;
		
		errString = "While trying to open file '" + filePath + "'";
		throw TSymLibErrorObj(errno,errString);
	}
	
	if (fd != -1)
	{
		try
		{
			unsigned long		totalBytesRead = 0;
			unsigned long		maxFileSize = 8192;
			
			do
			{
				string		interimBuffer;
				char*		buffStartPtr = NULL;
				ssize_t		bytesRead = 0;
				
				interimBuffer.resize(kReadWriteBlockSize);
				buffStartPtr = const_cast<char*>(interimBuffer.data());
				bytesRead = read(fd,buffStartPtr,std::min(kReadWriteBlockSize,maxFileSize-totalBytesRead));
				if (bytesRead < 0)
				{
					string		errString;
					
					errString += "While attempting to read from file '" + filePath + "' with file descriptor ";
					errString += NumToString(fd);
					throw TSymLibErrorObj(errno,errString);
				}
				else if (bytesRead > 0)
				{
					bufferObj.append(interimBuffer,0,bytesRead);
					totalBytesRead += bytesRead;
				}
				else
				{
					// End of file
					break;
				}
			}
			while (totalBytesRead < maxFileSize);
			
			close(fd);
		}
		catch (...)
		{
			close(fd);
			if (throwOnError)
				throw;
		}
	}
}

//---------------------------------------------------------------------
// TInfoCollector::_ReadSymbolicLink (static protected)
//---------------------------------------------------------------------
void TInfoCollector::_ReadSymbolicLink (const string& filePath,
											 string& bufferObj,
											 bool throwOnError)
{
	int	finalSize = 0;
	
	bufferObj.resize(2048);
	
	finalSize = readlink(filePath.c_str(),const_cast<char*>(bufferObj.data()),bufferObj.capacity()-1);
	
	if (finalSize == -1)
	{
		if (throwOnError)
		{
			string		errString;
			
			errString += "While attempting to read from symbolic link '" + filePath + "'";
			throw TSymLibErrorObj(errno,errString);
		}
		else
		{
			finalSize = 0;
		}
	}
	
	bufferObj.resize(finalSize);
}

//---------------------------------------------------------------------
// TInfoCollector::_HexEthernetToUInt (static protected)
//---------------------------------------------------------------------
uint16_t TInfoCollector::_HexEthernetToUInt (const string& addrStr)
{
	uint16_t			num = 0;
	unsigned char*		numPtr = reinterpret_cast<unsigned char*>(&num);
	unsigned int		digitCount = addrStr.length() / 2;
	unsigned int		digitOffset = 0;
	
	if (digitCount > sizeof(num))
		digitCount = sizeof(num);
	digitOffset = sizeof(num) - digitCount;
	
	// Stuff the numeric variable big-endian (network byte order)
	for (unsigned int x = 0; x < digitCount; x++)
	{
		unsigned int	ch1 = toupper(addrStr[x*2]);
		unsigned int	ch2 = toupper(addrStr[x*2+1]);
		unsigned int	temp = 0;
		
		if (ch1 > '9')
			ch1 = ch1 - 'A' + 10;
		else
			ch1 = ch1 - '0';
		if (ch2 > '9')
			ch2 = ch2 - 'A' + 10;
		else
			ch2 = ch2 - '0';
		
		temp = ch1 * 16 + ch2;
		numPtr[x + digitOffset] = temp;
	}
	
	return num;
}

//---------------------------------------------------------------------
// TInfoCollector::_HexEthernetToULong (static protected)
//---------------------------------------------------------------------
unsigned long TInfoCollector::_HexEthernetToULong (const string& addrStr)
{
	unsigned long		num = 0;
	unsigned char*		numPtr = reinterpret_cast<unsigned char*>(&num);
	unsigned int		digitCount = addrStr.length() / 2;
	unsigned int		digitOffset = 0;
	
	if (digitCount > sizeof(num))
		digitCount = sizeof(num);
	digitOffset = sizeof(num) - digitCount;
	
	// Stuff the numeric variable big-endian (network byte order)
	for (unsigned int x = 0; x < digitCount; x++)
	{
		unsigned int	ch1 = toupper(addrStr[x*2]);
		unsigned int	ch2 = toupper(addrStr[x*2+1]);
		unsigned int	temp = 0;
		
		if (ch1 > '9')
			ch1 = ch1 - 'A' + 10;
		else
			ch1 = ch1 - '0';
		if (ch2 > '9')
			ch2 = ch2 - 'A' + 10;
		else
			ch2 = ch2 - '0';
		
		temp = ch1 * 16 + ch2;
		numPtr[x + digitOffset] = temp;
	}
	
	return num;
}

//---------------------------------------------------------------------
// TInfoCollector::_HexEthernetToIPv4Addr (static protected)
//---------------------------------------------------------------------
string TInfoCollector::_HexEthernetToIPv4Addr (const string& addrStr)
{
	struct in_addr		address;
	
	address.s_addr = htonl(_HexEthernetToULong(addrStr));
	
	return _IPAddressAsString(address);
}

//---------------------------------------------------------------------
// TInfoCollector::_HexEthernetToIPv6Addr (static protected)
//---------------------------------------------------------------------
string TInfoCollector::_HexEthernetToIPv6Addr (const string& addrStr)
{
	struct in6_addr		address;
	
	for (unsigned int x = 0; x < 4; x++)
		address.s6_addr32[x] = htonl(_HexEthernetToULong(addrStr.substr(x*8,8)));
	
	return _IPAddressAsString(address);
}

//---------------------------------------------------------------------
// TInfoCollector::_IPAddressAsString (static protected)
//---------------------------------------------------------------------
string TInfoCollector::_IPAddressAsString (const struct in_addr& addr)
{
	string					addrStr;
	struct sockaddr_in		socketInfo;
	int						niFlags = NI_NUMERICHOST;
	
	#ifdef NI_WITHSCOPEID
		niFlags |= NI_WITHSCOPEID;
	#endif
	
	addrStr.resize(NI_MAXHOST);
	memset(&socketInfo,0,sizeof(socketInfo));
	socketInfo.sin_family = AF_INET;
	#if defined(HAVE_STRUCT_SOCKADDR_IN_SIN_LEN)
		socketInfo.sin_len = sizeof(socketInfo);
	#endif
	socketInfo.sin_addr = addr;
	
	if (getnameinfo(reinterpret_cast<struct sockaddr*>(&socketInfo),sizeof(socketInfo),const_cast<char*>(addrStr.data()),addrStr.capacity()-1,NULL,0,niFlags) == 0)
		addrStr.resize(strlen(addrStr.c_str()));
	else
		addrStr = "";
	
	return addrStr;
}

#if HAVE_DECL_AF_INET6
	//---------------------------------------------------------------------
	// TInfoCollector::_IPAddressAsString (static protected)
	//---------------------------------------------------------------------
	string TInfoCollector::_IPAddressAsString (const struct in6_addr& addr)
	{
		string					addrStr;
		struct sockaddr_in6		socketInfo;
		int						niFlags = NI_NUMERICHOST;
		
		#ifdef NI_WITHSCOPEID
			niFlags |= NI_WITHSCOPEID;
		#endif
		
		addrStr.resize(NI_MAXHOST);
		memset(&socketInfo,0,sizeof(socketInfo));
		socketInfo.sin6_family = AF_INET6;
		#if defined(HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN)
			socketInfo.sin6_len = sizeof(socketInfo);
		#endif
		socketInfo.sin6_addr = addr;
		
		if (IN6_IS_ADDR_LINKLOCAL(&addr) && *(reinterpret_cast<u_int16_t*>(&socketInfo.sin6_addr.s6_addr[2])) != 0)
		{
			socketInfo.sin6_scope_id = ntohs(*(reinterpret_cast<u_int16_t*>(&socketInfo.sin6_addr.s6_addr[2])));
			socketInfo.sin6_addr.s6_addr[2] = socketInfo.sin6_addr.s6_addr[3] = 0;
		}
		
		if (getnameinfo(reinterpret_cast<struct sockaddr*>(&socketInfo),sizeof(socketInfo),const_cast<char*>(addrStr.data()),addrStr.capacity()-1,NULL,0,niFlags) == 0)
			addrStr.resize(strlen(addrStr.c_str()));
		else
			addrStr = "";
		
		return addrStr;
	}
#endif

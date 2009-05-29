/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Agent to obtain system information from BSD
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					08 Dec 2003
#		Last Modified:				25 Feb 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------

#if !USE_INLINE_FREEBSD_FILE_STRUCT
	// We need to do some preliminary includes here, defining KERNEL, before
	// other headers get pulled in.  Specifically, <sys/file.h> won't define
	// 'struct file' without the KERNEL define.
	#include <sys/types.h>
	#define KERNEL
	#include <sys/file.h>
	#undef KERNEL
#endif

// Now, on to our regularly-scheduled program

#include "kvm-proc.h"

#include "plugin-utils.h"

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <climits>

#include <fcntl.h>
#if HAVE_SYS_QUEUE_H
	#include <sys/queue.h>
#endif
#include <sys/filedesc.h>
#include <sys/vnode.h>
#include <unistd.h>

// ---------------------
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <sys/domain.h>
#include <sys/protosw.h>

#if USE_INLINE_FREEBSD_FILE_STRUCT
	#include <sys/types.h>
	#include <sys/file.h>
	#include <sys/mutex.h>
	#include <sys/queue.h>
	#include <sys/ucred.h>
	#include <sys/vnode.h>
	struct fileops;
	struct file
		{
			LIST_ENTRY(file)	f_list;
			short				f_type;
			void*				f_data;
			u_int				f_flag;
			struct mtx*			f_mtxp;
			struct fileops*		f_ops;
			struct	ucred*		f_cred;
			int					f_count;
			struct vnode*		f_vnode;
			off_t				f_offset;
			short				f_gcflag;
			#define	FMARK 0x1
			#define	FDEFER 0x2
			int					f_msgcount;
			int					f_seqcount;
			off_t				f_nextoff;
		};
#endif

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

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
	kvm_t*				kvmHandle = NULL;
	struct kinfo_proc*	processList = NULL;
	struct kinfo_proc*	lastProcessPtr = NULL;
	
	// Make sure our arguments are clear
	procInfoMap.clear();
	netConnMap.clear();
	
	// Open a handle to the KVM interface
	kvmHandle = kvm_open(NULL,NULL,NULL,O_RDONLY,NULL);
	if (!kvmHandle)
		throw TSymLibErrorObj(-1,"Unable to open KVM interface");
	
	try
	{
		int		processCount = 0;
		
		// Get the process list
		processList = kvm_getprocs(kvmHandle,KERN_PROC_ALL,0,&processCount);
		
		if (!processList)
			throw TSymLibErrorObj(-1,"Unable to obtain process list");
		
		// Walk the list, extracting interesting information
		lastProcessPtr = &processList[processCount];
		for (struct kinfo_proc* aProcessPtr = processList; aProcessPtr < lastProcessPtr; aProcessPtr++)
		{
			try
			{
				int	processStatus = 0;
				
				#if HAVE_STRUCT_KINFO_PROC_KP_PROC
					processStatus = aProcessPtr->kp_proc.p_stat;
				#else
					processStatus = aProcessPtr->ki_stat;
				#endif
				
				if (processStatus != SZOMB)
				{
					struct proc					procStruct;
					pid_t						pid = 0;
					ProcessInfo					procInfo;
					
					#if HAVE_STRUCT_KINFO_PROC_KP_EPROC
						struct kinfo_proc::eproc*	eProcPtr = &aProcessPtr->kp_eproc;
						
						_KVMRead(kvmHandle,eProcPtr->e_paddr,procStruct);
						
						// Get the userID
						procInfo.ownerID = eProcPtr->e_ucred.cr_uid;
					#else
						struct proc*				procPtr = aProcessPtr->ki_paddr;
						
						_KVMRead(kvmHandle,procPtr,procStruct);
						
						// Get the userID
						procInfo.ownerID = procPtr->p_ucred->cr_uid;
					#endif
					
					// Path
					procInfo.path = procStruct.p_comm;
					
					// ProcID
					pid = procStruct.p_pid;
					
					if (procStruct.p_fd)
					{
						// We have open files/sockets/whatever
						struct filedesc		fileDesc;
						unsigned long		fileListSize = 0;
						struct file**		openFileList = NULL;
						
						_KVMRead(kvmHandle,procStruct.p_fd,fileDesc);
						
						fileListSize = (fileDesc.fd_lastfile+1)*sizeof(struct file*);
						openFileList = static_cast<struct file**>(malloc(fileListSize));
						
						if (!openFileList)
							throw TSymLibErrorObj(ENOMEM,"Not enough memory");
						
						try
						{
							_KVMRead(kvmHandle,fileDesc.fd_ofiles,openFileList,fileListSize);
							
							for (int fd = 0; fd < fileDesc.fd_lastfile; fd++)
							{
								struct file		aFile;
								
								_KVMRead(kvmHandle,openFileList[fd],aFile);
								
								if (aFile.f_type == DTYPE_SOCKET)
								{
									// Network socket -- finally!
									
									struct socket*		socketPtr = NULL;
									struct socket		socketInfo;
									struct protosw		protocolInfo;
									struct domain		domainInfo;
									
									socketPtr = reinterpret_cast<struct socket*>(aFile.f_data);
									
									_KVMRead(kvmHandle,socketPtr,socketInfo);
									if (socketInfo.so_pcb && ((socketInfo.so_state & SS_ISDISCONNECTED) != SS_ISDISCONNECTED))
									{
										_KVMRead(kvmHandle,socketInfo.so_proto,protocolInfo);
										_KVMRead(kvmHandle,protocolInfo.pr_domain,domainInfo);
										
										if (domainInfo.dom_family == AF_INET)
										{
											struct inpcb	inpcbInfo;
											long			ref = 0;
											
											_KVMRead(kvmHandle,socketInfo.so_pcb,inpcbInfo);
											
											if (protocolInfo.pr_protocol == IPPROTO_TCP)
												ref = reinterpret_cast<unsigned long>(inpcbInfo.inp_ppcb);
											else
												ref = reinterpret_cast<unsigned long>(socketInfo.so_pcb);
											
											if (ref != 0)
											{
												if (netConnMap.find(ref) == netConnMap.end())
												{
													NetworkConnection			connInfo;
													
													connInfo.protoID = protocolInfo.pr_protocol;
													connInfo.protoFamily = domainInfo.dom_family;
													connInfo.sourceAddr = _IPAddressAsString(inpcbInfo.inp_laddr);
													connInfo.destAddr = _IPAddressAsString(inpcbInfo.inp_faddr);
													connInfo.sourcePort = htons(inpcbInfo.inp_lport);
													connInfo.destPort = htons(inpcbInfo.inp_fport);
													
													netConnMap[ref] = connInfo;
												}
												
												procInfo.inodeList.push_back(ref);
											}
										}
										#if HAVE_DECL_AF_INET6
											else if (domainInfo.dom_family == AF_INET6)
											{
												struct in6pcb	inpcbInfo;
												long			ref = 0;
												
												_KVMRead(kvmHandle,socketInfo.so_pcb,inpcbInfo);
												
												if (protocolInfo.pr_protocol == IPPROTO_TCP)
													ref = reinterpret_cast<unsigned long>(inpcbInfo.inp_ppcb);
												else
													ref = reinterpret_cast<unsigned long>(socketInfo.so_pcb);
												
												if (ref != 0)
												{
													if (netConnMap.find(ref) == netConnMap.end())
													{
														NetworkConnection			connInfo;
														
														connInfo.protoID = protocolInfo.pr_protocol;
														connInfo.protoFamily = domainInfo.dom_family;
														connInfo.sourceAddr = _IPAddressAsString(inpcbInfo.in6p_laddr);
														connInfo.destAddr = _IPAddressAsString(inpcbInfo.in6p_faddr);
														connInfo.sourcePort = htons(inpcbInfo.in6p_lport);
														connInfo.destPort = htons(inpcbInfo.in6p_fport);
														
														netConnMap[ref] = connInfo;
													}
													
													procInfo.inodeList.push_back(ref);
												}
											}
										#endif
									}
								}
							}
						}
						catch (...)
						{
							// Make sure we deallocate our openFileList handle
							free(openFileList);
							// Re-throw the error
							throw;
						}
						
						free(openFileList);
					}
					
					procInfoMap[pid] = procInfo;
				}
			}
			catch (TSymLibErrorObj& errObj)
			{
				if (errObj.GetError() != kErrorKVMReadFailed)
					throw;
			}
			catch (...)
			{
				throw;
			}
		}
	}
	catch (...)
	{
		// Make sure various things are disposed of
		if (kvmHandle)
		{
			kvm_close(kvmHandle);
			kvmHandle = NULL;
		}
		throw;
	}
	
	if (kvmHandle)
	{
		kvm_close(kvmHandle);
		kvmHandle = NULL;
	}
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

/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		Agent to examine TCP network data
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					05 Jan 2004
#		Last Modified:				05 Jan 2004
#		
#######################################################################
*/

#if !defined(NETWORK_HEADERS)
#define NETWORK_HEADERS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

//---------------------------------------------------------------------
// Import namespaces for convenience
//---------------------------------------------------------------------
using namespace std;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

#if HAVE_NET_ETHERNET_H
	#include <net/ethernet.h>
#else
	#define	ETHER_ADDR_LEN		6
	#define ETHER_HDR_LEN		14
	
	struct	ether_header
		{
			u_int8_t	ether_dhost[ETHER_ADDR_LEN];
			u_int8_t	ether_shost[ETHER_ADDR_LEN];
			u_int16_t	ether_type;
		};
#endif

#if HAVE_NETINET_IP_ICMP_H && HAVE_STRUCT_ICMP_ICMP_TYPE
	#include <netinet/ip_icmp.h>
#else
	struct icmp_ra_addr
		{
			u_int32_t ira_addr;
			u_int32_t ira_preference;
		};

	struct icmp
		{
			u_int8_t  icmp_type;
			u_int8_t  icmp_code;
			u_int16_t icmp_cksum;
			union
			{
				u_char ih_pptr;
				struct in_addr ih_gwaddr;
				struct ih_idseq
				{
					u_int16_t icd_id;
					u_int16_t icd_seq;
				} ih_idseq;
				u_int32_t ih_void;
				struct ih_pmtu
				{
					u_int16_t ipm_void;
					u_int16_t ipm_nextmtu;
				} ih_pmtu;
				struct ih_rtradv
				{
					u_int8_t irt_num_addrs;
					u_int8_t irt_wpa;
					u_int16_t irt_lifetime;
				} ih_rtradv;
			} icmp_hun;
			#define	icmp_pptr	icmp_hun.ih_pptr
			#define	icmp_gwaddr	icmp_hun.ih_gwaddr
			#define	icmp_id		icmp_hun.ih_idseq.icd_id
			#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
			#define	icmp_void	icmp_hun.ih_void
			#define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
			#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
			#define	icmp_num_addrs	icmp_hun.ih_rtradv.irt_num_addrs
			#define	icmp_wpa	icmp_hun.ih_rtradv.irt_wpa
			#define	icmp_lifetime	icmp_hun.ih_rtradv.irt_lifetime
			union
			{
				struct
				{
					u_int32_t its_otime;
					u_int32_t its_rtime;
					u_int32_t its_ttime;
				} id_ts;
				struct
				{
					struct ip idi_ip;
				} id_ip;
				struct icmp_ra_addr id_radv;
				u_int32_t   id_mask;
				u_int8_t    id_data[1];
			} icmp_dun;
			#define	icmp_otime	icmp_dun.id_ts.its_otime
			#define	icmp_rtime	icmp_dun.id_ts.its_rtime
			#define	icmp_ttime	icmp_dun.id_ts.its_ttime
			#define	icmp_ip		icmp_dun.id_ip.idi_ip
			#define	icmp_radv	icmp_dun.id_radv
			#define	icmp_mask	icmp_dun.id_mask
			#define	icmp_data	icmp_dun.id_data
		};
#endif

#if HAVE_NET_IF_ARP_H
	#include <net/if_arp.h>
#else
struct arphdr
	{
		unsigned short int ar_hrd;
		unsigned short int ar_pro;
		unsigned char ar_hln;
		unsigned char ar_pln;
		unsigned short int ar_op;
	};
#endif

//---------------------------------------------------------------------
#endif // NETWORK_HEADERS

/*
#######################################################################
#		SYMBIOT
#		
#		Real-time Network Threat Modeling
#		(C) 2002-2004 Symbiot, Inc.	---	ALL RIGHTS RESERVED
#		
#		log-watcher file
#		
#		http://www.symbiot.com
#		
#######################################################################
#		Author: Borrowed Time, Inc.
#		e-mail: libsymbiot@bti.net
#		
#		Created:					15 Apr 2004
#		Last Modified:				21 Sep 2004
#		
#######################################################################
*/

#if !defined(PLUGIN_DEFS)
#define PLUGIN_DEFS

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-api.h"

#include <map>
#include <string>
#include <vector>

//---------------------------------------------------------------------
// Import symbols
//---------------------------------------------------------------------
using namespace symbiot;

using std::map;
using std::pair;
using std::string;
using std::vector;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

#define	kMessageNodeWatchFile							"WATCH_FILE"
#define	kMessageAttributeFilePath							"path"
#define	kMessageAttributeWatchInterval						"watch_interval"
#define	kMessageAttributeWatchStyle							"watch_style"

#define	kMessageNodePatternList								"PATTERN_LIST"
#define	kMessageNodePattern										"PATTERN"
#define	kMessageAttributeServerRef									"ref"
#define	kMessageAttributePattern									"pattern"
#define	kMessageAttributeOptions									"options"

#define	kMessageNodeLogAlert							"LOG_ALERT"
#define	kMessageNodeLogEntry								"ENTRY"

#define	kMessageNodePCREInfo							"PCRE_INFO"
#define	kMessageAttributePCREEnabled						"enabled"
#define	kMessageAttributePCREVersion						"version"
#define	kMessageAttributePCREUTF8							"utf8"


#define	kMessageAttributeLogEntryCount					"count"
#define	kMessageAttributeLogEntryText					"text"
#define	kMessageAttributeValueTrue						"true"
#define	kMessageAttributeValueFalse						"false"
#define	kMessageAttributeValueTail						"tail"
#define	kMessageAttributeValueContents					"contents"

#define	kSearchOptionUsePCRE							'p'
#define	kSearchOptionUseRegex							'r'
#define	kSearchOptionCaseInsensitive					'i'
#define	kSearchOptionInvertMatch						'v'
#define	kSearchOptionEnableUTF8							'8'	// PCRE-only feature

//---------------------------------------------------------------------
#endif // PLUGIN_DEFS

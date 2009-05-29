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
#		Created:					28 Aug 2003
#		Last Modified:				16 Feb 2004
#
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-prefs.h"

#include "symlib-threads.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
#define	kLocalConfFileName							"symagent.xml"
#define	kLocalConfFileMinVersion					1.0

#define	kTagPreferences								"preferences"
#define	kTagPrefAttribWhere							"where"
#define	kTagPrefAttribVersion						"version"

#define	kTagPrefAttribValueLocal					"local"
#define	kTagPrefAttribValueRemote					"remote"

//---------------------------------------------------------------------
// Global Variables
//---------------------------------------------------------------------
static	TLibSymPrefs*								gLibSymPrefsPtr = NULL;
static	TPthreadMutexObj							gLibSymPrefsPtrMutex;

//*********************************************************************
// Class TLibSymPrefs
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TLibSymPrefs::TLibSymPrefs ()
	:	fPrefLocalHomeNodePtr(NULL),
		fPrefRemoteHomeNodePtr(NULL)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TLibSymPrefs::~TLibSymPrefs ()
{
}

//---------------------------------------------------------------------
// TLibSymPrefs::LoadLocalConfFile
//---------------------------------------------------------------------
void TLibSymPrefs::LoadLocalConfFile ()
{
	std::string			confFilePath(_FindLocalConfFile());
	TFileObj			configFile;
	TConfigXMLObj		configParser;
	TXMLNodeObj*		remoteRootNodePtr = NULL;
	const TXMLNodeObj*	loggingNodePtr = NULL;
	
	if (confFilePath.empty())
		throw TSymLibErrorObj(kErrorLocalPreferenceNotFound);
	
	configFile.SetPath(confFilePath);
	
	// Verify the ownership of the file
	if (configFile.OwnerID(true) != getuid())
	{
		std::string		errString;
		
		errString = "Ownership of configuration file '" + confFilePath + "' is incorrect";
		throw TSymLibErrorObj(kErrorLocalPreferencesPermissionsBad,errString);
	}
	
	// Verify the permissions on the file
	if (configFile.Permissions(true) != (S_IWUSR|S_IRUSR))
	{
		std::string		errString;
		
		errString = "Access permissions on configuration file '" + confFilePath + "' are incorrect";
		throw TSymLibErrorObj(kErrorLocalPreferencesPermissionsBad,errString);
	}
	
	if (!configParser.ParseConfig(configFile,fPrefRootNode))
		throw TSymLibErrorObj(kErrorLocalPreferenceCorrupt);
	
	// Validate the parsed preferences
	_ValidateLocalConf();
	
	// Setup the node that will contain the server-provided preferences
	remoteRootNodePtr = new TXMLNodeObj;
	remoteRootNodePtr->SetTag(kTagPreferences);
	remoteRootNodePtr->AddAttribute(kTagPrefAttribWhere,kTagPrefAttribValueRemote);
	fPrefRemoteHomeNodePtr = const_cast<TXMLNodeObj*>(fPrefRootNode.Append(remoteRootNodePtr));
	
	// Extract some choice preferences
	loggingNodePtr = GetPrefsPtr()->GetPrefNodePtr(kTagPrefLogging);
	gEnvironObjPtr->SetLogDirectory(GetPrefsPtr()->GetPrefData(kTagPrefLogDir),true);
	gEnvironObjPtr->SetLogUser(GetPrefsPtr()->GetPrefData(kTagPrefLogUser));
	gEnvironObjPtr->SetLogGroup(GetPrefsPtr()->GetPrefData(kTagPrefLogGroup));
}

//---------------------------------------------------------------------
// TLibSymPrefs::AppendPrefNodePtr
//---------------------------------------------------------------------
const TXMLNodeObj* TLibSymPrefs::AppendPrefNodePtr (const std::string& tag,
													const std::string& data)
{
	if (!LocalPrefsLoaded())
		throw TSymLibErrorObj(kErrorLocalPreferenceNotLoaded,"Within TLibSymPrefs::AppendPrefNodePtr()");
	
	// New nodes appended through this function will always be appended to the remote
	// preference section
	
	return fPrefRemoteHomeNodePtr->Append(tag,data);
}

//---------------------------------------------------------------------
// TLibSymPrefs::AppendPrefNodePtr
//---------------------------------------------------------------------
const TXMLNodeObj* TLibSymPrefs::AppendPrefNodePtr (const TXMLNodeObj* nodeObjPtr)
{
	if (!LocalPrefsLoaded())
		throw TSymLibErrorObj(kErrorLocalPreferenceNotLoaded,"Within TLibSymPrefs::AppendPrefNodePtr()");
	
	// New nodes appended through this function will always be appended to the remote
	// preference section
	
	return fPrefRemoteHomeNodePtr->Append(new TXMLNodeObj(*nodeObjPtr));
}

//---------------------------------------------------------------------
// TLibSymPrefs::GetPrefNodePtr
//---------------------------------------------------------------------
const TXMLNodeObj* TLibSymPrefs::GetPrefNodePtr (const std::string& tag,
												 const std::string& attribute,
												 const std::string& attributeValue) const
{
	const TXMLNodeObj*	foundNodePtr = NULL;
	
	if (!LocalPrefsLoaded())
		throw TSymLibErrorObj(kErrorLocalPreferenceNotLoaded,"Within TLibSymPrefs::GetPrefNodePtr()");
	
	foundNodePtr = fPrefLocalHomeNodePtr->FindNode(tag,attribute,attributeValue);
	if (!foundNodePtr && fPrefRemoteHomeNodePtr)
		foundNodePtr = fPrefRemoteHomeNodePtr->FindNode(tag,attribute,attributeValue);
	
	return foundNodePtr;
}

//---------------------------------------------------------------------
// TLibSymPrefs::GetPrefData
//---------------------------------------------------------------------
std::string TLibSymPrefs::GetPrefData (const std::string& tag,
									   const std::string& attribute,
									   const std::string& attributeValue) const
{
	std::string			data;
	const TXMLNodeObj*	foundNodePtr = NULL;
	
	foundNodePtr = GetPrefNodePtr(tag,attribute,attributeValue);
	if (foundNodePtr)
		data = foundNodePtr->Data();
	
	return data;
}

//---------------------------------------------------------------------
// TLibSymPrefs::GetNodePtr
//---------------------------------------------------------------------
const TXMLNodeObj* TLibSymPrefs::GetNodePtr (const TXMLNodeObj* parentNodePtr,
											 const std::string& tag,
											 const std::string& attribute,
											 const std::string& attributeValue) const
{
	const TXMLNodeObj*	foundNodePtr = NULL;
	
	if (parentNodePtr == NULL)
		throw TSymLibErrorObj(EINVAL);
	
	foundNodePtr = parentNodePtr->FindNode(tag,attribute,attributeValue);
	
	return foundNodePtr;
}

//---------------------------------------------------------------------
// TLibSymPrefs::GetNodePtrData
//---------------------------------------------------------------------
std::string TLibSymPrefs::GetNodePtrData (const TXMLNodeObj* parentNodePtr,
										  const std::string& tag,
										  const std::string& attribute,
										  const std::string& attributeValue) const
{
	std::string			data;
	const TXMLNodeObj*	foundNodePtr = NULL;
	
	if (parentNodePtr == NULL)
		throw TSymLibErrorObj(EINVAL);
	
	foundNodePtr = parentNodePtr->FindNode(tag,attribute,attributeValue);
	if (foundNodePtr)
		data = foundNodePtr->Data();
	
	return data;
}

//---------------------------------------------------------------------
// TLibSymPrefs::_FindLocalConfFile (protected)
//---------------------------------------------------------------------
std::string TLibSymPrefs::_FindLocalConfFile () const
{
	std::string		confFilePath;
	std::string		confFileName = kLocalConfFileName;
	StdStringList	appArgList(gEnvironObjPtr->ArgList());
	
	if (!appArgList.empty())
	{
		std::string		realAppDir;
		std::string		appDir;
		TFileObj		appFileObj(appArgList.front());
		TFileObj		confFileObj;
		StdStringList	possibleDirectoryList;
		
		appDir = appFileObj.DirectoryPath();
		realAppDir = TFileObj(appFileObj.RealPath()).DirectoryPath();
		
		// Look for a configuration file in various places
		possibleDirectoryList.push_back(GetCurrentDirectory());
		possibleDirectoryList.push_back(appDir);
		possibleDirectoryList.push_back(realAppDir);
		possibleDirectoryList.push_back(ABS_SYSCONFDIR);
		possibleDirectoryList.push_back("/usr/local/etc/opensims/");
		possibleDirectoryList.push_back("/etc/local/opensims/");
		possibleDirectoryList.push_back("/usr/local/opensims/");
		possibleDirectoryList.push_back("/usr/etc/opensims/");
		possibleDirectoryList.push_back("/etc/opensims/");
		possibleDirectoryList.push_back("/usr/opensims/");
		
		if (kPathDelimiterAsChar != '/')
		{
			// This system's path delimiter is different; do a global find-and-replace on all paths we just defined
			for (StdStringList_iter x = possibleDirectoryList.begin(); x != possibleDirectoryList.end(); x++)
			{
				for (unsigned int y = 0; y < x->length(); y++)
				{
					if ((*x)[y] == '/')
						(*x)[y] = kPathDelimiterAsChar;
				}
			}
		}
		
		if (!gEnvironObjPtr->ConfFileLoc().empty())
			confFileName = gEnvironObjPtr->ConfFileLoc();
		confFilePath = FindFile(confFileName,possibleDirectoryList);
	}
	
	return confFilePath;
}

//---------------------------------------------------------------------
// TLibSymPrefs::_ValidateLocalConf (protected)
//---------------------------------------------------------------------
void TLibSymPrefs::_ValidateLocalConf ()
{
	std::string			tempString;
	
	// Find and retain the toplevel preferences tag
	fPrefLocalHomeNodePtr = fPrefRootNode.FindNode(kTagPreferences,kTagPrefAttribWhere,kTagPrefAttribValueLocal);
	
	if (!LocalPrefsLoaded())
		throw TSymLibErrorObj(kErrorLocalPreferenceNotLoaded,"While validating local configuration file");
	
	if (!fPrefLocalHomeNodePtr)
		throw TSymLibErrorObj(kErrorLocalPreferenceCorrupt);
	
	// Make sure the version format is ok
	tempString = fPrefLocalHomeNodePtr->AttributeValue(kTagPrefAttribVersion);
	
	if (tempString.empty() || StringToNum(tempString) < kLocalConfFileMinVersion)
		throw TSymLibErrorObj(kErrorLocalPreferenceVersionMismatch);
	
	// Verify that we have an entry certificate directories
	if (fPrefLocalHomeNodePtr->GetData(kTagPrefCertDir).empty())
		throw TSymLibErrorObj(kErrorLocalPreferenceCorrupt);
	
	// Find the server info node
	const TXMLNodeObj* serverNodePtr = fPrefLocalHomeNodePtr->FindNode(kTagPrefServer);
	
	if (!serverNodePtr)
		throw TSymLibErrorObj(kErrorLocalPreferenceCorrupt);
	
	// Verify server information exists
	tempString = serverNodePtr->GetData(kTagPrefHost);
	if (tempString.empty())
		throw TSymLibErrorObj(kErrorLocalPreferenceCorrupt);
	if (static_cast<unsigned int>(StringToNum(serverNodePtr->GetData(kTagPrefPort))) == 0)
		throw TSymLibErrorObj(kErrorLocalPreferenceCorrupt);
	if (static_cast<unsigned int>(StringToNum(serverNodePtr->GetData(kTagPrefSSLPort))) == 0)
		throw TSymLibErrorObj(kErrorLocalPreferenceCorrupt);
}

//*********************************************************************
// Global Functions
//*********************************************************************

//---------------------------------------------------------------------
// GetPrefsPtr
//---------------------------------------------------------------------
TLibSymPrefs* GetPrefsPtr ()
{
	if (!gLibSymPrefsPtr)
	{
		TLockedPthreadMutexObj		lock(gLibSymPrefsPtrMutex);
		
		if (!gLibSymPrefsPtr)
		{
			gLibSymPrefsPtr = new TLibSymPrefs;
		}
	}
	
	return gLibSymPrefsPtr;
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

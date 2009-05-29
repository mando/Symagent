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
#		Created:					28 Oct 2003
#		Last Modified:				28 Oct 2003
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-expat.h"

#include "symlib-threads.h"
#include "symlib-utils.h"

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
const int	TExpatBaseObj::kReadBufferMaxSize = 32768;	// must be a power of 2
const int	TExpatBaseObj::kReadBufferMinSize = 4096;	// must be a power of 2

//---------------------------------------------------------------------
// Static member intialization
//---------------------------------------------------------------------
TExpatBaseObj::TInstanceMapObj*						TExpatBaseObj::gInstanceMapPtr = NULL;

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------
TPthreadMutexObj									gInstanceMapMutex;

//*********************************************************************
// Class TExpatBaseObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TExpatBaseObj::TExpatBaseObj (const std::string& encoding, const XML_Char& namespaceSeparator)
	:	fParserHandle(NULL),
		fEncoding(encoding),
		fNamespaceSeparator(namespaceSeparator),
		fAutoTrimCharData(false),
		fPassEmptyCharData(true)
{
	const XML_Char*		encodingPtr = (encoding.empty() ? NULL : encoding.c_str());
	
	if (namespaceSeparator == '\0')
		fParserHandle = XML_ParserCreate(encodingPtr);
	else
		fParserHandle = XML_ParserCreateNS(encodingPtr,fNamespaceSeparator);
	
	// Make sure our instance map singleton object is initialized
	if (!gInstanceMapPtr)
	{
		TLockedPthreadMutexObj		lock(gInstanceMapMutex);
		
		if (!gInstanceMapPtr)
		{
			gInstanceMapPtr = new TInstanceMapObj;
		}
	}
	
	if (fParserHandle)
	{
		XML_UseParserAsHandlerArg(fParserHandle);
		gInstanceMapPtr->AddEntry(fParserHandle,this);
	}
}

//---------------------------------------------------------------------
// Constructor (protected)
//---------------------------------------------------------------------
TExpatBaseObj::TExpatBaseObj (bool /* fake */)
	:	fParserHandle(NULL),
		fNamespaceSeparator('\0'),
		fAutoTrimCharData(false),
		fPassEmptyCharData(true)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TExpatBaseObj::~TExpatBaseObj ()
{
	_ClearInternalList();
	
	if (fParserHandle)
	{
		gInstanceMapPtr->RemoveEntry(fParserHandle);
		XML_ParserFree(fParserHandle);
		fParserHandle = NULL;
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::Reset
//---------------------------------------------------------------------
bool TExpatBaseObj::Reset (const std::string& newEncoding)
{
	bool				success = false;
	const XML_Char*		encodingPtr = (newEncoding.empty() ? NULL : newEncoding.c_str());
	
	if (XML_ParserReset(fParserHandle,encodingPtr) == XML_TRUE)
	{
		if (!newEncoding.empty())
			fEncoding = newEncoding;
		
		_ClearInternalList();
		
		success = true;
	}
	
	return success;
}

//---------------------------------------------------------------------
// TExpatBaseObj::FreeContentModel
//---------------------------------------------------------------------
void TExpatBaseObj::FreeContentModel (const XML_Content* model)
{
	XMLContentPtrList_iter	found_iter = find(fXMLContentPtrList.begin(),fXMLContentPtrList.end(),model);
	
	if (found_iter != fXMLContentPtrList.end())
		fXMLContentPtrList.erase(found_iter);
	
	XML_FreeContentModel(fParserHandle,const_cast<XML_Content*>(model));
}

//---------------------------------------------------------------------
// TExpatBaseObj::SetEncoding
//---------------------------------------------------------------------
XML_Status TExpatBaseObj::SetEncoding (const std::string& newEncoding)
{
	XML_Status			result = XML_STATUS_OK;
	const XML_Char*		newEncodingPtr = (newEncoding.empty() ? NULL : newEncoding.c_str());
	
	result = XML_SetEncoding(fParserHandle,newEncodingPtr);
	if (result == XML_STATUS_OK)
		fEncoding = newEncoding;
	
	return result;
}

//---------------------------------------------------------------------
// TExpatBaseObj::GetBase
//---------------------------------------------------------------------
std::string TExpatBaseObj::GetBase ()
{
	return std::string(XML_GetBase(fParserHandle));
}

//---------------------------------------------------------------------
// TExpatBaseObj::SetBase
//---------------------------------------------------------------------
XML_Status TExpatBaseObj::SetBase (const std::string& newBase)
{
	const XML_Char*		newBasePtr = (newBase.empty() ? NULL : newBase.c_str());
	
	return XML_SetBase(fParserHandle,newBasePtr);
}

//---------------------------------------------------------------------
// TExpatBaseObj::UseForeignDTD
//---------------------------------------------------------------------
XML_Error TExpatBaseObj::UseForeignDTD (bool useForeign)
{
	XML_Bool	xmlUseForeign = (useForeign ? XML_TRUE : XML_FALSE);
	
	return XML_UseForeignDTD(fParserHandle,xmlUseForeign);
}

//---------------------------------------------------------------------
// TExpatBaseObj::CreateExternalEntityParserObj ()
//---------------------------------------------------------------------
TExpatBaseObj* TExpatBaseObj::CreateExternalEntityParserObj (const std::string& context, const std::string& encoding)
{
	TExpatBaseObj*		newExpatObjPtr = NULL;
	const XML_Char*		contextPtr = (context.empty() ? NULL : context.c_str());
	const XML_Char*		encodingPtr = (encoding.empty() ? NULL : encoding.c_str());
	XML_Parser			parserHandle = XML_ExternalEntityParserCreate(fParserHandle,contextPtr,encodingPtr);
	
	if (parserHandle)
	{
		newExpatObjPtr = _NewObject();
		
		newExpatObjPtr->fParserHandle = parserHandle;
		newExpatObjPtr->fContext = context;
		newExpatObjPtr->fEncoding = encoding;
		
		fExternalExpatObjPtrList.push_back(newExpatObjPtr);
	}
	
	return newExpatObjPtr;
}

//---------------------------------------------------------------------
// TExpatBaseObj::SetParamEntityParsing ()
//---------------------------------------------------------------------
bool TExpatBaseObj::SetParamEntityParsing (XML_ParamEntityParsing howToParse)
{
	bool	success = false;
	
	if (XML_SetParamEntityParsing(fParserHandle,howToParse) != 0)
		success = true;
	
	return success;
}

//---------------------------------------------------------------------
// TExpatBaseObj::GetExpatBuffer ()
//---------------------------------------------------------------------
void* TExpatBaseObj::GetExpatBuffer (int requestedSize)
{
	return XML_GetBuffer(fParserHandle,requestedSize);
}

//---------------------------------------------------------------------
// TExpatBaseObj::Parse
//---------------------------------------------------------------------
XML_Status TExpatBaseObj::Parse (size_t bufferSize)
{
	return XML_ParseBuffer(fParserHandle,bufferSize,0);
}

//---------------------------------------------------------------------
// TExpatBaseObj::Parse
//---------------------------------------------------------------------
XML_Status TExpatBaseObj::Parse (const char* bufferPtr, size_t bufferSize)
{
	return XML_Parse(fParserHandle,bufferPtr,bufferSize,0);
}

//---------------------------------------------------------------------
// TExpatBaseObj::Parse
//---------------------------------------------------------------------
XML_Status TExpatBaseObj::Parse (const std::string& bufferObj)
{
	return XML_Parse(fParserHandle,bufferObj.data(),bufferObj.length(),0);
}

//---------------------------------------------------------------------
// TExpatBaseObj::Parse
//---------------------------------------------------------------------
XML_Status TExpatBaseObj::Parse (TFileObj& fileObj)
{
	XML_Status				status = XML_STATUS_OK;
	XML_Status				finalStatus = XML_STATUS_OK;
	bool					fileWasOpen = fileObj.IsOpen();
	std::string				fileBuffer;
	const unsigned long		kFileBufferSize = 16384;
	
	// Open the file for reading, if necessary
	if (!fileWasOpen)
	{
		// Open the file in read-only mode
		fileObj.Open(O_RDONLY);
	}
	
	// Make sure we're reading from the beginning
	fileObj.SetFilePosition(0);
	
	// Read segments from the file, parsing as we go
	while (!fileObj.IsEOF())
	{
		fileObj.Read(fileBuffer,kFileBufferSize);
		if (!fileBuffer.empty())
		{
			status = Parse(fileBuffer);
			if (status != XML_STATUS_OK)
				break;
		}
	}
	
	// Tell expat we're finished
	finalStatus = Finalize();
	if (status == XML_STATUS_OK && finalStatus != XML_STATUS_OK)
		status = finalStatus;
	
	if (!fileWasOpen)
	{
		// The file wasn't open before, so close it now
		fileObj.Close();
	}
	
	return status;
}

//---------------------------------------------------------------------
// TExpatBaseObj::Finalize
//---------------------------------------------------------------------
XML_Status TExpatBaseObj::Finalize ()
{
	return XML_Parse(fParserHandle,NULL,0,1);
}

//---------------------------------------------------------------------
// TExpatBaseObj::SetDefaultCurrent
//---------------------------------------------------------------------
void TExpatBaseObj::SetDefaultCurrent ()
{
	XML_DefaultCurrent(fParserHandle);
}

//---------------------------------------------------------------------
// TExpatBaseObj::GetByteCount
//---------------------------------------------------------------------
long TExpatBaseObj::GetByteCount ()
{
	return XML_GetCurrentByteCount(fParserHandle);
}

//---------------------------------------------------------------------
// TExpatBaseObj::GetByteIndex
//---------------------------------------------------------------------
long TExpatBaseObj::GetByteIndex ()
{
	return XML_GetCurrentByteIndex(fParserHandle);
}

//---------------------------------------------------------------------
// TExpatBaseObj::GetLineIndex
//---------------------------------------------------------------------
long TExpatBaseObj::GetLineIndex ()
{
	return XML_GetCurrentLineNumber(fParserHandle);
}

//---------------------------------------------------------------------
// TExpatBaseObj::GetColumnIndex
//---------------------------------------------------------------------
long TExpatBaseObj::GetColumnIndex ()
{
	return XML_GetCurrentColumnNumber(fParserHandle);
}

//---------------------------------------------------------------------
// TExpatBaseObj::ErrorCode
//---------------------------------------------------------------------
XML_Error TExpatBaseObj::ErrorCode ()
{
	return XML_GetErrorCode(fParserHandle);
}

//---------------------------------------------------------------------
// TExpatBaseObj::ErrorDescription
//---------------------------------------------------------------------
std::string TExpatBaseObj::ErrorDescription ()
{
	return ErrorCodeDescription(ErrorCode());
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableElementHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableElementHandling ()
{
	XML_SetElementHandler(fParserHandle,_ElementHandler_Start,_ElementHandler_End);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableElementHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableElementHandling ()
{
	XML_SetElementHandler(fParserHandle,NULL,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableCharacterDataHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableCharacterDataHandling (bool autoTrim, bool passEmpty)
{
	XML_SetCharacterDataHandler(fParserHandle,_CharacterDataHandler);
	fAutoTrimCharData = autoTrim;
	fPassEmptyCharData = passEmpty;
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableCharacterDataHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableCharacterDataHandling ()
{
	XML_SetCharacterDataHandler(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableProcessingInstructionHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableProcessingInstructionHandling ()
{
	XML_SetProcessingInstructionHandler(fParserHandle,_ProcessingInstructionHandler);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableProcessingInstructionHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableProcessingInstructionHandling ()
{
	XML_SetProcessingInstructionHandler(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableCommentHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableCommentHandling ()
{
	XML_SetCommentHandler(fParserHandle,_CommentHandler);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableCommentHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableCommentHandling ()
{
	XML_SetCommentHandler(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableCDataSectionHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableCDataSectionHandling ()
{
	XML_SetCdataSectionHandler(fParserHandle,_CDataSectionHandler_Start,_CDataSectionHandler_End);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableCDataSectionHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableCDataSectionHandling ()
{
	XML_SetCdataSectionHandler(fParserHandle,NULL,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableDefaultHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableDefaultHandling ()
{
	XML_SetDefaultHandler(fParserHandle,_DefaultHandler);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableDefaultHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableDefaultHandling ()
{
	XML_SetDefaultHandler(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableDefaultExpandHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableDefaultExpandHandling ()
{
	XML_SetDefaultHandlerExpand(fParserHandle,_DefaultExpandHandler);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableDefaultExpandHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableDefaultExpandHandling ()
{
	XML_SetDefaultHandlerExpand(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableDoctypeDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableDoctypeDeclHandling ()
{
	XML_SetDoctypeDeclHandler(fParserHandle,_DoctypeDeclHandler_Start,_DoctypeDeclHandler_End);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableDoctypeDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableDoctypeDeclHandling ()
{
	XML_SetDoctypeDeclHandler(fParserHandle,NULL,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableUnparsedEntityDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableUnparsedEntityDeclHandling ()
{
	XML_SetUnparsedEntityDeclHandler(fParserHandle,_UnparsedEntityDeclHandler);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableUnparsedEntityDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableUnparsedEntityDeclHandling ()
{
	XML_SetUnparsedEntityDeclHandler(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableNotationDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableNotationDeclHandling ()
{
	XML_SetNotationDeclHandler(fParserHandle,_NotationDeclHandler);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableNotationDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableNotationDeclHandling ()
{
	XML_SetNotationDeclHandler(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableNamespaceDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableNamespaceDeclHandling ()
{
	XML_SetNamespaceDeclHandler(fParserHandle,_NamespaceDeclHandler_Start,_NamespaceDeclHandler_End);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableNamespaceDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableNamespaceDeclHandling ()
{
	XML_SetNamespaceDeclHandler(fParserHandle,NULL,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableExternalEntityRefHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableExternalEntityRefHandling ()
{
	XML_SetExternalEntityRefHandler(fParserHandle,_ExternalEntityRefHandler);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableExternalEntityRefHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableExternalEntityRefHandling ()
{
	XML_SetExternalEntityRefHandler(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableSkippedEntityHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableSkippedEntityHandling ()
{
	XML_SetSkippedEntityHandler(fParserHandle,_SkippedEntityHandler);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableSkippedEntityHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableSkippedEntityHandling ()
{
	XML_SetSkippedEntityHandler(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableUnknownEncodingHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableUnknownEncodingHandling ()
{
	XML_SetUnknownEncodingHandler(fParserHandle,_UnknownEncodingHandler,fParserHandle);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableUnknownEncodingHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableUnknownEncodingHandling ()
{
	XML_SetUnknownEncodingHandler(fParserHandle,NULL,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableElementDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableElementDeclHandling ()
{
	XML_SetElementDeclHandler(fParserHandle,_ElementDeclHandler);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableElementDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableElementDeclHandling ()
{
	XML_SetElementDeclHandler(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableAttlistDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableAttlistDeclHandling ()
{
	XML_SetAttlistDeclHandler(fParserHandle,_AttlistDeclHandler);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableAttlistDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableAttlistDeclHandling ()
{
	XML_SetAttlistDeclHandler(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::EnableXMLDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::EnableXMLDeclHandling ()
{
	XML_SetXmlDeclHandler(fParserHandle,_XMLDeclHandler);
}

//---------------------------------------------------------------------
// TExpatBaseObj::DisableXMLDeclHandling
//---------------------------------------------------------------------
void TExpatBaseObj::DisableXMLDeclHandling ()
{
	XML_SetXmlDeclHandler(fParserHandle,NULL);
}

//---------------------------------------------------------------------
// TExpatBaseObj::ElementHandler_Start
//---------------------------------------------------------------------
void TExpatBaseObj::ElementHandler_Start (const std::string& name,
										  const ExpatAttributeMap& specificAttributeMap,
										  const ExpatAttributeMap& inheritedAttributeMap)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::ElementHandler_End
//---------------------------------------------------------------------
void TExpatBaseObj::ElementHandler_End (const std::string& name)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::CharacterDataHandler
//---------------------------------------------------------------------
void TExpatBaseObj::CharacterDataHandler (const std::string& data)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::ProcessingInstructionHandler
//---------------------------------------------------------------------
void TExpatBaseObj::ProcessingInstructionHandler (const std::string& target, const std::string& data)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::CommentHandler
//---------------------------------------------------------------------
void TExpatBaseObj::CommentHandler (const std::string& data)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::CDataSectionHandler_Start
//---------------------------------------------------------------------
void TExpatBaseObj::CDataSectionHandler_Start ()
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::CDataSectionHandler_End
//---------------------------------------------------------------------
void TExpatBaseObj::CDataSectionHandler_End ()
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::DefaultHandler
//---------------------------------------------------------------------
void TExpatBaseObj::DefaultHandler (const std::string& data)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::DefaultExpandHandler
//---------------------------------------------------------------------
void TExpatBaseObj::DefaultExpandHandler (const std::string& data)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::DoctypeDeclHandler_Start
//---------------------------------------------------------------------
void TExpatBaseObj::DoctypeDeclHandler_Start (const std::string& doctypeName,
											  const std::string& sysID,
											  const std::string& pubID,
											  bool hasInternalSubset)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::DoctypeDeclHandler_End
//---------------------------------------------------------------------
void TExpatBaseObj::DoctypeDeclHandler_End ()
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::UnparsedEntityDeclHandler
//---------------------------------------------------------------------
void TExpatBaseObj::UnparsedEntityDeclHandler (const std::string& entityName,
											   const std::string& base,
											   const std::string& systemID,
											   const std::string& publicID,
											   const std::string& notationName)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::NotationDeclHandler
//---------------------------------------------------------------------
void TExpatBaseObj::NotationDeclHandler (const std::string& notationName,
										 const std::string& base,
										 const std::string& systemID,
										 const std::string& publicID)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::NamespaceDeclHandler_Start
//---------------------------------------------------------------------
void TExpatBaseObj::NamespaceDeclHandler_Start (const std::string& prefix, const std::string& uri)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::NamespaceDeclHandler_End
//---------------------------------------------------------------------
void TExpatBaseObj::NamespaceDeclHandler_End (const std::string& prefix)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::ExternalEntityRefHandler
//---------------------------------------------------------------------
int TExpatBaseObj::ExternalEntityRefHandler (const std::string& context,
											 const std::string& base,
											 const std::string& systemID,
											 const std::string& publicID)
{
	int		result = XML_STATUS_ERROR;
	
	return result;
}

//---------------------------------------------------------------------
// TExpatBaseObj::SkippedEntityHandler
//---------------------------------------------------------------------
void TExpatBaseObj::SkippedEntityHandler (const std::string& entityName, bool isParameterEntity)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::UnknownEncodingHandler
//---------------------------------------------------------------------
int TExpatBaseObj::UnknownEncodingHandler (const std::string& name, XML_Encoding* info)
{
	int		result = XML_STATUS_ERROR;
	
	return result;
}

//---------------------------------------------------------------------
// TExpatBaseObj::ElementDeclHandler
//---------------------------------------------------------------------
void TExpatBaseObj::ElementDeclHandler (const std::string& name, const XML_Content* model)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::AttlistDeclHandler
//---------------------------------------------------------------------
void TExpatBaseObj::AttlistDeclHandler (const std::string& tagName,
										const std::string& attributeName,
										const std::string& attributeType,
										const std::string& defaultValue,
										bool isRequired)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::XMLDeclHandler
//---------------------------------------------------------------------
void TExpatBaseObj::XMLDeclHandler (const std::string& version,
									const std::string& encoding,
									XMLDeclStandalone standaloneType)
{
}

//---------------------------------------------------------------------
// TExpatBaseObj::LibraryVersion (static)
//---------------------------------------------------------------------
std::string TExpatBaseObj::LibraryVersion ()
{
	return std::string(XML_ExpatVersion());
}

//---------------------------------------------------------------------
// TExpatBaseObj::GetFeatureList (static)
//---------------------------------------------------------------------
void TExpatBaseObj::GetFeatureList (ExpatFeatureList& featureList)
{
	const XML_Feature*	featureArray = XML_GetFeatureList();
	
	featureList.clear();
	
	if (featureArray)
	{
		int		index = 0;
		
		while (featureArray[index].feature != XML_FEATURE_END)
		{
			featureList.push_back(featureArray[index]);
			++index;
		}
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::ErrorCodeDescription (static)
//---------------------------------------------------------------------
std::string TExpatBaseObj::ErrorCodeDescription (const XML_Error& errorCode)
{
	return std::string(XML_ErrorString(errorCode));
}

//---------------------------------------------------------------------
// TExpatBaseObj::_ElementHandler_Start (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_ElementHandler_Start (void* userData,
										   const XML_Char* name,
										   const XML_Char** attributeArray)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
		{
			ExpatAttributeMap		specificAttributeMap;
			ExpatAttributeMap		inheritedAttributeMap;
			
			if (attributeArray)
			{
				int		specificCount = XML_GetSpecifiedAttributeCount(parserHandle);
				int		index = 0;
				
				while (attributeArray[index] != 0 && index < specificCount)
				{
					specificAttributeMap[attributeArray[index]] = attributeArray[index+1];
					index += 2;
				}
				
				while (attributeArray[index] != 0)
				{
					inheritedAttributeMap[attributeArray[index]] = attributeArray[index+1];
					index += 2;
				}
			}
			
			foundExpatObjPtr->ElementHandler_Start(std::string(name),specificAttributeMap,inheritedAttributeMap);
		}
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_ElementHandler_End (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_ElementHandler_End (void* userData, const XML_Char* name)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->ElementHandler_End(std::string(name));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_CharacterDataHandler (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_CharacterDataHandler (void* userData,
										   const XML_Char* s,
										   int len)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
		{
			std::string		data(s,static_cast<unsigned long>(len));
			
			if (foundExpatObjPtr->fAutoTrimCharData)
			{
				while (!data.empty() && isspace(data[data.length()-1]))
					data.resize(data[data.length()-1]);
				
				while (!data.empty() && isspace(data[0]))
					data.erase(0);
			}
			
			if (!data.empty() || foundExpatObjPtr->fPassEmptyCharData)
				foundExpatObjPtr->CharacterDataHandler(data);
		}
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_ProcessingInstructionHandler (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_ProcessingInstructionHandler (void* userData,
												   const XML_Char* target,
												   const XML_Char* data)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->ProcessingInstructionHandler(std::string(target),std::string(data));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_CommentHandler (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_CommentHandler (void* userData, const XML_Char* data)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->CommentHandler(std::string(data));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_CDataSectionHandler_Start (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_CDataSectionHandler_Start (void* userData)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->CDataSectionHandler_Start();
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_CDataSectionHandler_End (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_CDataSectionHandler_End (void* userData)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->CDataSectionHandler_End();
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_DefaultHandler (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_DefaultHandler (void* userData,
									 const XML_Char* s,
									 int len)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->DefaultHandler(std::string(s,static_cast<unsigned long>(len)));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_DefaultExpandHandler (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_DefaultExpandHandler (void* userData,
										   const XML_Char* s,
										   int len)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->DefaultExpandHandler(std::string(s,static_cast<unsigned long>(len)));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_DoctypeDeclHandler_Start (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_DoctypeDeclHandler_Start (void* userData,
											   const XML_Char* doctypeName,
											   const XML_Char* sysid,
											   const XML_Char* pubid,
											   int has_internal_subset)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->DoctypeDeclHandler_Start(std::string(doctypeName),
													   std::string(sysid),
													   std::string(pubid),
													   (has_internal_subset != 0 ? true : false));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_DoctypeDeclHandler_End (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_DoctypeDeclHandler_End (void* userData)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->DoctypeDeclHandler_End();
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_UnparsedEntityDeclHandler (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_UnparsedEntityDeclHandler (void* userData,
												const XML_Char* entityName,
												const XML_Char* base,
												const XML_Char* systemId,
												const XML_Char* publicId,
												const XML_Char* notationName)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->UnparsedEntityDeclHandler(std::string(entityName),
														std::string(base),
														std::string(systemId),
														std::string(publicId),
														std::string(notationName));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_NotationDeclHandler (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_NotationDeclHandler (void* userData,
										  const XML_Char* notationName,
										  const XML_Char* base,
										  const XML_Char* systemId,
										  const XML_Char* publicId)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->NotationDeclHandler(std::string(notationName),
												  std::string(base),
												  std::string(systemId),
												  std::string(publicId));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_NamespaceDeclHandler_Start (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_NamespaceDeclHandler_Start (void* userData,
												 const XML_Char* prefix,
												 const XML_Char* uri)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->NamespaceDeclHandler_Start(std::string(prefix),std::string(uri));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_NamespaceDeclHandler_End (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_NamespaceDeclHandler_End (void* userData, const XML_Char* prefix)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->NamespaceDeclHandler_End(std::string(prefix));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_ExternalEntityRefHandler (protected static)
//---------------------------------------------------------------------
int TExpatBaseObj::_ExternalEntityRefHandler (XML_Parser parser,
											  const XML_Char* context,
											  const XML_Char* base,
											  const XML_Char* systemId,
											  const XML_Char* publicId)
{
	int								result = XML_STATUS_ERROR;
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parser);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			result = foundExpatObjPtr->ExternalEntityRefHandler(std::string(context),
																std::string(base),
																std::string(systemId),
																std::string(publicId));
	}
	
	return result;
}

//---------------------------------------------------------------------
// TExpatBaseObj::_SkippedEntityHandler (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_SkippedEntityHandler (void *userData,
										   const XML_Char *entityName,
										   int is_parameter_entity)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->SkippedEntityHandler(std::string(entityName),
												   (is_parameter_entity != 0 ? true : false));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_UnknownEncodingHandler (protected static)
//---------------------------------------------------------------------
int TExpatBaseObj::_UnknownEncodingHandler (void* encodingHandlerData,
											const XML_Char* name,
											XML_Encoding* info)
{
	int								result = XML_STATUS_ERROR;
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(encodingHandlerData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			result = foundExpatObjPtr->UnknownEncodingHandler(std::string(name),info);
	}
	
	return result;
}

//---------------------------------------------------------------------
// TExpatBaseObj::_ElementDeclHandler (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_ElementDeclHandler (void* userData,
										 const XML_Char* name,
										 XML_Content* model)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
		{
			foundExpatObjPtr->fXMLContentPtrList.push_back(model);
			foundExpatObjPtr->ElementDeclHandler(std::string(name),model);
		}
		else
		{
			if (model != NULL)
				XML_FreeContentModel(parserHandle,model);
		}
	}
	else
	{
		if (model != NULL)
			XML_FreeContentModel(parserHandle,model);
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_AttlistDeclHandler (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_AttlistDeclHandler (void* userData,
										 const XML_Char* elname,
										 const XML_Char* attname,
										 const XML_Char* att_type,
										 const XML_Char* dflt,
										 int isrequired)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
			foundExpatObjPtr->AttlistDeclHandler(std::string(elname),
												 std::string(attname),
												 std::string(att_type),
												 std::string(dflt),
												 (isrequired != 0 ? true : false));
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_XMLDeclHandler (protected static)
//---------------------------------------------------------------------
void TExpatBaseObj::_XMLDeclHandler (void* userData,
									 const XML_Char* version,
									 const XML_Char* encoding,
									 int standalone)
{
	XML_Parser						parserHandle = reinterpret_cast<XML_Parser>(userData);
	TExpatObjPtrInstanceMap_iter	foundObjIter = gInstanceMapPtr->Get(parserHandle);
	
	if (foundObjIter != gInstanceMapPtr->End())
	{
		TExpatBaseObj*	foundExpatObjPtr = foundObjIter->second;
		
		if (foundExpatObjPtr)
		{
			XMLDeclStandalone	standaloneType;
			
			switch (standalone)
			{
				case -1:	standaloneType = kXMLDeclStandaloneUnknown;		break;
				case 0:		standaloneType = kXMLDeclStandaloneNo;			break;
				case 1:		standaloneType = kXMLDeclStandaloneYes;			break;
				default:	standaloneType = kXMLDeclStandaloneUnknown;		break;
			}
			
			foundExpatObjPtr->XMLDeclHandler(std::string(version),
											 std::string(encoding),
											 standaloneType);
		}
	}
}

//---------------------------------------------------------------------
// TExpatBaseObj::_ClearInternalList (protected)
//---------------------------------------------------------------------
void TExpatBaseObj::_ClearInternalList ()
{
	while (!fXMLContentPtrList.empty())
	{
		XML_FreeContentModel(fParserHandle,fXMLContentPtrList.back());
		fXMLContentPtrList.pop_back();
	}
	
	while (!fExternalExpatObjPtrList.empty())
	{
		delete(fExternalExpatObjPtrList.back());
		fExternalExpatObjPtrList.pop_back();
	}
}

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

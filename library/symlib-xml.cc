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
#		Created:					28 Oct 2003
#		Last Modified:				23 May 2005
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-xml.h"

#include "symlib-utils.h"

#include <unistd.h>

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TXMLNodeObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TXMLNodeObj::TXMLNodeObj ()
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TXMLNodeObj::TXMLNodeObj (const std::string& tag)
	:	fTag(tag)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TXMLNodeObj::TXMLNodeObj (const std::string& tag, const std::string& data)
	:	fTag(tag),
		fData(data)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TXMLNodeObj::TXMLNodeObj (const TXMLNodeObj& obj)
	:	fTag(obj.fTag),
		fData(obj.fData),
		fAttributes(obj.fAttributes)
{
	for (TXMLNodeObjList_const_iter x = obj.fTXMLNodeObjList.begin(); x != obj.fTXMLNodeObjList.end(); x++)
		fTXMLNodeObjList.push_back(new TXMLNodeObj(**x));
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TXMLNodeObj::~TXMLNodeObj ()
{
	Reset();
}

//---------------------------------------------------------------------
// TXMLNodeObj::Reset
//---------------------------------------------------------------------
void TXMLNodeObj::Reset ()
{
	fTag.clear();
	fData.clear();
	fAttributes.clear();
	
	while (!fTXMLNodeObjList.empty())
	{
		delete(fTXMLNodeObjList.back());
		fTXMLNodeObjList.pop_back();
	}
}

//---------------------------------------------------------------------
// TXMLNodeObj::Append
//---------------------------------------------------------------------
const TXMLNodeObj* TXMLNodeObj::Append (const TXMLNodeObj* nodeObjPtr)
{
	fTXMLNodeObjList.push_back(const_cast<TXMLNodeObj*>(nodeObjPtr));
	
	return nodeObjPtr;
}

//---------------------------------------------------------------------
// TXMLNodeObj::Append
//---------------------------------------------------------------------
const TXMLNodeObj* TXMLNodeObj::Append (const std::string& tag)
{
	return Append(new TXMLNodeObj(tag));
}

//---------------------------------------------------------------------
// TXMLNodeObj::Append
//---------------------------------------------------------------------
const TXMLNodeObj* TXMLNodeObj::Append (const std::string& tag, const std::string& data)
{
	return Append(new TXMLNodeObj(tag,data));
}

//---------------------------------------------------------------------
// TXMLNodeObj::FindNode
//---------------------------------------------------------------------
const TXMLNodeObj* TXMLNodeObj::FindNode (const std::string& tag,
										  const std::string& attribute,
										  const std::string& attributeValue) const
{
	TXMLNodeObj*	foundNodePtr = NULL;
	
	if (Tag() == tag)
	{
		if (attribute == "")
		{
			foundNodePtr = const_cast<TXMLNodeObj*>(this);
		}
		else
		{
			ExpatAttributeMap_const_iter	foundAttrIter = fAttributes.find(attribute);
			
			if (foundAttrIter != fAttributes.end() && foundAttrIter->second == attributeValue)
			{
				foundNodePtr = const_cast<TXMLNodeObj*>(this);
			}
		}
	}
	
	if (!foundNodePtr && IsList())
	{
		for (TXMLNodeObjList_const_iter y = fTXMLNodeObjList.begin(); y != fTXMLNodeObjList.end(); y++)
		{
			if (*y)
			{
				foundNodePtr = const_cast<TXMLNodeObj*>((*y)->FindNode(tag,attribute,attributeValue));
				if (foundNodePtr)
					break;
			}
		}
	}
	
	return foundNodePtr;
}

//---------------------------------------------------------------------
// TXMLNodeObj::GetData
//---------------------------------------------------------------------
std::string TXMLNodeObj::GetData (const std::string& tag,
								  const std::string& attribute,
								  const std::string& attributeValue) const
{
	std::string			data;
	const TXMLNodeObj*	foundNodePtr = FindNode(tag,attribute,attributeValue);
	
	if (foundNodePtr && foundNodePtr->IsSimple())
		data = foundNodePtr->Data();
	
	return data;
}

//---------------------------------------------------------------------
// TXMLNodeObj::AsString
//---------------------------------------------------------------------
std::string TXMLNodeObj::AsString (const std::string& indent, const std::string& lineDelimiter) const
{
	return _AsString(indent,lineDelimiter,0);
}

//---------------------------------------------------------------------
// TXMLNodeObj::_AsString (protected)
//---------------------------------------------------------------------
std::string TXMLNodeObj::_AsString (const std::string& indent,
									const std::string& lineDelimiter,
									unsigned int depth) const
{
	std::string			output;
	
	if (!indent.empty())
	{
		for (unsigned int x = 0; x < depth; x++)
			output += indent;
	}
	
	if (IsBool())
	{
		output += "<" + _EscapeForXML(Tag()) + "/>" + lineDelimiter;
	}
	else
	{
		std::string		data(Data());
		
		output += "<" + Tag();
		for (ExpatAttributeMap_const_iter y = fAttributes.begin(); y != fAttributes.end(); y++)
			output += " " + y->first + "=\"" + _EscapeForXML(y->second) + "\"";
		
		if (!IsList() && data.empty())
		{
			// Nothing more
			output += "/>" + lineDelimiter;
		}
		else
		{
			output += ">";
			
			if (IsList())
			{
				output += lineDelimiter;
				for (TXMLNodeObjList_const_iter y = fTXMLNodeObjList.begin(); y != fTXMLNodeObjList.end(); y++)
					output += (*y)->_AsString(indent,lineDelimiter,depth + 1);
				if (!indent.empty())
				{
					for (unsigned int x = 0; x < depth; x++)
						output += indent;
				}
			}
			else
			{
				output += Data();
			}
			
			output += "</" + Tag() + ">" + lineDelimiter;
		}
	}
	
	return output;
}

//---------------------------------------------------------------------
// TXMLNodeObj::_EscapeForXML (static protected)
//---------------------------------------------------------------------
std::string TXMLNodeObj::_EscapeForXML (const std::string& s)
{
	std::string		newString;
	
	for (unsigned long x = 0; x < s.length(); x++)
	{
		switch (s[x])
		{
			case '<':
				newString += "&lt;";
				break;
			
			case '>':
				newString += "&gt;";
				break;
			
			case '&':
				newString += "&amp;";
				break;
			
			case '"':
				newString += "&quot;";
				break;
			
			default:
				newString.push_back(s[x]);
				break;
		}
	}
	
	return newString;
}

//*********************************************************************
// Class TConfigXMLObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TConfigXMLObj::TConfigXMLObj ()
	:	Inherited(),
		fRootNodePtr(NULL)
{
	EnableElementHandling();
	EnableCharacterDataHandling(true,false); // auto-trim, don't pass empty data
	EnableCDataSectionHandling();
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TConfigXMLObj::TConfigXMLObj (const TConfigXMLObj& obj)
	:	Inherited(),
		fRootNodePtr(obj.fRootNodePtr),
		fParseStack(obj.fParseStack)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TConfigXMLObj::~TConfigXMLObj ()
{
}

//---------------------------------------------------------------------
// TConfigXMLObj::Reset
//---------------------------------------------------------------------
void TConfigXMLObj::Reset ()
{
	Inherited::Reset();
	fRootNodePtr = NULL;
	fParseStack.clear();
}

//---------------------------------------------------------------------
// TConfigXMLObj::ParseConfig
//---------------------------------------------------------------------
bool TConfigXMLObj::ParseConfig (TFileObj& fileObj, TXMLNodeObj& rootNodeObj)
{
	bool		wasLoaded = true;
	XML_Status	parseStatus = XML_STATUS_OK;
	
	fRootNodePtr = &rootNodeObj;
	
	parseStatus = Parse(fileObj);
	if (parseStatus != XML_STATUS_OK)
		wasLoaded = false;
	
	return wasLoaded;
}

//---------------------------------------------------------------------
// TConfigXMLObj::ParseConfig
//---------------------------------------------------------------------
bool TConfigXMLObj::ParseConfig (const std::string& bufferObj, TXMLNodeObj& rootNodeObj)
{
	bool		wasLoaded = true;
	XML_Status	parseStatus = XML_STATUS_OK;
	
	fRootNodePtr = &rootNodeObj;
	
	parseStatus = Parse(bufferObj);
	if (parseStatus != XML_STATUS_OK)
		wasLoaded = false;
	
	return wasLoaded;
}

//---------------------------------------------------------------------
// TConfigXMLObj::ElementHandler_Start
//---------------------------------------------------------------------
void TConfigXMLObj::ElementHandler_Start (const std::string& name,
										  const ExpatAttributeMap& specificAttributeMap,
										  const ExpatAttributeMap& inheritedAttributeMap)
{
	fParseStack.push_back(new TXMLNodeObj(name));
	
	for (ExpatAttributeMap_const_iter x = inheritedAttributeMap.begin(); x != inheritedAttributeMap.end(); x++)
		fParseStack.back()->AddAttribute(x->first,x->second);
	
	for (ExpatAttributeMap_const_iter x = specificAttributeMap.begin(); x != specificAttributeMap.end(); x++)
		fParseStack.back()->AddAttribute(x->first,x->second);
}

//---------------------------------------------------------------------
// TConfigXMLObj::ElementHandler_End
//---------------------------------------------------------------------
void TConfigXMLObj::ElementHandler_End (const std::string& name)
{
	TXMLNodeObj*	currentNodePtr(fParseStack.back());
	
	fParseStack.pop_back();
	
	if (fParseStack.empty())
		*fRootNodePtr = *currentNodePtr;
	else
		fParseStack.back()->Append(currentNodePtr);
}

//---------------------------------------------------------------------
// TConfigXMLObj::CharacterDataHandler
//---------------------------------------------------------------------
void TConfigXMLObj::CharacterDataHandler (const std::string& data)
{
	fParseStack.back()->SetData(data);
}

//---------------------------------------------------------------------
// TConfigXMLObj::CDataSectionHandler_Start
//---------------------------------------------------------------------
void TConfigXMLObj::CDataSectionHandler_Start ()
{
}

//---------------------------------------------------------------------
// TConfigXMLObj::CDataSectionHandler_End
//---------------------------------------------------------------------
void TConfigXMLObj::CDataSectionHandler_End ()
{
}

//---------------------------------------------------------------------
// TConfigXMLObj::_NewObject (protected)
//---------------------------------------------------------------------
TConfigXMLObj* TConfigXMLObj::_NewObject () const
{
	return new TConfigXMLObj;
}

//*********************************************************************
// Class TSymbiotMessageBase
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSymbiotMessageBase::TSymbiotMessageBase ()
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSymbiotMessageBase::TSymbiotMessageBase (const std::string& topLevelTag,
										  const std::string& attribute,
										  const std::string& attributeValue)
{
	fXMLMessage.SetTag(topLevelTag);
	
	if (!attribute.empty())
		fXMLMessage.AddAttribute(attribute,attributeValue);
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TSymbiotMessageBase::TSymbiotMessageBase (const TSymbiotMessageBase& obj)
	:	fXMLMessage(obj.fXMLMessage)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TSymbiotMessageBase::~TSymbiotMessageBase ()
{
	Reset();
}

//---------------------------------------------------------------------
// TSymbiotMessageBase::Reset
//---------------------------------------------------------------------
void TSymbiotMessageBase::Reset ()
{
	fXMLMessage.Reset();
}

//---------------------------------------------------------------------
// TSymbiotMessageBase::Parse
//---------------------------------------------------------------------
void TSymbiotMessageBase::Parse (const std::string& data)
{
	TMessageParser		parserObj;
	
	parserObj.ParseBuffer(data,fXMLMessage);
}

//---------------------------------------------------------------------
// TSymbiotMessageBase::Append
//---------------------------------------------------------------------
const TXMLNodeObj* TSymbiotMessageBase::Append (const TXMLNodeObj* nodeObjPtr)
{
	return fXMLMessage.Append(nodeObjPtr);
}

//---------------------------------------------------------------------
// TSymbiotMessageBase::Append
//---------------------------------------------------------------------
const TXMLNodeObj* TSymbiotMessageBase::Append (const std::string& tag)
{
	return fXMLMessage.Append(new TXMLNodeObj(tag));
}

//---------------------------------------------------------------------
// TSymbiotMessageBase::Append
//---------------------------------------------------------------------
const TXMLNodeObj* TSymbiotMessageBase::Append (const std::string& tag, const std::string& data)
{
	return fXMLMessage.Append(new TXMLNodeObj(tag,data));
}

//---------------------------------------------------------------------
// TSymbiotMessageBase::AddAttribute
//---------------------------------------------------------------------
void TSymbiotMessageBase::AddAttribute (const std::string& attribute, const std::string& attributeValue)
{
	return fXMLMessage.AddAttribute(attribute,attributeValue);
}

//---------------------------------------------------------------------
// TSymbiotMessageBase::FindNode
//---------------------------------------------------------------------
const TXMLNodeObj* TSymbiotMessageBase::FindNode (const std::string& tag,
												  const std::string& attribute,
												  const std::string& attributeValue) const
{
	return fXMLMessage.FindNode(tag,attribute,attributeValue);
}

//---------------------------------------------------------------------
// TSymbiotMessageBase::GetData
//---------------------------------------------------------------------
std::string TSymbiotMessageBase::GetData (const std::string& tag,
										  const std::string& attribute,
										  const std::string& attributeValue) const
{
	return fXMLMessage.GetData(tag,attribute,attributeValue);
}

//---------------------------------------------------------------------
// TSymbiotMessageBase::AsString
//---------------------------------------------------------------------
std::string TSymbiotMessageBase::AsString (const std::string& indent, const std::string& lineDelimiter) const
{
	return fXMLMessage.AsString(indent,lineDelimiter);
}

//---------------------------------------------------------------------
// TSymbiotMessageBase::AsCompressedString
//---------------------------------------------------------------------
std::string TSymbiotMessageBase::AsCompressedString () const
{
	return AsString("","");
}

//*********************************************************************
// Global Functions
//*********************************************************************

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

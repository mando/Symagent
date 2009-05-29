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
#		Created:					17 Sep 2003
#		Last Modified:				26 Feb 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-message.h"

#include "symlib-utils.h"
#include "symlib-xml.h"

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//*********************************************************************
// Class TMessageNode
//*********************************************************************

//---------------------------------------------------------------------
// Global helper functions for TMessageNode -- module-only level
//---------------------------------------------------------------------

TXMLNodeObj* _ConvertMessageNodeObj (const TMessageNode* p);			// Declaration
TXMLNodeObj* _ConvertMessageNodeObj (const TMessageNode* p)
	{ return static_cast<TXMLNodeObj*>(const_cast<TMessageNode*>(p)->GetPtr()); }

TXMLNodeObj* _ConvertMessageNodeObj (const TMessageNode& p);			// Declaration
TXMLNodeObj* _ConvertMessageNodeObj (const TMessageNode& p)
	{ return static_cast<TXMLNodeObj*>(p.GetPtr()); }

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TMessageNode::TMessageNode ()
	:	fNodePtr(NULL)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TMessageNode::TMessageNode (const TMessageNode& obj)
	:	fNodePtr(obj.fNodePtr)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TMessageNode::~TMessageNode ()
{
}

//---------------------------------------------------------------------
// TMessageNode::IsValid
//---------------------------------------------------------------------
bool TMessageNode::IsValid () const
{
	return (fNodePtr != NULL);
}

//---------------------------------------------------------------------
// TMessageNode::SetPtr
//---------------------------------------------------------------------
void TMessageNode::SetPtr (const void* ptr)
{
	fNodePtr = static_cast<TXMLNodeObj*>(const_cast<void*>(ptr));
}

//---------------------------------------------------------------------
// TMessageNode::GetPtr
//---------------------------------------------------------------------
void* TMessageNode::GetPtr () const
{
	return fNodePtr;
}

//---------------------------------------------------------------------
// TMessageNode::MarkNotLocal
//---------------------------------------------------------------------
void TMessageNode::MarkNotLocal ()
{
}

//---------------------------------------------------------------------
// TMessageNode::Append
//---------------------------------------------------------------------
TMessageNode TMessageNode::Append (const std::string& tag,
								   const std::string& attribute,
								   const std::string& attributeValue,
								   const std::string& data)
{
	TMessageNode	nodeRef;
	
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		
		if (thisNodePtr)
		{
			TXMLNodeObj*	newNodePtr = const_cast<TXMLNodeObj*>(thisNodePtr->Append(tag,data));
			
			if (newNodePtr)
			{
				if (!attribute.empty())
					newNodePtr->AddAttribute(attribute,attributeValue);
				
				nodeRef.SetPtr(newNodePtr);
			}
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return nodeRef;
}

//---------------------------------------------------------------------
// TMessageNode::Append
//---------------------------------------------------------------------
TMessageNode TMessageNode::Append (TMessageNode& messageNode)
{
	TMessageNode	nodeRef;
	
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		TXMLNodeObj*	otherNodePtr = _ConvertMessageNodeObj(&messageNode);
		
		if (thisNodePtr && otherNodePtr)
		{
			TXMLNodeObj*	newNodePtr = const_cast<TXMLNodeObj*>(thisNodePtr->Append(otherNodePtr));
			
			if (newNodePtr)
			{
				nodeRef.SetPtr(newNodePtr);
				messageNode.MarkNotLocal();
			}
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return nodeRef;
}

//---------------------------------------------------------------------
// TMessageNode::AddAttribute
//---------------------------------------------------------------------
void TMessageNode::AddAttribute (const std::string& newAttribute,
								 const std::string& newAttributeValue)
{
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		
		if (thisNodePtr)
			thisNodePtr->AddAttribute(newAttribute,newAttributeValue);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// TMessageNode::GetAttributeValue
//---------------------------------------------------------------------
std::string TMessageNode::GetAttributeValue (const std::string& attribute) const
{
	std::string		data;
	
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		
		if (thisNodePtr)
			data = thisNodePtr->AttributeValue(attribute);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return data;
}

//---------------------------------------------------------------------
// TMessageNode::SetTag
//---------------------------------------------------------------------
void TMessageNode::SetTag (const std::string& newTag)
{
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		
		if (thisNodePtr)
			thisNodePtr->SetTag(newTag);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// TMessageNode::GetTag
//---------------------------------------------------------------------
std::string TMessageNode::GetTag () const
{
	std::string		tag;
	
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		
		if (thisNodePtr)
			tag = thisNodePtr->Tag();
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return tag;
}

//---------------------------------------------------------------------
// TMessageNode::SetData
//---------------------------------------------------------------------
void TMessageNode::SetData (const std::string& data)
{
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		
		if (thisNodePtr)
			thisNodePtr->SetData(data);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// TMessageNode::GetData
//---------------------------------------------------------------------
std::string TMessageNode::GetData () const
{
	std::string		data;
	
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		
		if (thisNodePtr)
			data = thisNodePtr->Data();
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return data;
}

//---------------------------------------------------------------------
// TMessageNode::SubnodeCount
//---------------------------------------------------------------------
unsigned long TMessageNode::SubnodeCount () const
{
	unsigned long		count = 0;
	
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		
		if (thisNodePtr)
			count = thisNodePtr->SubnodeCount();
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return count;
}

//---------------------------------------------------------------------
// TMessageNode::GetNthSubnode
//---------------------------------------------------------------------
TMessageNode TMessageNode::GetNthSubnode (unsigned long n) const
{
	TMessageNode	nodeRef;
	
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		
		if (thisNodePtr)
		{
			TXMLNodeObj*	nodePtr = const_cast<TXMLNodeObj*>(thisNodePtr->NthSubnode(n));
			
			if (nodePtr)
				nodeRef.SetPtr(nodePtr);
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return nodeRef;
}

//*********************************************************************
// Class TMessage
//*********************************************************************

//---------------------------------------------------------------------
// Global helper functions for TMessage -- module-only level
//---------------------------------------------------------------------

TSymbiotMessageBase* _ConvertMessageObjPtr (void* ptr);		// Declaration
TSymbiotMessageBase* _ConvertMessageObjPtr (void* ptr)
{
	return static_cast<TSymbiotMessageBase*>(ptr);
}

//---------------------------------------------------------------------
// Constructor (protected)
//---------------------------------------------------------------------
TMessage::TMessage ()
{
	fMessageObjPtr = new TSymbiotMessageBase;
}

//---------------------------------------------------------------------
// Constructor (protected)
//---------------------------------------------------------------------
TMessage::TMessage (const std::string& topLeveltag)
{
	TSymbiotMessageBase*	newMessagePtr = NULL;
	TXMLNodeObj*			rootNodePtr = NULL;
	std::string				timeNowStr;
	unsigned long long		millisecond;
	
	millisecond = static_cast<unsigned long long>(CurrentMilliseconds() * 1000);
	
	newMessagePtr = new TSymbiotMessageBase(topLeveltag);
	
	// Add attributes common to all messages
	rootNodePtr = const_cast<TXMLNodeObj*>(newMessagePtr->RootNodePtr());
	timeNowStr = NumToString(millisecond);
	
	rootNodePtr->AddAttribute("agent_id",gEnvironObjPtr->AgentName());
	rootNodePtr->AddAttribute("plugin_id",gEnvironObjPtr->GetTaskName(false));
	rootNodePtr->AddAttribute(kMessageTagNonce,gEnvironObjPtr->ServerNonce());
	rootNodePtr->AddAttribute("platform",PLATFORM);
	rootNodePtr->AddAttribute("timestamp",timeNowStr);
	
	// Internally assign to the void*
	fMessageObjPtr = newMessagePtr;
}

//---------------------------------------------------------------------
// Constructor (protected)
//---------------------------------------------------------------------
TMessage::TMessage (const TMessage& obj)
{
	fMessageObjPtr = new TSymbiotMessageBase(*_ConvertMessageObjPtr(obj.fMessageObjPtr));
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TMessage::~TMessage ()
{
	TSymbiotMessageBase*	messageObjPtr = _ConvertMessageObjPtr(fMessageObjPtr);
	
	if (messageObjPtr)
		delete(messageObjPtr);
}

//---------------------------------------------------------------------
// TMessage::Reset
//---------------------------------------------------------------------
void TMessage::Reset ()
{
	try
	{
		TSymbiotMessageBase*	messageObjPtr = _ConvertMessageObjPtr(fMessageObjPtr);
		
		if (messageObjPtr)
			messageObjPtr->Reset();
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// TMessage::Parse
//---------------------------------------------------------------------
void TMessage::Parse (const std::string& data)
{
	try
	{
		TSymbiotMessageBase*	messageObjPtr = _ConvertMessageObjPtr(fMessageObjPtr);
		
		if (messageObjPtr)
			messageObjPtr->Parse(data);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// TMessage::Append
//---------------------------------------------------------------------
TMessageNode TMessage::Append (const std::string& tag,
							   const std::string& attribute,
							   const std::string& attributeValue,
							   const std::string& data)
{
	TMessageNode	nodeRef;
	
	try
	{
		TSymbiotMessageBase*	messageObjPtr = _ConvertMessageObjPtr(fMessageObjPtr);
		
		if (messageObjPtr)
		{
			TXMLNodeObj*	newNodePtr = const_cast<TXMLNodeObj*>(messageObjPtr->Append(tag,data));
			
			if (newNodePtr)
			{
				if (!attribute.empty())
					newNodePtr->AddAttribute(attribute,attributeValue);
				
				nodeRef.SetPtr(newNodePtr);
			}
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return nodeRef;
}

//---------------------------------------------------------------------
// TMessage::Append
//---------------------------------------------------------------------
TMessageNode TMessage::Append (TMessageNode& messageNode)
{
	TMessageNode	nodeRef;
	
	try
	{
		TSymbiotMessageBase*	messageObjPtr = _ConvertMessageObjPtr(fMessageObjPtr);
		TXMLNodeObj*			otherNodePtr = _ConvertMessageNodeObj(&messageNode);
		
		if (messageObjPtr && otherNodePtr)
		{
			TXMLNodeObj*	newNodePtr = const_cast<TXMLNodeObj*>(messageObjPtr->Append(otherNodePtr));
			
			if (newNodePtr)
			{
				nodeRef.SetPtr(newNodePtr);
				messageNode.MarkNotLocal();
			}
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return nodeRef;
}

//---------------------------------------------------------------------
// TMessage::AddAttribute
//---------------------------------------------------------------------
void TMessage::AddAttribute (const std::string& newAttribute,
							 const std::string& newAttributeValue)
{
	try
	{
		TSymbiotMessageBase*	messageObjPtr = _ConvertMessageObjPtr(fMessageObjPtr);
		
		if (messageObjPtr)
			messageObjPtr->AddAttribute(newAttribute,newAttributeValue);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
}

//---------------------------------------------------------------------
// TMessage::FindNode
//---------------------------------------------------------------------
TMessageNode TMessage::FindNode (const std::string& tag,
								 const std::string& attribute,
								 const std::string& attributeValue) const
{
	TMessageNode		nodeRef;
	
	try
	{
		TSymbiotMessageBase*	messageObjPtr = _ConvertMessageObjPtr(fMessageObjPtr);
		
		if (messageObjPtr)
		{
			TXMLNodeObj*	tempNodePtr = const_cast<TXMLNodeObj*>(messageObjPtr->FindNode(tag,attribute,attributeValue));
			
			if (tempNodePtr)
				nodeRef.SetPtr(tempNodePtr);
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return nodeRef;
}

//---------------------------------------------------------------------
// TMessage::AsString
//---------------------------------------------------------------------
std::string TMessage::AsString (const std::string& indent,
								const std::string& lineDelimiter) const
{
	std::string		s;
	
	try
	{
		TSymbiotMessageBase*	messageObjPtr = _ConvertMessageObjPtr(fMessageObjPtr);
		
		if (messageObjPtr)
			s = messageObjPtr->AsString(indent,lineDelimiter);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return s;
}

//---------------------------------------------------------------------
// TMessage::AsCompressedString
//---------------------------------------------------------------------
std::string TMessage::AsCompressedString () const
{
	return AsString("","");
}

//*********************************************************************
// Class TServerMessage
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TServerMessage::TServerMessage ()
	:	Inherited(kMessageRootTag)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TServerMessage::TServerMessage (const TServerMessage& obj)
	:	Inherited(obj)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TServerMessage::~TServerMessage ()
{
}

//*********************************************************************
// Class TServerReply
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TServerReply::TServerReply ()
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TServerReply::TServerReply (const TServerReply& obj)
	:	Inherited(obj)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TServerReply::~TServerReply ()
{
}

//*********************************************************************
// Class TPreferenceNode
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPreferenceNode::TPreferenceNode ()
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TPreferenceNode::TPreferenceNode (const Inherited& obj)
	:	Inherited(obj)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TPreferenceNode::~TPreferenceNode ()
{
}

//---------------------------------------------------------------------
// TPreferenceNode::FindNode
//---------------------------------------------------------------------
TPreferenceNode TPreferenceNode::FindNode (const std::string& tag,
										   const std::string& attribute,
										   const std::string& attributeValue) const
{
	TMessageNode		nodeRef;
	
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		
		if (thisNodePtr)
		{
			TXMLNodeObj*	tempNodePtr = const_cast<TXMLNodeObj*>(thisNodePtr->FindNode(tag,attribute,attributeValue));
			
			if (tempNodePtr)
				nodeRef.SetPtr(tempNodePtr);
		}
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return nodeRef;
}

//---------------------------------------------------------------------
// TPreferenceNode::AsString
//---------------------------------------------------------------------
std::string TPreferenceNode::AsString (const std::string& indent,
									   const std::string& lineDelimiter) const
{
	std::string		s;
	
	try
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		
		if (thisNodePtr)
			s = thisNodePtr->AsString(indent,lineDelimiter);
	}
	catch (TSymLibErrorObj& errObj)
	{
		if (!errObj.IsLogged())
		{
			WriteToErrorLogFile(errObj.GetDescription());
			errObj.MarkAsLogged();
		}
		throw;
	}
	catch (int errNum)
	{
		std::string			errString;
		TSymLibErrorObj		newErrObj(errNum);
		
		errString = "Generic Error: ";
		errString += NumToString(errNum);
		WriteToErrorLogFile(errString);
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	catch (...)
	{
		TSymLibErrorObj	newErrObj(-1,"Unknown error");
		
		WriteToErrorLogFile("Unknown Error...");
		
		newErrObj.MarkAsLogged();
		throw newErrObj;
	}
	
	return s;
}

//---------------------------------------------------------------------
// TPreferenceNode::AsCompressedString
//---------------------------------------------------------------------
std::string TPreferenceNode::AsCompressedString () const
{
	return AsString("","");
}

//*********************************************************************
// Class TLoginDataNode
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TLoginDataNode::TLoginDataNode ()
	:	Inherited(),
		fNodePtr(NULL),
		fIsLocal(false)
{
	fNodePtr = new TXMLNodeObj;
	fIsLocal = true;
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TLoginDataNode::TLoginDataNode (const std::string& tag,
							const std::string& attribute,
							const std::string& attributeValue)
	:	Inherited(),
		fNodePtr(NULL),
		fIsLocal(false)
{
	TXMLNodeObj*	newNode = new TXMLNodeObj(tag);
	
	if (!attribute.empty())
		newNode->AddAttribute(attribute,attributeValue);
	fNodePtr = newNode;
	fIsLocal = true;
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TLoginDataNode::TLoginDataNode (TLoginDataNode& obj)
	:	Inherited()
{
	if (fNodePtr)
		delete(static_cast<TXMLNodeObj*>(fNodePtr));
	fNodePtr = obj.fNodePtr;
	fIsLocal = true;
	obj.fIsLocal = false;
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TLoginDataNode::~TLoginDataNode ()
{
	if (fIsLocal)
	{
		TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
		if (thisNodePtr)
			delete(thisNodePtr);
		fNodePtr = NULL;
		fIsLocal = false;
	}
}

//---------------------------------------------------------------------
// TLoginDataNode::IsValid
//---------------------------------------------------------------------
bool TLoginDataNode::IsValid () const
{
	bool			valid = false;
	TXMLNodeObj*	thisNodePtr = _ConvertMessageNodeObj(this);
	
	if (thisNodePtr)
	{
		if (!thisNodePtr->Tag().empty() ||
			thisNodePtr->HasAttributes() ||
			!thisNodePtr->Data().empty() ||
			thisNodePtr->IsList())
		{
			valid = true;
		}
	}
	
	return valid;
}

//---------------------------------------------------------------------
// TLoginDataNode::GetPtr
//---------------------------------------------------------------------
void* TLoginDataNode::GetPtr () const
{
	return fNodePtr;
}

//---------------------------------------------------------------------
// TLoginDataNode::MarkNotLocal
//---------------------------------------------------------------------
void TLoginDataNode::MarkNotLocal ()
{
	fIsLocal = false;
}

//*********************************************************************
// Global Functions
//*********************************************************************

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

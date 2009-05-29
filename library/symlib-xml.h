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
#		Last Modified:				08 Feb 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_XML)
#define SYMLIB_XML

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-config.h"

#include "symlib-expat.h"
#include "symlib-file.h"

#include <vector>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TXMLNodeObj;
class TConfigXMLObj;
class TSymbiotMessageBase;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef std::vector<TXMLNodeObj*>			TXMLNodeObjList;
typedef TXMLNodeObjList::iterator			TXMLNodeObjList_iter;
typedef TXMLNodeObjList::const_iterator		TXMLNodeObjList_const_iter;

//---------------------------------------------------------------------
// Class TXMLNodeObj
//
// A basic class that provides a mechanism for storing and accessing
// XML-formatted data structures.  This is meant to be a rather opaque
// data structure, meaning that it does not expose introspective methods.
//
// Every instance of TXMLNodeObj is potentially a 'root node' for other,
// encapsulated nodes.
//---------------------------------------------------------------------
class TXMLNodeObj
{
	public:
		
		TXMLNodeObj ();
			// Constructor
		
		TXMLNodeObj (const std::string& tag);
			// Constructor
		
		TXMLNodeObj (const std::string& tag, const std::string& data);
			// Constructor
		
		TXMLNodeObj (const TXMLNodeObj& obj);
			// Constructor
		
		virtual ~TXMLNodeObj ();
			// Destructor
		
		virtual void Reset ();
			// Resets the object to empty values, including any objects
			// in the internal lists.
		
		virtual const TXMLNodeObj* Append (const TXMLNodeObj* nodeObjPtr);
			// Appends the given node to the internal list.  Returns a pointer
			// to the node just added.
		
		virtual const TXMLNodeObj* Append (const std::string& tag);
			// Appends a new node, containing only a tag, to the internal list.
			// Returns a pointer to the node just added.
		
		virtual const TXMLNodeObj* Append (const std::string& tag, const std::string& data);
			// Appends a new node, defined by the tag and data arguments,
			// to the internal list.  Returns a pointer to the node just added.
		
		virtual const TXMLNodeObj* FindNode (const std::string& tag,
											 const std::string& attribute = "",
											 const std::string& attributeValue = "") const;
			// Searches the node heirarchy beginning with the current node, using
			// the tag argument and optionally the attribute and attributeValue arguments
			// for a matching node.  Returns a pointer to the first matching node if
			// found, NULL otherwise.  Note that the search is case-insensitive.
		
		virtual std::string GetData (const std::string& tag,
									 const std::string& attribute = "",
									 const std::string& attributeValue = "") const;
			// Uses FindNode() to locate a matching node.  If found, and the node is 'simple',
			// then the data from that node is returned.
		
		virtual std::string AsString (const std::string& indent = "\t",
									  const std::string& lineDelimiter = "\n") const;
			// Returns a string containing a nicely-formatted version of the parsed nodes,
			// beginning with the current node.
		
		// -------------------------------------------
		// Accessors
		// -------------------------------------------
		
		inline std::string Tag () const
			{ return fTag; }
		
		inline void SetTag (const std::string& tag)
			{ fTag = tag; }
		
		inline std::string Data () const
			{ return fData; }
		
		inline void SetData (const std::string& data)
			{ fData = data; }
		
		inline void AddAttribute (const std::string& attribute, const std::string& value)
			{ fAttributes[attribute] = value; }
		
		inline bool HasAttributes () const
			{ return (fAttributes.size() > 0); }
		
		inline std::string AttributeValue (const std::string& attribute) const
			{
				std::string		value;
				
				if (!attribute.empty())
				{
					ExpatAttributeMap_const_iter	foundAttr = fAttributes.find(attribute);
					
					if (foundAttr != fAttributes.end())
						value = foundAttr->second;
				}
				
				return value;
			}
		
		inline bool IsSimple () const
			{ return (fTXMLNodeObjList.size() == 0); }
		
		inline bool IsList () const
			{ return (fTXMLNodeObjList.size() > 0); }
		
		inline bool IsBool () const
			{ return (IsSimple() && !HasAttributes() && fData.empty() && (fTag == "true" || fTag == "false")); }
		
		inline unsigned long SubnodeCount () const
			{ return fTXMLNodeObjList.size(); }
		
		inline const TXMLNodeObj* NthSubnode (unsigned long n) const
			{
				TXMLNodeObj*	nodePtr = NULL;
				
				if (n < fTXMLNodeObjList.size())
					nodePtr = const_cast<TXMLNodeObj*>(fTXMLNodeObjList[n]);
				
				return nodePtr;
			}
	
	protected:
		
		virtual std::string _AsString (const std::string& indent,
									   const std::string& lineDelimiter,
									   unsigned int depth) const;
			// Internal recursive method supporting AsString() public method.
		
		static std::string _EscapeForXML (const std::string& s);
			// Returns a rewrite of the argument with certain characters rewritten
			// as XML character entities.
	
	protected:
		
		std::string									fTag;
		std::string									fData;
		TXMLNodeObjList								fTXMLNodeObjList;
		ExpatAttributeMap							fAttributes;
};

//---------------------------------------------------------------------
// Class TConfigXMLObj
//
// Simple subclass of TExpatBaseObj that provides a mechanism for
// reading an XML-formatted configuration file and storing the parsed
// information into an accessible RAM-based structure (TXMLNodeObj).
//
// The typical usage is something like the following:
//
//		TXMLNodeObj			configRoot;
//		TConfigXMLObj		configParser;
//		TFileObj			configFile("my.conf");
//
//		configParser.ParseConfig(configFile,configRoot);
//
// After calling ParseConfig() the configRoot object will become the
// root node for the parsed information.
//---------------------------------------------------------------------
class TConfigXMLObj : public TExpatBaseObj
{
	protected:
		
		typedef		TExpatBaseObj					Inherited;
	
	public:
		
		TConfigXMLObj ();
			// Constructor
		
		TConfigXMLObj (const TConfigXMLObj& obj);
			// Copy constructor
		
		virtual ~TConfigXMLObj ();
			// Destructor
		
		virtual void Reset ();
			// Resets the object.
		
		virtual bool ParseConfig (TFileObj& fileObj, TXMLNodeObj& rootNodeObj);
			// Parses the file pointed to by the fileObj argument, placing the results
			// into the rootNodeObj argument (which becomes the root of the parsed file).
			// Returns a boolean indicating success or failure of the parse.
		
		virtual bool ParseConfig (const std::string& bufferObj, TXMLNodeObj& rootNodeObj);
			// Parses the contents of the bufferObj argument as configuration data, placing
			// the results into the rootNodeObj argument (which becomes the root of the
			// parsed information).  Returns a boolean indicating success or failure of
			// the parse.
		
		virtual void ElementHandler_Start (const std::string& name,
										   const ExpatAttributeMap& specificAttributeMap,
										   const ExpatAttributeMap& inheritedAttributeMap);
			// Override.
		
		virtual void ElementHandler_End (const std::string& name);
			// Override.
		
		virtual void CharacterDataHandler (const std::string& data);
			// Override.
		
		virtual void CDataSectionHandler_Start ();
			// Override.  Note that this doesn't do anything; it's presence simply tells
			// the expat library to strip the "<![CDATA[" prefix from the data.  The data
			// is still handled by CharacterDataHandler().
		
		virtual void CDataSectionHandler_End ();
			// Override.  Note that this doesn't do anything; it's presence simply tells
			// the expat library to strip the "]]>" suffix from the data.  The data
			// is still handled by CharacterDataHandler().
	
	protected:
		
		virtual TConfigXMLObj* _NewObject () const;
			// Returns a new object of this type.
		
		TXMLNodeObj*								fRootNodePtr;
		TXMLNodeObjList								fParseStack;
};

//---------------------------------------------------------------------
// Class TSymbiotMessageBase
//---------------------------------------------------------------------
class TSymbiotMessageBase
{
	protected:
		
		class TMessageParser : public TExpatBaseObj
		{
			protected:
				
				typedef		TExpatBaseObj					Inherited;
			
			public:
				
				TMessageParser () : Inherited(),fRootNodePtr(NULL)
					{
						EnableElementHandling();
						EnableCharacterDataHandling(true,false); // auto-trim, don't pass empty data
						EnableCDataSectionHandling();
					}
			
			private:
				
				TMessageParser (const TMessageParser& obj) // : Inherited(),fRootNodePtr(obj.fRootNodePtr),fParseStack(obj.fParseStack)
					{
					}
			
			public:
				
				virtual ~TMessageParser ()
					{
					}
				
				virtual void Reset ()
					{
						Inherited::Reset();
						fRootNodePtr = NULL;
						
						while (!fParseStack.empty())
						{
							delete(fParseStack.back());
							fParseStack.pop_back();
						}
					}
				
				virtual bool ParseBuffer (const std::string& bufferObj, TXMLNodeObj& rootNodeObj)
					{
						bool		wasLoaded = true;
						XML_Status	parseStatus = XML_STATUS_OK;
						
						fRootNodePtr = &rootNodeObj;
						
						parseStatus = Parse(bufferObj);
						if (parseStatus != XML_STATUS_OK)
							wasLoaded = false;
						
						return wasLoaded;
					}
				
				virtual void ElementHandler_Start (const std::string& name,
												   const ExpatAttributeMap& specificAttributeMap,
												   const ExpatAttributeMap& inheritedAttributeMap)
					{
						fParseStack.push_back(new TXMLNodeObj(name));
						
						for (ExpatAttributeMap_const_iter x = inheritedAttributeMap.begin(); x != inheritedAttributeMap.end(); x++)
							fParseStack.back()->AddAttribute(x->first,x->second);
						
						for (ExpatAttributeMap_const_iter x = specificAttributeMap.begin(); x != specificAttributeMap.end(); x++)
							fParseStack.back()->AddAttribute(x->first,x->second);
					}
				
				virtual void ElementHandler_End (const std::string& name)
					{
						TXMLNodeObj*	currentNodePtr(fParseStack.back());
						
						fParseStack.pop_back();
						
						if (fParseStack.empty())
							*fRootNodePtr = *currentNodePtr;
						else
							fParseStack.back()->Append(currentNodePtr);
					}
				
				virtual void CharacterDataHandler (const std::string& data)
					{
						fParseStack.back()->SetData(data);
					}
				
				virtual void CDataSectionHandler_Start ()
					{
					}
				
				virtual void CDataSectionHandler_End ()
					{
					}
			
			protected:
				
				virtual TMessageParser* _NewObject () const
					{
						return new TMessageParser;
					}
				
				TXMLNodeObj*								fRootNodePtr;
				TXMLNodeObjList								fParseStack;
		};
		
	public:
		
		TSymbiotMessageBase ();
			// Constructor
		
		TSymbiotMessageBase (const std::string& topLevelTag,
							 const std::string& attribute = "",
							 const std::string& attributeValue = "");
			// Constructor
		
		TSymbiotMessageBase (const TSymbiotMessageBase& obj);
			// Constructor
		
		virtual ~TSymbiotMessageBase ();
			// Destructor
		
		virtual void Reset ();
			// Resets the object to empty values.
		
		virtual void Parse (const std::string& data);
			// Parses the argument's contents, replacing any contents we may
			// already have.
		
		virtual const TXMLNodeObj* Append (const TXMLNodeObj* nodeObjPtr);
			// Appends the given node to the internal list.
		
		virtual const TXMLNodeObj* Append (const std::string& tag);
			// Appends a new node, containing only a tag, to the internal list.
		
		virtual const TXMLNodeObj* Append (const std::string& tag, const std::string& data);
			// Appends a new node, defined by the tag and data arguments,
			// to the internal list.
		
		virtual void AddAttribute (const std::string& attribute, const std::string& attributeValue);
			// Adds the given attribute/attributeValue key pair to the root note.
		
		virtual const TXMLNodeObj* FindNode (const std::string& tag,
											 const std::string& attribute = "",
											 const std::string& attributeValue = "") const;
			// Searches the node heirarchy beginning with the current node, using
			// the tag argument and optionally the attribute and attributeValue arguments
			// for a matching node.  Returns a pointer to the first matching node if
			// found, NULL otherwise.  Note that the search is case-insensitive.
		
		virtual std::string GetData (const std::string& tag,
									 const std::string& attribute = "",
									 const std::string& attributeValue = "") const;
			// Uses FindNode() to locate a matching node.  If found, and the node is 'simple',
			// then the data from that node is returned.
		
		virtual std::string AsString (const std::string& indent = "\t",
									  const std::string& lineDelimiter = "\n") const;
			// Returns the current message as a human-readable string.
		
		virtual std::string AsCompressedString () const;
			// Same as AsString() except formatting is removed.
		
		// ------------------------------
		// Accessors
		// ------------------------------
		
		inline const TXMLNodeObj* RootNodePtr () const
			{ return &fXMLMessage; }
		
		inline std::string RootTag () const
			{ return fXMLMessage.Tag(); }
	
	protected:
		
		TXMLNodeObj								fXMLMessage;
};

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif // SYMLIB_XML

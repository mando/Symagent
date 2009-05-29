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
#		Last Modified:				28 Jan 2004
#		
#######################################################################
*/

#if !defined(SYMLIB_MESSAGE)
#define SYMLIB_MESSAGE

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include <string>

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TMessageNode;
class TMessage;
class TServerMessage;
class TServerReply;
class TPreferenceNode;
class TLoginDataNode;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

#define	kMessageRootTag									"AGENT"

#define	kMessageTypeValueLogin							"LOGIN"
#define	kMessageTypeValueLogout							"LOGOUT"
#define	kMessageTypeValueConfig							"CONFIG"

#define	kMessageTagClientSignature						"app_signature"
#define	kMessageTagMACAddress							"mac_id"
#define	kMessageTagIPAddress							"ip"
#define	kMessageTagNonce								"nonce"
#define	kMessageTagLoad									"load"
#define	kMessageTagValue								"value"

//---------------------------------------------------------------------
// Class TMessageNode
//---------------------------------------------------------------------
class TMessageNode
{
	public:
		
		TMessageNode ();
			// Constructor
		
		TMessageNode (const TMessageNode& obj);
			// Copy constructor
		
		virtual ~TMessageNode ();
			// Destructor
		
		virtual bool IsValid () const;
			// Returns a boolean indicating whether the node is valid or not.
		
		virtual void SetPtr (const void* ptr);
			// Sets our internal pointer.
		
		virtual void* GetPtr () const;
		
		virtual void MarkNotLocal ();
			// Marks the object as not local so the internal pointer
			// won't be deleted on object destruction.  Does nothing in
			// this class, but subclasses may find it useful.
		
		virtual TMessageNode Append (const std::string& tag,
									 const std::string& attribute,
									 const std::string& attributeValue,
									 const std::string& data = "");
			// Appends a new node, defined by the arguments, to the
			// internal list.  Returns the reference to newly-appended
			// node.
		
		virtual TMessageNode Append (TMessageNode& messageNode);
			// Appends the argument node to the internal list.
			// Returns a reference to the newly-appended node.
		
		virtual void AddAttribute (const std::string& newAttribute,
								   const std::string& newAttributeValue);
			// Adds a newAttribute/newAttributeValue key pair to the node defined
			// solely by tagPath.
		
		virtual std::string GetAttributeValue (const std::string& attribute) const;
			// Returns the value associated with the node at the given path, with the
			// given attribute.  Will return an empty string if no such node or
			// attribute is found.
		
		virtual void SetTag (const std::string& newTag);
			// Changes the tag of this node.
		
		virtual std::string GetTag () const;
			// Returns the tag for this node.
		
		virtual void SetData (const std::string& data);
			// Sets the data associated with this node.
		
		virtual std::string GetData () const;
			// Returns the data associated with this node.
		
		virtual unsigned long SubnodeCount () const;
			// Returns the number of child nodes within this one.  Does not
			// count embedded children.
		
		virtual TMessageNode GetNthSubnode (unsigned long n) const;
			// Returns a reference to the nth child node.  Callers should test
			// with IsValid() to be sure that a node was really returned.
	
	private:
		
		void*											fNodePtr;
};

//---------------------------------------------------------------------
// Class TMessage
//---------------------------------------------------------------------
class TMessage
{
	protected:
		
		TMessage ();
			// Constructor for incoming messages
		
		TMessage (const std::string& topLeveltag);
			// Constructor for outbound messages.  Many default attributes
			// and nodes are set in this constructor.
		
		TMessage (const TMessage& obj);
			// Constructor
	
	public:
		
		virtual ~TMessage ();
			// Destructor
		
		virtual void Reset ();
			// Resets the object to empty values.
		
		virtual void Parse (const std::string& data);
			// Parses the argument's contents, replacing any data we're
			// currently holding with the results.
		
		virtual TMessageNode Append (const std::string& tag,
									 const std::string& attribute,
									 const std::string& attributeValue,
									 const std::string& data = "");
			// Appends a new node, defined by the arguments, to the
			// internal list.  Returns the reference to newly-appended
			// node.
		
		virtual TMessageNode Append (TMessageNode& messageNode);
			// Appends a copy of the the argument node to the internal list.
			// Returns a reference to the newly-appended node.
		
		virtual void AddAttribute (const std::string& newAttribute,
								   const std::string& newAttributeValue);
			// Adds a newAttribute/newAttributeValue key pair to the node defined
			// solely by tagPath.
		
		virtual TMessageNode FindNode (const std::string& tag,
									   const std::string& attribute = "",
									   const std::string& attributeValue = "") const;
			// Returns a reference to a node matching the given criteria.
		
		virtual std::string AsString (const std::string& indent = "\t",
									  const std::string& lineDelimiter = "\n") const;
			// Returns the current message as a human-readable string.
		
		virtual std::string AsCompressedString () const;
			// Same as AsString() except formatting is removed.
	
	protected:
		
		void*										fMessageObjPtr;
};

//---------------------------------------------------------------------
// Class TServerMessage
//---------------------------------------------------------------------
class TServerMessage : public TMessage
{
	private:
		
		typedef		TMessage						Inherited;
	
	public:
		
		TServerMessage ();
			// Constructor for incoming messages
		
		TServerMessage (const TServerMessage& obj);
			// Constructor
		
		virtual ~TServerMessage ();
			// Destructor
};

//---------------------------------------------------------------------
// Class TServerReply
//---------------------------------------------------------------------
class TServerReply : public TMessage
{
	private:
		
		typedef		TMessage						Inherited;
	
	public:
		
		TServerReply ();
			// Constructor for incoming messages
		
		TServerReply (const TServerReply& obj);
			// Constructor
		
		virtual ~TServerReply ();
			// Destructor
};

//---------------------------------------------------------------------
// Class TPreferenceNode
//---------------------------------------------------------------------
class TPreferenceNode : public TMessageNode
{
	private:
		
		typedef		TMessageNode					Inherited;
	
	public:
		
		TPreferenceNode ();
			// Constructor for incoming messages
		
		TPreferenceNode (const Inherited& obj);
			// Constructor
		
		virtual ~TPreferenceNode ();
			// Destructor
		
		virtual TMessageNode Append (const std::string& tag,
									 const std::string& attribute,
									 const std::string& attributeValue,
									 const std::string& data = "")
			{ return TMessageNode(); }
		
		virtual TMessageNode Append (const TMessageNode& messageNode)
			{ return TMessageNode(); }
		
		virtual void AddAttribute (const std::string& newAttribute,
								   const std::string& newAttributeValue)
			{}
		
		virtual TPreferenceNode FindNode (const std::string& tag,
										  const std::string& attribute = "",
										  const std::string& attributeValue = "") const;
			// Returns a reference to a node matching the given criteria.
		
		virtual std::string AsString (const std::string& indent = "\t",
									  const std::string& lineDelimiter = "\n") const;
			// Returns the current message as a human-readable string.
		
		virtual std::string AsCompressedString () const;
			// Same as AsString() except formatting is removed.
};

//---------------------------------------------------------------------
// Class TLoginDataNode
//---------------------------------------------------------------------
class TLoginDataNode : public TMessageNode
{
	private:
		
		typedef		TMessageNode					Inherited;
	
	public:
		
		TLoginDataNode ();
			// Constructor
		
		TLoginDataNode (const std::string& tag,
						const std::string& attribute = "",
						const std::string& attributeValue = "");
			// Constructor
		
		TLoginDataNode (TLoginDataNode& obj);
			// Copy constructor.  Note the argument is not const.
		
		virtual ~TLoginDataNode ();
			// Destructor
		
		virtual bool IsValid () const;
			// Returns a boolean indicating whether this node is valid.
			// That is, whether anything has been defined in it.
		
		virtual void* GetPtr () const;
		
		virtual void MarkNotLocal ();
			// Marks the object as not local so the internal pointer
			// won't be deleted on object destruction.
	
	private:
		
		void*											fNodePtr;
		bool											fIsLocal;
};

//---------------------------------------------------------------------
// Global Function Declarations
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif // SYMLIB_MESSAGE

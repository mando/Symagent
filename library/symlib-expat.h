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

#if !defined(SYMLIB_EXPAT)
#define SYMLIB_EXPAT

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "symlib-config.h"

#include "symlib-file.h"

#include <expat.h>
#include <map>
#include <vector>

//---------------------------------------------------------------------
// Check expat version: 1.95.6 minimum
//---------------------------------------------------------------------
#if !defined(XML_MAJOR_VERSION) || !defined(XML_MINOR_VERSION) || !defined(XML_MICRO_VERSION)
	#error Expat version 1.95.6 or later is required
#else
	#if XML_MAJOR_VERSION < 1
		#error Expat version 1.95.6 or later is required
	#elif XML_MAJOR_VERSION == 1
		#if XML_MINOR_VERSION < 95
			#error Expat version 1.95.6 or later is required
		#elif XML_MINOR_VERSION == 95
			#if XML_MICRO_VERSION < 6
				#error Expat version 1.95.6 or later is required
			#endif
		#endif
	#endif
#endif

//---------------------------------------------------------------------
// Begin Environment
//---------------------------------------------------------------------
namespace symbiot {

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TExpatBaseObj;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------
typedef std::vector<XML_Feature>									ExpatFeatureList;
typedef	ExpatFeatureList::iterator									ExpatFeatureList_iter;
typedef	ExpatFeatureList::const_iterator							ExpatFeatureList_const_iter;

typedef std::vector<XML_Content*>									XMLContentPtrList;
typedef	XMLContentPtrList::iterator									XMLContentPtrList_iter;
typedef	XMLContentPtrList::const_iterator							XMLContentPtrList_const_iter;

typedef std::vector<TExpatBaseObj*>									TExpatBaseObjPtrList;
typedef	TExpatBaseObjPtrList::iterator								TExpatBaseObjPtrList_iter;
typedef	TExpatBaseObjPtrList::const_iterator						TExpatBaseObjPtrList_const_iter;

typedef std::map<std::string,std::string>							ExpatAttributeMap;
typedef	ExpatAttributeMap::iterator									ExpatAttributeMap_iter;
typedef	ExpatAttributeMap::const_iterator							ExpatAttributeMap_const_iter;

typedef	enum	{
					kXMLDeclStandaloneUnknown = -1,
					kXMLDeclStandaloneNo = 0,
					kXMLDeclStandaloneYes = 1
				}	XMLDeclStandalone;

//---------------------------------------------------------------------
// Class TExpatBaseObj
//
// This is basically a class wrapper for the expat XML parsing library.
// Most of the expat functionality is included here.  The primary
// advantage of using an object is in defining handlers:  Instead of
// creating C-style functions to deal with everything, you can simply
// override class methods.  This also allows you to create a hierarchy
// of objects, reusing functionality as needed.
//
// Expat itself isn't explained here.  If you need documentation, see
// http://www.libexpat.org/ or http://sourceforge.net/projects/expat/.
// Note that the expat function calls that are used in this class are
// included here in the header, in the appropriate class method, so
// it should be relatively easy to map expat functions to class methods.
//
// The TExpatBaseObj class cannot be instantiated directly -- it MUST
// be subclassed.  Only one class method -- _NewObject() -- must be
// overridden in order to make a subclass compile, but of course then
// it wouldn't do anything.  Subclasses should, in general, provide
// their own versions of the Handlers and then activate them via the
// suite of Enabler calls.
//---------------------------------------------------------------------
class TExpatBaseObj
{
	private:
		
		static const int	kReadBufferMaxSize;
		static const int	kReadBufferMinSize;
	
	protected:
		
		typedef		std::map<XML_Parser,TExpatBaseObj*,std::less<XML_Parser> >		TExpatObjPtrInstanceMap;
		typedef		TExpatObjPtrInstanceMap::iterator								TExpatObjPtrInstanceMap_iter;
		typedef		TExpatObjPtrInstanceMap::const_iterator							TExpatObjPtrInstanceMap_const_iter;
		
		class TInstanceMapObj
		{
			public:
				
				TInstanceMapObj () {}
				~TInstanceMapObj () {}
				
				inline void AddEntry (XML_Parser& parserRef, TExpatBaseObj* expatObjPtr)
					{
						fInstanceMap[parserRef] = expatObjPtr;
					}
				
				inline void RemoveEntry (XML_Parser& parserRef)
					{
						fInstanceMap.erase(parserRef);
					}
				
				inline TExpatObjPtrInstanceMap_iter Get (XML_Parser& parserRef)
					{
						return fInstanceMap.find(parserRef);
					}
				
				inline TExpatObjPtrInstanceMap_iter End ()
					{
						return fInstanceMap.end();
					}
			
			private:
				
				TExpatObjPtrInstanceMap				fInstanceMap;
		};
		
		static		TInstanceMapObj*					gInstanceMapPtr;
	
	protected:
		
		TExpatBaseObj (const std::string& encoding = "", const XML_Char& namespaceSeparator = '\0');
			// Constructor.  It's protected because only subclasses should be instantiating.
			// Expat functions:  XML_ParserCreate, XML_ParserCreateNS
		
		TExpatBaseObj (bool);
			// Private constructor used to generate parsers for external references
	
	private:
	
		TExpatBaseObj (const TExpatBaseObj& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TExpatBaseObj ();
			// Destructor
			// Expat functions:  XML_ParserFree
		
		virtual bool Reset (const std::string& newEncoding = "");
			// Resets the object completely, including any handlers you may have setup.  Be
			// sure to call any EnableXXXX() methods you need after calling this method.
			// Expat functions:  XML_ParserReset
		
		virtual void FreeContentModel (const XML_Content* model);
			// Frees the content model passed as the argument.  Also removes it from the internal
			// list, if necessary.
			// Expat functions:  XML_FreeContentModel
		
		virtual XML_Status SetEncoding (const std::string& newEncoding);
			// Sets the current encoding scheme for the object.  Must be called before
			// parsing begins.
			// Expat functions:  XML_SetEncoding
		
		virtual std::string GetBase ();
			// Returns the current base used to resolve relative URIs in system identifiers
			// in declarations.
			// Expat functions:  XML_GetBase
		
		virtual XML_Status SetBase (const std::string& newBase);
			// Sets the base to be used for resolving relative URIs in system identifiers
			// in declarations.
			// Expat functions:  XML_SetBase
		
		virtual XML_Error UseForeignDTD (bool useForeign);
			// Tells Expat whether or not to assume that there is an external subset to the
			// current document.
			// Expat functions:  XML_UseForeignDTD
		
		virtual TExpatBaseObj* CreateExternalEntityParserObj (const std::string& context, const std::string& encoding);
			// Creates a new parser object for parsing an external entity.  A pointer to the
			// new object is returned, but this (parent) object retains ownership of the
			// external entity object and will delete it eventually.
			// Expat functions:  XML_ExternalEntityParserCreate
		
		virtual bool SetParamEntityParsing (XML_ParamEntityParsing howToParse);
			// Determines how Expat handles the parsing of parameter entities.  Returns true
			// if the request took effect, false otherwise.
			// Expat functions:  XML_SetParamEntityParsing
		
		virtual void* GetExpatBuffer (int requestedSize);
			// Requests a buffer of size requestedSize from the expat library, returning
			// a pointer to the allocated buffer or NULL if allocation fails.
			// Expat functions: XML_GetBuffer
		
		virtual XML_Status Parse (size_t bufferSize);
			// Parses bufferSize bytes of the buffer previously obtained via a call
			// to GetExpatBuffer().
			// Expat functions: XML_ParseBuffer
		
		virtual XML_Status Parse (const char* bufferPtr, size_t bufferSize);
			// Parses bufferSize bytes of memory pointed to by bufferPtr.
			// Expat functions:  XML_Parse
		
		virtual XML_Status Parse (const std::string& bufferObj);
			// Parses the contents of the argument.
			// Expat functions:  XML_Parse
		
		virtual XML_Status Parse (TFileObj& fileObj);
			// Parses the contents of the file indicated by the argument.
			// Expat functions:  XML_Parse
		
		virtual XML_Status Finalize ();
			// Tells the expat library that we're done parsing the document.
			// Expat functions:  XML_Parse
		
		virtual void SetDefaultCurrent ();
			// Called during parsing.  Causes either DefaultHandler() or DefaultExpandHandler()
			// , whichever is active, to be called with the current markup.
			// Expat functions:  XML_DefaultCurrent
		
		virtual long GetByteCount ();
			// Returns the number of bytes parsed so far in the current event.  Valid only
			// while parsing.
			// Expat functions:  XML_GetCurrentByteCount
		
		virtual long GetByteIndex ();
			// Gets the current byte offset from the beginning of the document.  Valid only while
			// parsing.
			// Expat functions:  XML_GetCurrentByteIndex
		
		virtual long GetLineIndex ();
			// Gets the current line offset from the beginning of the document.  Valid only while
			// parsing.
			// Expat functions:  XML_GetCurrentLineNumber
		
		virtual long GetColumnIndex ();
			// Gets the current column offset from the beginning of the current line.  Valid only
			// while parsing.
			// Expat functions:  XML_GetCurrentColumnNumber
		
		virtual XML_Error ErrorCode ();
			// Returns a code designating the last error that occurred with this parser object.
			// Expat functions:  XML_GetErrorCode
		
		virtual std::string ErrorDescription ();
			// Returns a description of the last error that occurred with this parser object.
		
		// ------------------------------------------------
		// Enablers
		// ------------------------------------------------
		
		virtual void EnableElementHandling ();
			// Enables callbacks to ElementHandler_Start() and ElementHandler_End() methods.
			// Expat functions:  XML_SetElementHandler
		
		virtual void DisableElementHandling ();
			// Disables callbacks to ElementHandler_Start() and ElementHandler_End() methods.
			// Expat functions:  XML_SetElementHandler
		
		virtual void EnableCharacterDataHandling (bool autoTrim = false, bool passEmpty = true);
			// Enables callbacks to the CharacterDataHandler() method.
			// Expat functions:  XML_SetCharacterDataHandler
		
		virtual void DisableCharacterDataHandling ();
			// Disables callbacks to the CharacterDataHandler() method.
			// Expat functions:  XML_SetCharacterDataHandler
		
		virtual void EnableProcessingInstructionHandling ();
			// Enables callbacks to the ProcessingInstructionHandler() method.
			// Expat functions:  XML_SetProcessingInstructionHandler
		
		virtual void DisableProcessingInstructionHandling ();
			// Disables callbacks to the ProcessingInstructionHandler() method.
			// Expat functions:  XML_SetProcessingInstructionHandler
		
		virtual void EnableCommentHandling ();
			// Enables callbacks to the CommentHandler() method.
			// Expat functions:  XML_SetCommentHandler
		
		virtual void DisableCommentHandling ();
			// Disables callbacks to the CommentHandler() method.
			// Expat functions:  XML_SetCommentHandler
		
		virtual void EnableCDataSectionHandling ();
			// Enables callbacks to CDataSectionHandler_Start() and CDataSectionHandler_End() methods.
			// Expat functions:  XML_SetCdataSectionHandler
		
		virtual void DisableCDataSectionHandling ();
			// Disables callbacks to CDataSectionHandler_Start() and CDataSectionHandler_End() methods.
			// Expat functions:  XML_SetCdataSectionHandler
		
		virtual void EnableDefaultHandling ();
			// Enables callbacks to the DefaultHandler() method.
			// Expat functions:  XML_SetDefaultHandler
		
		virtual void DisableDefaultHandling ();
			// Disables callbacks to the DefaultHandler() method.
			// Expat functions:  XML_SetDefaultHandler
		
		virtual void EnableDefaultExpandHandling ();
			// Enables callbacks to the DefaultExpandHandler() method.
			// Expat functions:  XML_SetDefaultHandlerExpand
		
		virtual void DisableDefaultExpandHandling ();
			// Disables callbacks to the DefaultExpandHandler() method.
			// Expat functions:  XML_SetDefaultHandlerExpand
		
		virtual void EnableDoctypeDeclHandling ();
			// Enables callbacks to DoctypeDeclHandler_Start() and DoctypeDeclHandler_End() methods.
			// Expat functions:  XML_SetDoctypeDeclHandler
		
		virtual void DisableDoctypeDeclHandling ();
			// Disables callbacks to DoctypeDeclHandler_Start() and DoctypeDeclHandler_End() methods.
			// Expat functions:  XML_SetDoctypeDeclHandler
		
		virtual void EnableUnparsedEntityDeclHandling ();
			// Enables callbacks to the UnparsedEntityDeclHandler() method.
			// Expat functions:  XML_SetUnparsedEntityDeclHandler
		
		virtual void DisableUnparsedEntityDeclHandling ();
			// Disables callbacks to the UnparsedEntityDeclHandler() method.
			// Expat functions:  XML_SetUnparsedEntityDeclHandler
		
		virtual void EnableNotationDeclHandling ();
			// Enables callbacks to the NotationDeclHandler() method.
			// Expat functions:  XML_SetNotationDeclHandler
		
		virtual void DisableNotationDeclHandling ();
			// Disables callbacks to the NotationDeclHandler() method.
			// Expat functions:  XML_SetNotationDeclHandler
		
		virtual void EnableNamespaceDeclHandling ();
			// Enables callbacks to NamespaceDeclHandler_Start() and NamespaceDeclHandler_End() methods.
			// Expat functions:  XML_SetNamespaceDeclHandler
		
		virtual void DisableNamespaceDeclHandling ();
			// Disables callbacks to NamespaceDeclHandler_Start() and NamespaceDeclHandler_End() methods.
			// Expat functions:  XML_SetNamespaceDeclHandler
		
		virtual void EnableExternalEntityRefHandling ();
			// Enables callbacks to the ExternalEntityRefHandler() method.
			// Expat functions:  XML_SetExternalEntityRefHandler
		
		virtual void DisableExternalEntityRefHandling ();
			// Disables callbacks to the ExternalEntityRefHandler() method.
			// Expat functions:  XML_SetExternalEntityRefHandler
		
		virtual void EnableSkippedEntityHandling ();
			// Enables callbacks to the SkippedEntityHandler() method.
			// Expat functions:  XML_SetSkippedEntityHandler
		
		virtual void DisableSkippedEntityHandling ();
			// Disables callbacks to the SkippedEntityHandler() method.
			// Expat functions:  XML_SetSkippedEntityHandler
		
		virtual void EnableUnknownEncodingHandling ();
			// Enables callbacks to the UnknownEncodingHandler() method.
			// Expat functions:  XML_SetUnknownEncodingHandler
		
		virtual void DisableUnknownEncodingHandling ();
			// Disables callbacks to the UnknownEncodingHandler() method.
			// Expat functions:  XML_SetUnknownEncodingHandler
		
		virtual void EnableElementDeclHandling ();
			// Enables callbacks to the ElementDeclHandler() method.
			// Expat functions:  XML_SetElementDeclHandler
		
		virtual void DisableElementDeclHandling ();
			// Disables callbacks to the ElementDeclHandler() method.
			// Expat functions:  XML_SetElementDeclHandler
		
		virtual void EnableAttlistDeclHandling ();
			// Enables callbacks to the AttlistDeclHandler() method.
			// Expat functions:  XML_SetAttlistDeclHandler
		
		virtual void DisableAttlistDeclHandling ();
			// Disables callbacks to the AttlistDeclHandler() method.
			// Expat functions:  XML_SetAttlistDeclHandler
		
		virtual void EnableXMLDeclHandling ();
			// Enables callbacks to the XMLDeclHandler() method.
			// Expat functions:  XML_SetXMLDeclHandler
		
		virtual void DisableXMLDeclHandling ();
			// Disables callbacks to the XMLDeclHandler() method.
			// Expat functions:  XML_SetXMLDeclHandler
		
		// ------------------------------------------------
		// Handlers
		// ------------------------------------------------
		
		virtual void ElementHandler_Start (const std::string& name,
										   const ExpatAttributeMap& specificAttributeMap,
										   const ExpatAttributeMap& inheritedAttributeMap);
			// Callback from expat when a new tag is started.  Subclasses should override this
			// method and do something useful, as this version does nothing.
			// EnableElementHandling() must be called in order to activate this handler.
		
		virtual void ElementHandler_End (const std::string& name);
			// Callback from expat when a tag ends.  Subclasses should override this method
			// if they also overrode ElementHandler_Start() as this version does nothing.
			// EnableElementHandling() must be called in order to activate this handler.
		
		virtual void CharacterDataHandler (const std::string& data);
			// Callback from expat when character data is found.  Subclasses should override
			// this method, and this version does nothing.  Note that whitespace is included
			// in the passed-in data; you may have to Trim() it unless you've opted to
			// automatically trim it during while calling EnableCharacterDataHandling().
			// EnableCharacterDataHandling() must be called in order to activate this handler.
		
		virtual void ProcessingInstructionHandler (const std::string& target, const std::string& data);
			// Callback from expat when an instruction is found.  Subclasses should override
			// this method, and this version does nothing.  EnableProcessingInstructionHandling()
			// must be called in order to activate this handler.
		
		virtual void CommentHandler (const std::string& data);
			// Callback from expat when a comment is found.  Subclasses should override
			// this method, and this version does nothing.  EnableCommentHandling() must be called
			// in order to activate this handler.
		
		virtual void CDataSectionHandler_Start ();
			// Callback from expat when a CDATA section is started.  Subclasses should override this
			// method and do something useful, as this version does nothing.  EnableCDataSectionHandling()
			// must be called in order to activate this handler.
		
		virtual void CDataSectionHandler_End ();
			// Callback from expat when a CDATA tag ends.  Subclasses should override this method
			// if they also overrode CDataSectionHandler_Start() as this version does nothing.
			// EnableCDataSectionHandling() must be called in order to activate this handler.
		
		virtual void DefaultHandler (const std::string& data);
			// Callback from expat when it runs across characters that wouldn't be handled by
			// any other routine.  Subclass should override this method, as this version does
			// nothing.  EnableDefaultHandling() must be called in order to activate this handler.
		
		virtual void DefaultExpandHandler (const std::string& data);
			// Same as DefaultHandler() except that it doesn't inhibit the expansion of internal
			// entity references.  Subclasses should override this method, and this version
			// does nothing.  EnableDefaultExpandHandling() must be called in order to activate this
			// handler.
		
		virtual void DoctypeDeclHandler_Start (const std::string& doctypeName,
											   const std::string& sysID,
											   const std::string& pubID,
											   bool hasInternalSubset);
			// Callback from expat when a DOCTYPE declaration is started.  Subclasses should
			// override this method and do something useful, as this version does nothing.
			// EnableDoctypeDeclHandling() must be called in order to activate this handler.
		
		virtual void DoctypeDeclHandler_End ();
			// Callback from expat when a DOCTYPE declaration ends.  Subclasses should override
			// this method if they also overrode DoctypeDeclHandler_Start() as this version
			// does nothing.  EnableDoctypeDeclHandling() must be called in order to activate this handler.
		
		virtual void UnparsedEntityDeclHandler (const std::string& entityName,
												const std::string& base,
												const std::string& systemID,
												const std::string& publicID,
												const std::string& notationName);
			// Callback from expat when it receives a declaration of unparsed entities.  Subclasses
			// should override this method, and this version does nothing.  EnableUnparsedEntityDeclHandling()
			// must be called in order to activate this handler.
		
		virtual void NotationDeclHandler (const std::string& notationName,
										  const std::string& base,
										  const std::string& systemID,
										  const std::string& publicID);
			// Callback from expat when it receives notation declarations.  Subclasses should override
			// this method, and this version does nothing.  EnableNotationDeclHandling() must be called
			// in order to activate this handler.
		
		virtual void NamespaceDeclHandler_Start (const std::string& prefix, const std::string& uri);
			// Callback from expat when a namespace declaration is started.  Subclasses should override
			// this method and do something useful, as this version does nothing.
			// EnableNamespaceDeclHandling() must be called in order to activate this handler.
		
		virtual void NamespaceDeclHandler_End (const std::string& prefix);
			// Callback from expat when a namespace declaration ends.  Subclasses should override this
			// method if they also overrode NamespaceDeclHandler_Start() as this version does nothing.
			// EnableNamespaceDeclHandling() must be called in order to activate this handler.
		
		virtual int ExternalEntityRefHandler (const std::string& context,
											  const std::string& base,
											  const std::string& systemID,
											  const std::string& publicID);
			// Callback from expat when an external reference is found.  Subclasses should override
			// this method, and this version does nothing.  EnableExternalEntityRefHandling() must be
			// called in order to activate this handler.
		
		virtual void SkippedEntityHandler (const std::string& entityName, bool isParameterEntity);
			// Callback from expat when it finds a valid entity but no handler for it.  Subclasses
			// should override this method, and this version does nothing.  EnableSkippedEntityHandling()
			// must be called in order to activate this handler.
		
		virtual int UnknownEncodingHandler (const std::string& name, XML_Encoding* info);
			// Callback from expat when it finds an encoding it doesn't know what to do with.
			// Subclasses should override this method, and this version does nothing.
			// EnableUnknownEncodingHandling() must be called in order to activate this handler.
		
		virtual void ElementDeclHandler (const std::string& name, const XML_Content* model);
			// Callback from expat when it finds element declarations in a DTD.  Subclasses should
			// override this method, and this version does nothing.  EnableElementDeclHandling()
			// must be called in order to activate this handler.
		
		virtual void AttlistDeclHandler (const std::string& tagName,
										 const std::string& attributeName,
										 const std::string& attributeType,
										 const std::string& defaultValue,
										 bool isRequired);
			// Callback from expat when it finds attlist declarations in the DTD.  Subclasses should
			// override this method, and this version does nothing.  EnableAttlistDeclHandling()
			// must be called in order to activate this handler.
		
		virtual void XMLDeclHandler (const std::string& version,
									 const std::string& encoding,
									 XMLDeclStandalone standaloneType);
			// Callback from expat when it finds XML declarations and also for text declarations
			// discovered in external entities.  Subclasses should override this method, and this
			// version does nothing.  EnableXMLDeclHandling() must be called in order to
			// activate this handler.
	
	public:
		
		// ------------------------------------------------
		// Accessors
		// ------------------------------------------------
		
		inline const XML_Parser XMLParserHandle () const
			{ return fParserHandle; }
		
		inline XML_Parser XMLParserHandle ()
			{ return fParserHandle; }
		
		inline std::string Encoding () const
			{ return fEncoding; }
		
		inline std::string Context () const
			{ return fContext; }
		
		inline XML_Char NamespaceSeparator () const
			{ return fNamespaceSeparator; }
	
	public:
		
		// ------------------------------------------------
		// Public static methods
		// ------------------------------------------------
		
		static std::string LibraryVersion ();
			// Returns a string containing the Expat library version.
			// Expat functions:  XML_ExpatVersion
		
		static void GetFeatureList (ExpatFeatureList& featureList);
			// Destructively modifies the argument to contain a list of
			// structures, each of which describe a single feature found
			// in the expat library.
			// Expat functions:  XML_GetFeatureList
		
		static std::string ErrorCodeDescription (const XML_Error& errorCode);
			// Returns a description of the error code given as the argument.
			// Expat functions:  XML_ErrorString
	
	protected:
		
		// ------------------------------------------------
		// Protected static methods
		// ------------------------------------------------
		
		static void _ElementHandler_Start (void* userData,
										   const XML_Char* name,
										   const XML_Char** attributeArray);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the ElementHandler_Start() method in that TExpatObj after arguments
			// are coerced.
			// Expat functions:  XML_GetSpecifiedAttributeCount
		
		static void _ElementHandler_End (void* userData, const XML_Char* name);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the ElementHandler_End() method in that TExpatObj after arguments
			// are coerced.
		
		static void _CharacterDataHandler (void* userData,
										   const XML_Char* s,
										   int len);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the CharacterDataHandler() method in that TExpatObj after arguments
			// are coerced.
		
		static void _ProcessingInstructionHandler (void* userData,
												   const XML_Char* target,
												   const XML_Char* data);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the ProcessingInstructionHandler() method in that TExpatObj after arguments
			// are coerced.
		
		static void _CommentHandler (void* userData, const XML_Char* data);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the CommentHandler() method in that TExpatObj after arguments
			// are coerced.
		
		static void _CDataSectionHandler_Start (void* userData);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the CDataSectionHandler_Start() method in that TExpatObj after arguments
			// are coerced.
		
		static void _CDataSectionHandler_End (void* userData);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the CDataSectionHandler_End() method in that TExpatObj after arguments
			// are coerced.
		
		static void _DefaultHandler (void* userData,
									 const XML_Char* s,
									 int len);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the DefaultHandler() method in that TExpatObj after arguments
			// are coerced.
		
		static void _DefaultExpandHandler (void* userData,
										   const XML_Char* s,
										   int len);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the DefaultExpandHandler() method in that TExpatObj after arguments
			// are coerced.
		
		static void _DoctypeDeclHandler_Start (void *userData,
											   const XML_Char *doctypeName,
											   const XML_Char *sysid,
											   const XML_Char *pubid,
											   int has_internal_subset);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the DoctypeDeclHandler_Start() method in that TExpatObj after arguments
			// are coerced.
		
		static void _DoctypeDeclHandler_End (void* userData);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the DoctypeDeclHandler_End() method in that TExpatObj after arguments
			// are coerced.
		
		static void _UnparsedEntityDeclHandler (void* userData,
												const XML_Char* entityName,
												const XML_Char* base,
												const XML_Char* systemId,
												const XML_Char* publicId,
												const XML_Char* notationName);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the UnparsedEntityDeclHandler() method in that TExpatObj after arguments
			// are coerced.
		
		static void _NotationDeclHandler (void* userData,
										  const XML_Char* notationName,
										  const XML_Char* base,
										  const XML_Char* systemId,
										  const XML_Char* publicId);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the NotationDeclHandler() method in that TExpatObj after arguments
			// are coerced.
		
		static void _NamespaceDeclHandler_Start (void* userData,
												 const XML_Char* prefix,
												 const XML_Char* uri);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the NamespaceDeclHandler_Start() method in that TExpatObj after arguments
			// are coerced.
		
		static void _NamespaceDeclHandler_End (void* userData, const XML_Char* prefix);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the NamespaceDeclHandler_End() method in that TExpatObj after arguments
			// are coerced.
		
		static int _ExternalEntityRefHandler (XML_Parser parser,
											  const XML_Char* context,
											  const XML_Char* base,
											  const XML_Char* systemId,
											  const XML_Char* publicId);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the NotationDeclHandler() method in that TExpatObj after arguments
			// are coerced.
		
		static void _SkippedEntityHandler (void *userData,
										   const XML_Char *entityName,
										   int is_parameter_entity);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the SkippedEntityHandler() method in that TExpatObj after arguments
			// are coerced.
		
		static int _UnknownEncodingHandler (void* encodingHandlerData,
											const XML_Char* name,
											XML_Encoding* info);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the UnknownEncodingHandler() method in that TExpatObj after arguments
			// are coerced.
		
		static void _ElementDeclHandler (void* userData,
										 const XML_Char* name,
										 XML_Content* model);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the ElementDeclHandler() method in that TExpatObj after arguments
			// are coerced.  Note that the XML_Content argument is automatically
			// saved on an internal list for later reuse, and automatically disposed
			// of when the parser is reset or deleted.
			// Expat functions:  XML_FreeContentModel
		
		static void _AttlistDeclHandler (void* userData,
										 const XML_Char* elname,
										 const XML_Char* attname,
										 const XML_Char* att_type,
										 const XML_Char* dflt,
										 int isrequired);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the AttlistDeclHandler() method in that TExpatObj after arguments
			// are coerced.
		
		static void _XMLDeclHandler (void* userData,
									 const XML_Char* version,
									 const XML_Char* encoding,
									 int standalone);
			// Function actually called by expat.  userData is actually a XML_Parser
			// and that is used to locate the owning TExpatObj.  Dispatches to
			// the XMLDeclHandler() method in that TExpatObj after arguments
			// are coerced.
	
	protected:
		
		virtual TExpatBaseObj* _NewObject () const = 0;
			// This must be overridden in child classes.  All it does is return a new,
			// empty object of the same class (eg:  { return new TExpatBaseObj; }
		
		virtual void _ClearInternalList ();
			// Disposes of the internal lists maintained by this object.
			// Expat functions:  XML_FreeContentModel
	
	protected:
		
		XML_Parser									fParserHandle;
		std::string									fEncoding;
		std::string									fContext;
		TExpatBaseObjPtrList						fExternalExpatObjPtrList;
		XMLContentPtrList							fXMLContentPtrList;
		XML_Char									fNamespaceSeparator;
		bool										fAutoTrimCharData;
		bool										fPassEmptyCharData;
};

//---------------------------------------------------------------------
// Sample Basic Subclass
//---------------------------------------------------------------------
/*
using namespace symbiot;

class TMyExpat : public TExpatBaseObj
{
	public:
		
		TMyExpat () : TExpatBaseObj()
			{
				EnableElementHandling();
				EnableCharacterDataHandling(true,false); // auto-trim, don't pass empties
				
				// EnableProcessingInstructionHandling();
				// EnableCommentHandling();
				// EnableCDataSectionHandling();
				// EnableDefaultHandling();
				// EnableDefaultExpandHandling();
				// EnableDoctypeDeclHandling();
				// EnableUnparsedEntityDeclHandling();
				// EnableNotationDeclHandling();
				// EnableNamespaceDeclHandling();
				// EnableExternalEntityRefHandling();
				// EnableSkippedEntityHandling();
				// EnableUnknownEncodingHandling();
				// EnableElementDeclHandling();
				// EnableAttlistDeclHandling();
				// EnableXMLDeclHandling();
			}
		
		virtual ~TMyExpat () {}
		
		virtual void ElementHandler_Start (const std::string& name,
										   const ExpatAttributeMap& specificAttributeMap,
										   const ExpatAttributeMap& inheritedAttributeMap)
			{
			}
		
		virtual void ElementHandler_End (const std::string& name)
			{
			}
		
		virtual void CharacterDataHandler (const std::string& data)
			{
			}
		
	protected:
		
		virtual TMyExpat* _NewObject () const
			{ return new TMyExpat; }
};
*/

//---------------------------------------------------------------------
// End Environment
//---------------------------------------------------------------------
} // namespace symbiot

//*********************************************************************
#endif // SYMLIB_EXPAT

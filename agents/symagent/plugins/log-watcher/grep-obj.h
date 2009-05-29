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
#		Created:					18 Apr 2004
#		Last Modified:				20 Apr 2004
#		
#######################################################################
*/

#if !defined(GREP_OBJ)
#define GREP_OBJ

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "plugin-config.h"

#include "plugin-defs.h"

#include <regex.h>

#if USE_PCRE
	#include "pcre.h"
#endif

//---------------------------------------------------------------------
// Forward Class Declarations
//---------------------------------------------------------------------
class TGrepObj;
class TRegexObj;
class TGrepSet;

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Class TGrepObj
//---------------------------------------------------------------------
class TGrepObj
{
	public:
		
		TGrepObj ();
			// Constructor
	
	private:
		
		TGrepObj (const TGrepObj& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TGrepObj ();
			// Destructor
		
		virtual void Setup (const string& serverReference,
							const string& searchPattern,
							int searchOptions) = 0;
			// Sets up the search pattern that will be used to find
			// matching log file data.
		
		virtual bool IsMatch (const string& text) const = 0;
			// Search the text with the current search pattern, returning
			// true if a match is found and false otherwise.  Errors are
			// ignored. Setup() must be called before this function will
			// succeed.
		
		// ----------------------------
		// Accessors
		// ----------------------------
		
		inline string ServerReference () const
			{ return fServerReference; }
		
		inline void InvertMatch (bool invert)
			{ fInvertMatch = invert; }
	
	protected:
		
		string								fServerReference;
		bool								fInvertMatch;
};

//---------------------------------------------------------------------
// Class TRegexObj
//---------------------------------------------------------------------
class TRegexObj : public TGrepObj
{
	private:
		
		typedef	TGrepObj	Inherited;
	
	public:
		
		TRegexObj ();
			// Constructor
	
	private:
		
		TRegexObj (const TRegexObj& obj) {}
			// Copy constructor is illegal
	
	public:
		
		virtual ~TRegexObj ();
			// Destructor
		
		virtual void Setup (const string& serverReference,
							const string& searchPattern,
							int searchOptions);
			// Specialization.
		
		virtual bool IsMatch (const string& text) const;
			// Specialization.
	
	protected:
		
		virtual void _Reset ();
			// Resets our internal slots, frees memory, etc..
	
	protected:
		
		regex_t								fPatternBuffer;
		bool								fPatternSet;
};

#if USE_PCRE
	//---------------------------------------------------------------------
	// Class TPCREObj
	//---------------------------------------------------------------------
	class TPCREObj : public TGrepObj
	{
		private:
			
			typedef	TGrepObj	Inherited;
		
		public:
			
			TPCREObj ();
				// Constructor
		
		private:
			
			TPCREObj (const TPCREObj& obj) {}
				// Copy constructor is illegal
		
		public:
			
			virtual ~TPCREObj ();
				// Destructor
			
			virtual void Setup (const string& serverReference,
								const string& searchPattern,
								int searchOptions);
				// Specialization.
			
			virtual bool IsMatch (const string& text) const;
				// Specialization.
		
		protected:
			
			virtual void _Reset ();
				// Resets our internal slots, frees memory, etc..
		
		protected:
			
			pcre*								fPatternBufferPtr;
	};
#endif

//---------------------------------------------------------------------
// Class TGrepSet
//---------------------------------------------------------------------
class TGrepSet
{
	protected:
		
		typedef	vector<TGrepObj*>					TGrepObjPtrList;
		typedef	TGrepObjPtrList::iterator			TGrepObjPtrList_iter;
		typedef	TGrepObjPtrList::const_iterator		TGrepObjPtrList_const_iter;
		
		struct	SearchInfo
			{
				string		serverRef;
				string		pattern;
				string		options;
			};
		
		typedef	vector<SearchInfo>					SearchInfoList;
		typedef	SearchInfoList::const_iterator		SearchInfoList_const_iter;
	
	public:
		
		TGrepSet ();
			// Constructor
		
		TGrepSet (const TGrepSet& obj);
			// Copy constructor.
		
		virtual ~TGrepSet ();
			// Destructor
		
		virtual void AddSearch (const string& serverReference,
								const string& searchPattern,
								const string& searchOptions = "");
			// Adds a search with the given parameters to the current
			// set.
		
		virtual bool AnyMatch (const string& text, StdStringList& foundRefList);
			// Compares the internal list of grep objects to text, looking
			// for matches.  Destructively modifies the foundRefList argument
			// to contain a list of server references associated with successful
			// matches.  Returns true if any match was successful, false otherwise.
		
		// ----------------------------
		// Accessors
		// ----------------------------
		
		inline unsigned long size () const
			{ return fSearchInfoList.size(); }
		
		inline bool empty () const
			{ return fSearchInfoList.empty(); }
	
	protected:
		
		bool										fIsCompiled;
		SearchInfoList								fSearchInfoList;
		TGrepObjPtrList								fGrepObjPtrList;
};

//---------------------------------------------------------------------
#endif // GREP_OBJ

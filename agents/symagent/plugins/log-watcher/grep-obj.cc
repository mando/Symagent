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
#		Last Modified:				21 Apr 2004
#		
#######################################################################
*/

//---------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------
#include "grep-obj.h"

#include "plugin-utils.h"

//---------------------------------------------------------------------
// Definitions
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Module Globals
//---------------------------------------------------------------------

//*********************************************************************
// Class TGrepObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TGrepObj::TGrepObj ()
	:	fInvertMatch(false)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TGrepObj::~TGrepObj ()
{
}

//*********************************************************************
// Class TRegexObj
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TRegexObj::TRegexObj ()
	:	fPatternSet(false)
{
	memset(&fPatternBuffer,0,sizeof(fPatternBuffer));
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TRegexObj::~TRegexObj ()
{
	_Reset();
}

//---------------------------------------------------------------------
// TRegexObj::Setup
//---------------------------------------------------------------------
void TRegexObj::Setup (const string& serverReference,
					   const string& searchPattern,
					   int searchOptions)
{
	int		result = 0;
	
	// Clear any current search pattern
	_Reset();
	
	result = regcomp(&fPatternBuffer,searchPattern.c_str(),searchOptions);
	if (result != 0)
	{
		int			errorBufSize = 2048;
		char		errorBuf[errorBufSize];
		string		errString;
		
		memset(errorBuf,0,errorBufSize);
		regerror(result,&fPatternBuffer,errorBuf,errorBufSize-1);
		
		errString = "Error compiling regex pattern '" + searchPattern + "': " + errorBuf;
		
		throw TSymLibErrorObj(result,errString);
	}
	
	fPatternSet = true;
	fServerReference = serverReference;
}

//---------------------------------------------------------------------
// TRegexObj::IsMatch
//---------------------------------------------------------------------
bool TRegexObj::IsMatch (const string& text) const
{
	bool	matches = false;
	
	if (fPatternSet)
	{
		int				result = 0;
		regmatch_t		matchInfo;
		int				eFlags = 0;
		
		result = regexec(&fPatternBuffer,text.c_str(),static_cast<size_t>(1),&matchInfo,eFlags);
		if (result == 0)
			matches = true;
		
		if (fInvertMatch)
			matches = !matches;
	}
	
	return matches;
}

//---------------------------------------------------------------------
// TRegexObj::_Reset
//---------------------------------------------------------------------
void TRegexObj::_Reset ()
{
	if (fPatternSet)
	{
		regfree(&fPatternBuffer);
		memset(&fPatternBuffer,0,sizeof(fPatternBuffer));
		fPatternSet = false;
		fServerReference = "";
	}
}

#if USE_PCRE
	//*********************************************************************
	// Class TPCREObj
	//*********************************************************************
	
	//---------------------------------------------------------------------
	// Constructor
	//---------------------------------------------------------------------
	TPCREObj::TPCREObj ()
		:	fPatternBufferPtr(NULL)
	{
	}
	
	//---------------------------------------------------------------------
	// Destructor
	//---------------------------------------------------------------------
	TPCREObj::~TPCREObj ()
	{
		_Reset();
	}
	
	//---------------------------------------------------------------------
	// TPCREObj::Setup
	//---------------------------------------------------------------------
	void TPCREObj::Setup (const string& serverReference,
						   const string& searchPattern,
						   int searchOptions)
	{
		int			result = 0;
		const char*	errMessagePtr = NULL;
		int			errOffset = 0;
		
		// Clear any current search pattern
		_Reset();
		
		fPatternBufferPtr = pcre_compile(searchPattern.c_str(),searchOptions,&errMessagePtr,&errOffset,NULL);
		if (!fPatternBufferPtr)
		{
			string		errString;
			
			errString = "Error compiling PCRE search pattern '" + searchPattern + "': " + errMessagePtr;
			
			throw TSymLibErrorObj(result,errString);
		}
		
		fServerReference = serverReference;
	}
	
	//---------------------------------------------------------------------
	// TPCREObj::IsMatch
	//---------------------------------------------------------------------
	bool TPCREObj::IsMatch (const string& text) const
	{
		bool	matches = false;
		
		if (fPatternBufferPtr)
		{
			int			result = 0;
			int			options = 0;
			int			ovectorSize = 3;
			int			ovector[ovectorSize];
			
			result = pcre_exec(fPatternBufferPtr,NULL,text.c_str(),text.length(),0,options,ovector,ovectorSize);
			if (result >= 0)
				matches = true;
			
			if (fInvertMatch)
				matches = !matches;
		}
		
		return matches;
	}
	
	//---------------------------------------------------------------------
	// TPCREObj::_Reset
	//---------------------------------------------------------------------
	void TPCREObj::_Reset ()
	{
		if (fPatternBufferPtr)
		{
			pcre_free(fPatternBufferPtr);
			fPatternBufferPtr = NULL;
			fServerReference = "";
		}
	}
#endif // USE_PCRE

//*********************************************************************
// Class TGrepSet
//*********************************************************************

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TGrepSet::TGrepSet ()
	:	fIsCompiled(false)
{
}

//---------------------------------------------------------------------
// Constructor
//---------------------------------------------------------------------
TGrepSet::TGrepSet (const TGrepSet& obj)
	:	fIsCompiled(false),
		fSearchInfoList(obj.fSearchInfoList)
{
}

//---------------------------------------------------------------------
// Destructor
//---------------------------------------------------------------------
TGrepSet::~TGrepSet ()
{
	while (!fGrepObjPtrList.empty())
	{
		if (fGrepObjPtrList.back())
			delete(fGrepObjPtrList.back());
		fGrepObjPtrList.pop_back();
	}
}

//---------------------------------------------------------------------
// TGrepSet::AddSearch
//---------------------------------------------------------------------
void TGrepSet::AddSearch (const string& serverReference,
						  const string& searchPattern,
						  const string& searchOptions)
{
	SearchInfo	info;
	
	info.serverRef = serverReference;
	info.pattern = searchPattern;
	info.options = searchOptions;
	
	fSearchInfoList.push_back(info);
}

//---------------------------------------------------------------------
// TGrepSet::AnyMatch
//---------------------------------------------------------------------
bool TGrepSet::AnyMatch (const string& text, StdStringList& foundRefList)
{
	foundRefList.clear();
	
	if (!fIsCompiled)
	{
		// We need to create our grep objects first
		for (SearchInfoList_const_iter infoIter = fSearchInfoList.begin(); infoIter != fSearchInfoList.end(); infoIter++)
		{
			bool	usePCRE = false;
			
			// Determine which type of search method to use;
			// default is to use PCRE
			
			if (infoIter->options.find(kSearchOptionUsePCRE) != string::npos)
			{
				// PCRE is explicitly requested
				#if USE_PCRE
					usePCRE = true;
				#endif
			}
			else if (infoIter->options.find(kSearchOptionUseRegex) == string::npos)
			{
				// Nothing has been explicitly requested
				#if USE_PCRE
					usePCRE = true;
				#endif
			}
			
			if (usePCRE)
			{
				#if USE_PCRE
					TPCREObj*	newObj = new TPCREObj;
					int			searchOptions = PCRE_NO_AUTO_CAPTURE;
					bool		invertMatch = false;
					
					for (size_t x = 0; x < infoIter->options.length(); x++)
					{
						char	ch = infoIter->options[x];
						
						switch (ch)
						{
							case kSearchOptionCaseInsensitive:
								searchOptions |= PCRE_CASELESS;
								break;
							
							case kSearchOptionEnableUTF8:
								{
									int		pcreOption = 0;
									
									pcre_config(PCRE_CONFIG_UTF8,&pcreOption);
									if (pcreOption == 1)
										searchOptions |= PCRE_UTF8;
								}
								break;
							
							case kSearchOptionInvertMatch:
								invertMatch = true;
								break;
						}
					}
					
					try
					{
						newObj->Setup(infoIter->serverRef,infoIter->pattern,searchOptions);
						newObj->InvertMatch(invertMatch);
						fGrepObjPtrList.push_back(newObj);
					}
					catch (...)
					{
						delete(newObj);
						throw;
					}
				#endif
			}
			else
			{
				TRegexObj*	newObj = new TRegexObj;
				int			searchOptions = REG_EXTENDED | REG_NOSUB;
				bool		invertMatch = false;
				
				for (size_t x = 0; x < infoIter->options.length(); x++)
				{
					char	ch = infoIter->options[x];
					
					switch (ch)
					{
						case kSearchOptionCaseInsensitive:
							searchOptions |= REG_ICASE;
							break;
						
						case kSearchOptionInvertMatch:
							invertMatch = true;
							break;
					}
				}
				
				try
				{
					newObj->Setup(infoIter->serverRef,infoIter->pattern,searchOptions);
					newObj->InvertMatch(invertMatch);
					fGrepObjPtrList.push_back(newObj);
				}
				catch (...)
				{
					delete(newObj);
					throw;
				}
			}
		}
		
		fIsCompiled = true;
	}
	
	for (TGrepObjPtrList_const_iter aGrepObjPtr = fGrepObjPtrList.begin(); aGrepObjPtr != fGrepObjPtrList.end(); aGrepObjPtr++)
	{
		if ((*aGrepObjPtr)->IsMatch(text))
			foundRefList.push_back((*aGrepObjPtr)->ServerReference());
	}
	
	return !foundRefList.empty();
}

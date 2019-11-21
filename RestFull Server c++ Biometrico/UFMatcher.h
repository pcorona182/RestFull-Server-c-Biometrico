/////////////////////////////////////////////////////////////////////////////
//
// UniFinger Engine SDK 3.1
//
// UFMatcher.h
// Header file for UFMatcher module
//
// Copyright (C) 2007 Suprema Inc.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef _UFMATCHER_H_
#define _UFMATCHER_H_

#ifdef WIN32
	#ifdef UFM_EXPORTS
		#define UFM_API __declspec(dllexport) __stdcall
	#else
		#define UFM_API __stdcall
	#endif
#else
	#define UFM_API
#endif

#ifdef __cplusplus
extern "C" {
#endif


// Status Definition
#define UFM_STATUS						int

// Status Return Values
#define UFM_OK							0
#define UFM_ERROR						-1
#define UFM_ERR_NO_LICENSE				-101
#define UFM_ERR_LICENSE_NOT_MATCH		-102
#define UFM_ERR_LICENSE_EXPIRED			-103
#define UFM_ERR_NOT_SUPPORTED			-111
#define UFM_ERR_INVALID_PARAMETERS		-112
// For Matching
#define UFM_ERR_MATCH_TIMEOUT			-401
#define UFM_ERR_MATCH_ABORTED			-402
#define UFM_ERR_TEMPLATE_TYPE			-411

// Parameters
#define UFM_PARAM_FAST_MODE				301
#define UFM_PARAM_SECURITY_LEVEL		302
#define UFM_PARAM_USE_SIF				311
//
#define UFM_TEMPLATE_TYPE_SUPREMA		2001
#define UFM_TEMPLATE_TYPE_ISO19794_2	2002
#define UFM_TEMPLATE_TYPE_ANSI378		2003


typedef void* HUFMatcher;


UFM_STATUS UFM_API UFM_Create(HUFMatcher* phMatcher);
UFM_STATUS UFM_API UFM_Delete(HUFMatcher hMatcher);

UFM_STATUS UFM_API UFM_GetParameter(HUFMatcher hMatcher, int nParam, void* pValue);
UFM_STATUS UFM_API UFM_SetParameter(HUFMatcher hMatcher, int nParam, void* pValue);

UFM_STATUS UFM_API UFM_Verify(HUFMatcher hMatcher, unsigned char* pTemplate1, int nTemplate1Size, unsigned char* pTemplate2, int nTemplate2Size, int* bVerifySucceed);

UFM_STATUS UFM_API UFM_Identify(HUFMatcher hMatcher, unsigned char* pTemplate1, int nTemplate1Size, unsigned char** ppTemplate2, int* pnTemplate2Size, int nTemplate2Num, int nTimeout, int* pnMatchTemplate2Index);
UFM_STATUS UFM_API UFM_AbortIdentify(HUFMatcher hMatcher);

UFM_STATUS UFM_API UFM_IdentifyInit(HUFMatcher hMatcher, unsigned char* pTemplate1, int nTemplate1Size);
UFM_STATUS UFM_API UFM_IdentifyNext(HUFMatcher hMatcher, unsigned char* pTemplate2, int nTemplate2Size, int* bIdentifySucceed);

UFM_STATUS UFM_API UFM_RotateTemplate(HUFMatcher hMatcher, unsigned char* pTemplate, int nTemplateSize);

UFM_STATUS UFM_API UFM_GetErrorString(UFM_STATUS res, char* szErrorString);

UFM_STATUS UFM_API UFM_SetTemplateType(HUFMatcher hMatcher, int nTemplateType);
UFM_STATUS UFM_API UFM_GetTemplateType(HUFMatcher hMatcher, int *nTemplateType);


#ifdef __cplusplus
}
#endif

#endif // _UFMATCHER_H_
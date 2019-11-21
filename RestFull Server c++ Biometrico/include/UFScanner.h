/////////////////////////////////////////////////////////////////////////////
//
// UniFinger Engine SDK 3.5
//
// UFScanner.h
// Header file for UFScanner module
//
// Copyright (C) 2013 Suprema Inc.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef _UFSCANNER_H_
#define _UFSCANNER_H_

#ifdef WIN32
	#ifdef UFS_EXPORTS
		#define UFS_API __declspec(dllexport) __stdcall
	#else
		#define UFS_API __stdcall
	#endif
	#define UFS_CALLBACK __stdcall
#else
	#define UFS_API
	#define UFS_API
	#define UFS_CALLBACK
#endif

#ifdef __cplusplus
extern "C" {
#endif


// Status Definition
#define UFS_STATUS						int

// Status Return Values
#define UFS_OK							0
#define UFS_ERROR						-1
#define UFS_ERR_NO_LICENSE				-101
#define UFS_ERR_LICENSE_NOT_MATCH		-102
#define UFS_ERR_LICENSE_EXPIRED			-103
#define UFS_ERR_NOT_SUPPORTED			-111
#define UFS_ERR_INVALID_PARAMETERS		-112
// For Scanner
#define UFS_ERR_ALREADY_INITIALIZED		-201
#define UFS_ERR_NOT_INITIALIZED			-202
#define UFS_ERR_DEVICE_NUMBER_EXCEED	-203
#define UFS_ERR_LOAD_SCANNER_LIBRARY	-204
#define UFS_ERR_CAPTURE_RUNNING			-211
#define UFS_ERR_CAPTURE_FAILED			-212
// For Extraction
#define UFS_ERR_NOT_GOOD_IMAGE			-301
#define UFS_ERR_EXTRACTION_FAILED		-302
// For Extraction: Core Detection
#define UFS_ERR_CORE_NOT_DETECTED		-351
#define UFS_ERR_CORE_TO_LEFT			-352
#define UFS_ERR_CORE_TO_LEFT_TOP		-353
#define UFS_ERR_CORE_TO_TOP				-354
#define UFS_ERR_CORE_TO_RIGHT_TOP		-355
#define UFS_ERR_CORE_TO_RIGHT			-356
#define UFS_ERR_CORE_TO_RIGHT_BOTTOM	-357
#define UFS_ERR_CORE_TO_BOTTOM			-358
#define UFS_ERR_CORE_TO_LEFT_BOTTOM		-359
//
#define	UFS_ERR_FAKE_FINGER				-221
//
#define UFS_ERR_FINGER_ON_SENSOR		-231

// Parameters
// For Scanner
#define UFS_PARAM_TIMEOUT				201
#define UFS_PARAM_BRIGHTNESS		202
#define UFS_PARAM_SENSITIVITY		203
#define UFS_PARAM_SERIAL				204
// For Extraction
#define UFS_PARAM_DETECT_CORE			301
#define UFS_PARAM_TEMPLATE_SIZE			302
#define UFS_PARAM_USE_SIF				311

#define UFS_PARAM_DETECT_FAKE			312

// Scanner Type
#define UFS_SCANNER_TYPE_SFR200			1001
#define UFS_SCANNER_TYPE_SFR300			1002
#define UFS_SCANNER_TYPE_SFR300v2		1003
#define UFS_SCANNER_TYPE_SFR500			1004
#define UFS_SCANNER_TYPE_SFR600			1005

/////////////////////////////////////////////////////
#define UFS_TEMPLATE_TYPE_SUPREMA               2001
#define UFS_TEMPLATE_TYPE_ISO19794_2            2002
#define UFS_TEMPLATE_TYPE_ANSI378               2003
/////////////////////////////////////////////////////

typedef void* HUFScanner;

typedef int UFS_CALLBACK UFS_SCANNER_PROC(const char* szScannerID, int bSensorOn, void* pParam);
typedef int UFS_CALLBACK UFS_CAPTURE_PROC(HUFScanner hScanner, int bFingerOn, unsigned char* pImage, int nWidth, int nHeight, int nResolution, void* pParam);


UFS_STATUS UFS_API UFS_Init();
UFS_STATUS UFS_API UFS_Update();
UFS_STATUS UFS_API UFS_Uninit();

UFS_STATUS UFS_API UFS_SetScannerCallback(UFS_SCANNER_PROC* pScannerProc, void* pParam);
UFS_STATUS UFS_API UFS_RemoveScannerCallback();

UFS_STATUS UFS_API UFS_GetScannerNumber(int* pnScannerNumber);
UFS_STATUS UFS_API UFS_GetScannerHandle(int nScannerIndex, HUFScanner* phScanner);
UFS_STATUS UFS_API UFS_GetScannerHandleByID(const char* szScannerID, HUFScanner* phScanner);
UFS_STATUS UFS_API UFS_GetScannerIndex(HUFScanner hScanner, int* pnScannerIndex);
UFS_STATUS UFS_API UFS_GetScannerID(HUFScanner hScanner, char* szScannerID);
UFS_STATUS UFS_API UFS_GetCompanyID(HUFScanner hScanner, char* szCompanyID);
UFS_STATUS UFS_API UFS_GetScannerType(HUFScanner hScanner, int* pnScannerType);

UFS_STATUS UFS_API UFS_GetParameter(HUFScanner hScanner, int nParam, void* pValue);
UFS_STATUS UFS_API UFS_SetParameter(HUFScanner hScanner, int nParam, void* pValue);

UFS_STATUS UFS_API UFS_IsSensorOn(HUFScanner hScanner, int* pbSensorOn);
UFS_STATUS UFS_API UFS_IsFingerOn(HUFScanner hScanner, int* pbFingerOn);

UFS_STATUS UFS_API UFS_CaptureSingleImage(HUFScanner hScanner);
UFS_STATUS UFS_API UFS_StartCapturing(HUFScanner hScanner, UFS_CAPTURE_PROC* pCaptureProc, void* pParam);
UFS_STATUS UFS_API UFS_StartAutoCapture(HUFScanner hScanner, UFS_CAPTURE_PROC* pCaptureProc, void* pParam);
UFS_STATUS UFS_API UFS_IsCapturing(HUFScanner hScanner, int* pbCapturing);
UFS_STATUS UFS_API UFS_AbortCapturing(HUFScanner hScanner);

UFS_STATUS UFS_API UFS_Extract(HUFScanner hScanner, unsigned char* pTemplate, int* pnTemplateSize, int* pnEnrollQuality);
UFS_STATUS UFS_API UFS_ExtractEx(HUFScanner hScanner, int nBufferSize, unsigned char* pTemplate, int* pnTemplateSize, int* pnEnrollQuality);

UFS_STATUS UFS_API UFS_SetEncryptionKey(HUFScanner hScanner, unsigned char* pKey);
UFS_STATUS UFS_API UFS_EncryptTemplate(HUFScanner hScanner, unsigned char* pTemplateInput, int nTemplateInputSize, unsigned char* pTemplateOutput, int* pnTemplateOutputSize);
UFS_STATUS UFS_API UFS_DecryptTemplate(HUFScanner hScanner, unsigned char* pTemplateInput, int nTemplateInputSize, unsigned char* pTemplateOutput, int* pnTemplateOutputSize);

UFS_STATUS UFS_API UFS_GetCaptureImageBufferInfo(HUFScanner hScanner, int* pnWidth, int* pnHeight, int* pnResolution);
UFS_STATUS UFS_API UFS_GetCaptureImageBuffer(HUFScanner hScanner, unsigned char* pImageData);
UFS_STATUS UFS_API UFS_SaveCaptureImageBufferToBMP(HUFScanner hScanner, char* szFileName);

#ifdef WIN32
UFS_STATUS UFS_API UFS_DrawCaptureImageBuffer(HUFScanner hScanner, HDC hDC, int nLeft, int nTop, int nRight, int nBottom, int bCore);
UFS_STATUS UFS_API UFS_SaveCaptureImageBufferToBMP(HUFScanner hScanner, char* szFileName);
#endif
UFS_STATUS UFS_API UFS_SaveCaptureImageBufferToWSQ(HUFScanner hScanner, const float ratio, char* szFileName);
UFS_STATUS UFS_API UFS_SaveCaptureImageBufferTo19794_4(HUFScanner hScanner, char* szFileName);
UFS_STATUS UFS_API UFS_ClearCaptureImageBuffer(HUFScanner hScanner);

UFS_STATUS UFS_API UFS_GetErrorString(UFS_STATUS res, char* szErrorString);

UFS_STATUS UFS_API UFS_SetTemplateType(HUFScanner hScanner, int nTemplateType);
UFS_STATUS UFS_API UFS_GetTemplateType(HUFScanner hScanner, int *nTemplateType);

UFS_STATUS UFS_API UFS_SelectTemplate(HUFScanner hScanner, unsigned char** ppTemplateInput, int* pnTemplateInputSize, int nTemplateInputNum, unsigned char** ppTemplateOutput, int* pnTemplateOutputSize, int nTemplateOutputNum);
UFS_STATUS UFS_API UFS_SelectTemplateEx(HUFScanner hScanner, int nBufferSize, unsigned char** ppTemplateInput, int* pnTemplateInputSize, int nTemplateInputNum, unsigned char** ppTemplateOutput, int* pnTemplateOutputSize, int nTemplateOutputNum);

UFS_STATUS UFS_API UFS_GetNFIQScore(HUFScanner hScanner, int* pnNFIQ);

#ifdef __cplusplus
}
#endif

#endif // _UFSCANNER_H_

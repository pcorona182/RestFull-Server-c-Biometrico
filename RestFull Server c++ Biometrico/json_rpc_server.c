/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 *
 * To test this server, do
 *   $ curl -d '{"id":1,method:"sum",params:[22,33]}' 192.168.10.200:17000
 */
#ifndef WIN32
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

typedef int BOOL;
#define TRUE 1
#define FALSE 0
#else
#include <windows.h>
#include <stdio.h>
#endif
//
#include "mongoose.h"
#include "include/UFScanner.h"
#include "include/UFMatcher.h"



#define MAX_TEMPLATE_SIZE 1024
#define MAX_TEMPLATE_NUM 1// espacio para 3 templates

#define MAX_TEMPLATE_INPUT_NUM 4
#define MAX_TEMPLATE_OUTPUT_NUM 2
#define AddMessage printf
HUFMatcher m_hMatcher;

char m_strError[128];

unsigned char* m_template[MAX_TEMPLATE_NUM];
int m_template_size[MAX_TEMPLATE_NUM];
unsigned char* m_template2[MAX_TEMPLATE_NUM];
int m_template_size2[MAX_TEMPLATE_NUM];
int m_template_num;

unsigned char* m_enrolltemplate[MAX_TEMPLATE_NUM];
int m_enrolltemplateSize[MAX_TEMPLATE_NUM];

int m_nBrightness;
int m_nSensitivity;
BOOL m_bDetectCore;
int m_nSecurityLevel;
int m_nTimeout;
BOOL m_bFastMode;
int m_nEnrollQuality;
int m_nSelectID;
int m_nCurScannerIndex;
static const char *s_http_port = "17000";



unsigned char Template[MAX_TEMPLATE_SIZE];
int TemplateSize;
int nEnrollQuality;
int bVerifySucceed;
HUFScanner hScanner;
UFS_STATUS ufs_res;
UFM_STATUS ufm_res;


/////////////////////////////////////////////////////////////////////////////
// Inicio Scanner
/////////////////////////////////////////////////////////////////////////////

BOOL GetCurrentScannerHandle(HUFScanner* phScanner) {
    int nCurScannerIndex;
    UFS_STATUS ufs_res;

    nCurScannerIndex = m_nCurScannerIndex;
    ufs_res = UFS_GetScannerHandle(nCurScannerIndex, phScanner);
    if (ufs_res == UFS_OK) {
        return TRUE;
    } else {
        return FALSE;
    }
}

void GetCurrentScannerSettings() {
    HUFScanner hScanner;
    int value;

    if (!GetCurrentScannerHandle(&hScanner)) {
        AddMessage("There's no scanner detected.\n");
        return;
    }

    printf("\n");
    printf("Scanner Parameters:\n");
    printf("-------------------\n");

    // Unit of timeout is millisecond
    UFS_GetParameter(hScanner, UFS_PARAM_TIMEOUT, &value);
    m_nTimeout = value / 1000;
    printf("Timeout = %d sec\n", m_nTimeout);

    UFS_GetParameter(hScanner, UFS_PARAM_BRIGHTNESS, &value);
    m_nBrightness = value;
    printf("Brightness = %d\n", m_nBrightness);

    UFS_GetParameter(hScanner, UFS_PARAM_SENSITIVITY, &value);
    m_nSensitivity = value;
    printf("Sensitivity = %d\n", m_nSensitivity);

    UFS_GetParameter(hScanner, UFS_PARAM_DETECT_CORE, &value);
    m_bDetectCore = value;
    printf("Detect Core = %d\n", m_bDetectCore);

    UFS_GetParameter(hScanner, UFS_PARAM_DETECT_FAKE, &value);
    printf("Detect Fake = %d\n", value);

    printf("-------------------\n");
}

void GetMatcherSettings(HUFMatcher hMatcher) {
    int value;

    printf("\n");
    printf("Matcher Parameters:\n");
    printf("-------------------\n");

    // Security level ranges from 1 to 7
    UFM_GetParameter(hMatcher, UFM_PARAM_SECURITY_LEVEL, &value);
    m_nSecurityLevel = value;
    printf("Security Level = %d\n", m_nSecurityLevel);

    UFM_GetParameter(hMatcher, UFM_PARAM_FAST_MODE, &value);
    m_bFastMode = value;
    printf("Fast Mode = %d\n", m_bFastMode);

    printf("-------------------\n");
}

void GetScannerTypeString(int nScannerType, char* strScannerType) {
    switch (nScannerType) {
        case UFS_SCANNER_TYPE_SFR200:
            sprintf(strScannerType, "SFR200");
            break;
        case UFS_SCANNER_TYPE_SFR300:
            sprintf(strScannerType, "SFR300");
            break;
        case UFS_SCANNER_TYPE_SFR300v2:
            sprintf(strScannerType, "SFR300v2");
            break;
        case UFS_SCANNER_TYPE_SFR500:
            sprintf(strScannerType, "SFR500");
            break;
        case UFS_SCANNER_TYPE_SFR600:
            sprintf(strScannerType, "SFR600");
            break;
        default:
            sprintf(strScannerType, "Error");
            break;
    }
}

void UpdateScannerList() {
    UFS_STATUS ufs_res;
    int nScannerNumber;
    int i;

    ufs_res = UFS_GetScannerNumber(&nScannerNumber);
    if (ufs_res != UFS_OK) {
        UFS_GetErrorString(ufs_res, m_strError);
        AddMessage("UFS_GetScannerNumber: %s\r\n", m_strError);
        return;
    }

    for (i = 0; i < nScannerNumber; i++) {
        HUFScanner hScanner;
        int nScannerType;
        char strScannerType[64];
        char strID[64];
        char CID[8];

        ufs_res = UFS_GetScannerHandle(i, &hScanner);
        if (ufs_res != UFS_OK) {
            continue;
        }
        UFS_GetScannerType(hScanner, &nScannerType);
        UFS_GetScannerID(hScanner, strID);
        GetScannerTypeString(nScannerType, strScannerType);

        AddMessage("Scanner %d: %s ID: %s \r\n", i, strScannerType, strID);
    }

    if (nScannerNumber > 0) {
        m_nCurScannerIndex = 0;
        GetCurrentScannerSettings();
    }
}

int UFS_CALLBACK ScannerProc(const char* szScannerID, int bSensorOn, void* pParam) {
    if (bSensorOn) {
        // We cannot call UpdateData() directly from the different thread,
        // so we use PostMessage() to call UpdateScannerList() indirectly
        AddMessage("\n");
        AddMessage("----------------------------------------\n");
        AddMessage("Scanner (ID = %s) is connected\n", szScannerID);
        AddMessage("----------------------------------------\n");
    } else {
        AddMessage("\n");
        AddMessage("----------------------------------------\n");
        AddMessage("Scanner (ID = %s) is disconnected\n", szScannerID);
        AddMessage("----------------------------------------\n");
    }

    return 1;
}

int OnInit() {
    /////////////////////////////////////////////////////////////////////////////
    // Initilize scanner module and get scanner list
    /////////////////////////////////////////////////////////////////////////////
    UFS_STATUS ufs_res;
    int nScannerNumber;

    ufs_res = UFS_Init();
    if (ufs_res == UFS_OK) {
        AddMessage("UFS_Init: OK\r\n");
    } else {
        UFS_GetErrorString(ufs_res, m_strError);
        AddMessage("UFS_Init: %s\r\n", m_strError);
        return 20;
    }

    ufs_res = UFS_SetScannerCallback(ScannerProc, NULL);
    if (ufs_res == UFS_OK) {
        AddMessage("UFS_SetScannerCallback: OK\r\n");
    } else {
        UFS_GetErrorString(ufs_res, m_strError);
        AddMessage("UFS_SetScannerCallback: %s\r\n", m_strError);
        return 21;
    }

    ufs_res = UFS_GetScannerNumber(&nScannerNumber);
    if (ufs_res == UFS_OK) {
        AddMessage("UFS_GetScannerNumber: %d\r\n", nScannerNumber);
    } else {
        UFS_GetErrorString(ufs_res, m_strError);
        AddMessage("UFS_GetScannerNumber: %s\r\n", m_strError);
        return 22;
    }

    UpdateScannerList();
    /////////////////////////////////////////////////////////////////////////////

    /////////////////////////////////////////////////////////////////////////////
    // Create one matcher
    /////////////////////////////////////////////////////////////////////////////
    UFM_STATUS ufm_res;

    ufm_res = UFM_Create(&m_hMatcher);
    if (ufm_res == UFM_OK) {
        AddMessage("UFM_Create: OK\r\n");
    } else {
        UFM_GetErrorString(ufm_res, m_strError);
        AddMessage("UFM_Create: %s\r\n", m_strError);
        return 23;
    }

    GetMatcherSettings(m_hMatcher);
    return 1;
    /////////////////////////////////////////////////////////////////////////////
}
/////////////////////////////////////////////////////////////////////////////
// Fin Inicio scanner
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
//  Inicio Set Template
/////////////////////////////////////////////////////////////////////////////

int OnSetTemplateType() {
    HUFScanner hScanner;

    if (m_template_num > 0) {
        AddMessage("Template type cannot be changed if one or more template enrolled\n");
        return 10;
    }

    if (!GetCurrentScannerHandle(&hScanner)) {
        AddMessage("There's no scanner detected.\n");
        return 11;
    }

    printf("template type\n");
    printf("1.suprema type\n");

    switch (1) {

        case 1:
            UFS_SetTemplateType(hScanner, UFS_TEMPLATE_TYPE_SUPREMA);
            UFM_SetTemplateType(m_hMatcher, UFS_TEMPLATE_TYPE_SUPREMA);
            printf("template type:suprema");
            return 1;
            break;
        case 2:
            UFS_SetTemplateType(hScanner, UFS_TEMPLATE_TYPE_ISO19794_2);
            UFM_SetTemplateType(m_hMatcher, UFS_TEMPLATE_TYPE_ISO19794_2);
            printf("template type:iso");
            return 12;
            break;
        case 3:
            UFS_SetTemplateType(hScanner, UFS_TEMPLATE_TYPE_ANSI378);
            UFM_SetTemplateType(m_hMatcher, UFS_TEMPLATE_TYPE_ANSI378);
            printf("template type:ansi");
            return 13;
            break;
        default:
            printf("check number..\n");
            return 14;
    }
    printf("-------------------\n");


}
/////////////////////////////////////////////////////////////////////////////
//  fin Set Template
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//  inicio Set Identifica
/////////////////////////////////////////////////////////////////////////////

int setFinger() {
    if (!GetCurrentScannerHandle(&hScanner)) {
        AddMessage("There's no scanner detected.\n");
        return 10;
    }
    UFS_ClearCaptureImageBuffer(hScanner);


    ufs_res = UFS_CaptureSingleImage(hScanner);
    if (ufs_res != UFS_OK) {
        UFS_GetErrorString(ufs_res, m_strError);
        AddMessage("UFS_CaptureSingleImage: %s\r\n", m_strError);
        return 12;
    }

    ufs_res = UFS_ExtractEx(hScanner, MAX_TEMPLATE_SIZE, Template, &TemplateSize, &nEnrollQuality);
    if (ufs_res == UFS_OK) {
    } else {
        UFS_GetErrorString(ufs_res, m_strError);
        AddMessage("UFS_ExtractEx: %s\r\n", m_strError);
        return 13;
    }
    return 1;
}

int OnCompare() {
    int i = 0;
    if (!GetCurrentScannerHandle(&hScanner)) {
        AddMessage("There's no scanner detected.\n");
        return 10;
    }
    UFS_ClearCaptureImageBuffer(hScanner);

    if (m_template_num <= 0) {
        AddMessage("There no enrolled finger.\n");
        return 11;
    } else {
        AddMessage("There are %d fingers enrolled.\n", m_template_num);
    }

    

    int nMatchIndex;
    //// este compara
    //ufm_res = UFM_Verify(m_hMatcher, Template, TemplateSize, m_template[m_nSelectID], m_template_size[m_nSelectID], &bVerifySucceed);
    ufm_res = UFM_Identify(m_hMatcher, Template, TemplateSize, m_template, m_template_size, 1, 5000, &nMatchIndex);

    if (ufm_res != UFM_OK) {
        UFM_GetErrorString(ufm_res, m_strError);
        AddMessage("UFM_Identify: %s\r\n", m_strError);
        return 14;
        //goto errret;
    }

    if (nMatchIndex != -1) {
        AddMessage("Identification succeed (No.%d)\r\n", 1);
        return 1;
    } else {
        AddMessage("Identification failed\r\n");
        return 15;
    }





}

int OnPlace(char *buf, int len) {
    HUFScanner hScanner;
    int i = 0;

    m_nSelectID = 0; // fuerza el ID 0 de las plantillas 
    m_template[0] = buf;
    m_template[1] = buf;
    m_template_size[0] = len;
    m_template_size[1] = len;
    

    if (!GetCurrentScannerHandle(&hScanner)) {
        AddMessage("There's no scanner detected.\n");
        return 10;
    }
    UFS_ClearCaptureImageBuffer(hScanner);

    if (m_template_num <= 0) {
        AddMessage("There no enrolled finger.\n");
        return 11;
    } else {
        AddMessage("There are %d fingers enrolled.\n", m_template_num);
    }


    /////////////////
    //AddMessage("Place a finger\r\n");
    return 1;

}

/////////////////////////////////////////////////////////////////////////////
//  fin Identifica
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
// Funciones RPC
/////////////////////////////////////////////////////////////////////////////

static int rpc_setFinger(char *buf, int len, struct mg_rpc_request *req) {
    int estado = 0;
    if (req->params[0].type != JSON_TYPE_ARRAY) {
        return mg_rpc_create_std_error(buf, len, req,
                JSON_RPC_INVALID_PARAMS_ERROR);
    } else {
        estado = setFinger();

    }

    return mg_rpc_create_reply(buf, len, req, "i", estado);
}

static int rpc_Compara(char *buf, int len, struct mg_rpc_request *req) {
    int estado ,i = 0;
    //char sum [] =  "Vamos Cu !!!";


    if (req->params[0].type != JSON_TYPE_ARRAY) {
        return mg_rpc_create_std_error(buf, len, req,
                JSON_RPC_INVALID_PARAMS_ERROR);
    }
    //m_template_num = 1;

    estado = OnCompare();


    m_template_num = 0;
    
    
    for (i = 0; i < MAX_TEMPLATE_SIZE -1; i++) {
        m_template[0][i] = 0x00;
        m_template[1][i] = 0x00;
    }
    
    return mg_rpc_create_reply(buf, len, req, "i", estado);
    //return mg_rpc_create_reply(buf, len, req, "s", sum);
}

static int rpc_Place(char *buf, int len, struct mg_rpc_request *req) {
    int estado ,i , tamano= 0;
    //char sum [] =  "Vamos Cu !!!";


    if (req->params[0].type != JSON_TYPE_ARRAY) {
        return mg_rpc_create_std_error(buf, len, req,
                JSON_RPC_INVALID_PARAMS_ERROR);
    }
    m_template_num = 1;

    //Talvez Convertir a Unbsigend int
    //y = static_cast<unsigned char>(x); 
    
    
    printf("primer caracter = %d ",buf[0]);
    estado = OnPlace(buf, tamano);


    //m_template_num = 0;
    return mg_rpc_create_reply(buf, len, req, "i", estado);
    //return mg_rpc_create_reply(buf, len, req, "s", sum);
}

static int rpc_IniScanner(char *buf, int len, struct mg_rpc_request *req) {
    int estadoInit = 0;
    if (req->params[0].type != JSON_TYPE_ARRAY) {
        return mg_rpc_create_std_error(buf, len, req,
                JSON_RPC_INVALID_PARAMS_ERROR);
    } else {
        estadoInit = OnInit();
        if (estadoInit == 1) {
            estadoInit = OnSetTemplateType();
        }
    }

    return mg_rpc_create_reply(buf, len, req, "i", estadoInit);
}

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
    int i = 0;
    struct http_message *hm = (struct http_message *) ev_data;
    static const char *methods[] = {"Place", "IniScanner", "Compara", "setDedo", NULL};
    static mg_rpc_handler_t handlers[] = {rpc_Place, rpc_IniScanner, rpc_Compara, rpc_setFinger, NULL};
    char buf[MAX_TEMPLATE_SIZE] = {0x00}; //espacio para 1 templates

    switch (ev) {
        case MG_EV_HTTP_REQUEST:
            mg_rpc_dispatch(hm->body.p, hm->body.len, buf, sizeof (buf),
                    methods, handlers);
            mg_printf(nc, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n"
                    "Content-Type: application/json\r\n\r\n%s",
                    (int) strlen(buf), buf);
            nc->flags |= MG_F_SEND_AND_CLOSE;
            break;
        default:
            break;
    }
}
/////////////////////////////////////////////////////////////////////////////
// Fin Funciones RPC
/////////////////////////////////////////////////////////////////////////////

//Inicio
//$  curl -d '{"id":1,method:"IniScanner",params:[1]}' 192.168.10.200:17000
////1= 0k inicio
////20 = ya esta inciiado 
///11 no hay scanner
////cualquier otro hay falla


//curl -d '{"id":1,method:"setDedo",params:[]}' 192.168.10.200:17000

//// 
//$  curl -d '{"id":1,method:"Place",params:[]}' 192.168.10.200:17000
////1 = ok exito
///2 = scanner no conectado

//$  curl -d '{"id":1,method:"Compara",params:[]}' 192.168.10.200:17000
////1 huella encontrada
/// 2 y 3 huella no encontrada
/// 10 scanner no conectado
/// cualquier otro error

int main(void) {
    struct mg_mgr mgr;
    struct mg_connection *nc;
    int i;

    /////////////////////////////////////////////////////////////////////////////	
    for (i = 0; i < MAX_TEMPLATE_NUM; i++) {
        m_template[i] = (unsigned char*) malloc(MAX_TEMPLATE_SIZE);
        m_template2[i] = (unsigned char*) malloc(MAX_TEMPLATE_SIZE);
        memset(m_template[i], 0, MAX_TEMPLATE_SIZE);
        memset(m_template2[i], 0, MAX_TEMPLATE_SIZE);
        m_template_size[i] = 0;
        m_template_size2[i] = 0;
    }
    m_template_num = 0;
    m_hMatcher = NULL;
    m_nBrightness = -1;
    m_nSensitivity = -1;
    m_bDetectCore = FALSE;
    m_nSecurityLevel = 4;
    m_nTimeout = -1;
    m_bFastMode = FALSE;
    m_nEnrollQuality = 0;
    m_nSelectID = -1;
    m_nCurScannerIndex = 0;
    /////////////////////////////////////////////////////////////////////////////    


    mg_mgr_init(&mgr, NULL);
    nc = mg_bind(&mgr, s_http_port, ev_handler);
    mg_set_protocol_http_websocket(nc);

    printf("Starting JSON-RPC server on port %s\n", s_http_port);
    for (;;) {
        mg_mgr_poll(&mgr, 100000);
    }
    mg_mgr_free(&mgr);

    return 0;
}

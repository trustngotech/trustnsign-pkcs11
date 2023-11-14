/*
 *  Copyright 2023-2024 TrustnGo S.A.S
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef __REST_INTERFACE_PRIVATE_H__
#define __REST_INTERFACE_PRIVATE_H__

#include <json-c/json.h>
#include <curl/curl.h>
#include "pkcs11.h"

#define ENSURE_OR_EXIT(cond, error) \
    if (!(cond)) { \
        err2str(error, __FUNCTION__); \
        ret = -(error); \
        goto exit; \
    } \

// #define ENSURE_OR_EXIT(cond, error) assert((cond))

typedef enum pkcs11_types {
    PKCS11_BOOL = 0,
    PKCS11_UCHAR,
    PKCS11_ULONG,
    PKCS11_UCHAR_ARRAY,
    PKCS11_STRING,
} pkcs11_type_t;

typedef struct type_mapping {
    pkcs11_type_t pkcs11;
    enum json_type json;
} type_mapping_t;

typedef struct ck_object {
    CK_ATTRIBUTE_PTR pAttributes;
    size_t len;
} ck_object_t;

typedef struct ck_object_list {
    ck_object_t *pObjects;
    size_t len;
} ck_object_list_t;

typedef struct attribute_template{
    const CK_ATTRIBUTE_TYPE type;
    const char *key;
    const pkcs11_type_t  dtype;
} attribute_template_t;

/* holder for curl fetch */
struct curl_fetch_st {
    char *payload;
    size_t size;
};

typedef struct interface_ctx {
    int isCurlGlobalInit;
    CK_OBJECT_HANDLE hObject;
    CURL *hCurl;
    char *urlBase;
    ck_object_list_t objList;

} interface_ctx_t;

static interface_ctx_t ctx = {0};

static const attribute_template_t ATTRIBUTE_TABLE[] = 
{
    {CKA_CLASS,             "class",                PKCS11_ULONG},
    {CKA_ID,                "id",                   PKCS11_UCHAR_ARRAY},
    {CKA_LABEL,             "label",                PKCS11_STRING},
    {CKA_KEY_TYPE,          "key_type",             PKCS11_ULONG},
    {CKA_SIGN,              "sign",                 PKCS11_BOOL},
    {CKA_NEVER_EXTRACTABLE, "never_extractable",    PKCS11_BOOL},
    {CKA_EC_PARAMS,         "ec_params",            PKCS11_UCHAR_ARRAY},
    {CKA_EC_POINT,          "ec_point",             PKCS11_UCHAR_ARRAY},
    {CKA_MODULUS_BITS,      "modulus_bits",         PKCS11_ULONG},
    {CKA_MODULUS,           "modulus",              PKCS11_UCHAR_ARRAY},
    {CKA_PUBLIC_EXPONENT,   "public_exponent",      PKCS11_UCHAR_ARRAY},
    {CKA_VALUE,             "value",                PKCS11_UCHAR_ARRAY},
    {CKA_CERTIFICATE_TYPE,  "certificate_type",     PKCS11_ULONG},
    {CKA_SERIAL_NUMBER,     "serial_number",        PKCS11_UCHAR_ARRAY},
    {CKA_SUBJECT,           "subject",              PKCS11_STRING},
};
const size_t ATTRIBUTE_TABLE_LEN = sizeof(ATTRIBUTE_TABLE)/sizeof(ATTRIBUTE_TABLE[0]);

/* To allow easy indexing, mapping order should match the order of the labels in the pkcs11_type_t enum */
static const type_mapping_t TYPE_MAPPING[] =
{
    {.pkcs11 = PKCS11_BOOL, .json = json_type_boolean},
    {.pkcs11 = PKCS11_UCHAR, .json = json_type_int},
    {.pkcs11 = PKCS11_ULONG, .json = json_type_int},
    {.pkcs11 = PKCS11_UCHAR_ARRAY, .json = json_type_string},
    {.pkcs11 = PKCS11_STRING, .json = json_type_string},
};

#define TNS_OK 0
#define TNS_ERR_BAD_ARGUMENT 1
#define TNS_ERR_MEMORY_ALLOCATION 2
#define TNS_ERR_BAD_PIN_FORMAT 3
#define TNS_ERR_INAVLID_JSON 4
#define TNS_ERR_OBJECT_CREATION_FAILED 5
#define TNS_ERR_ATTRIBUTE_CREATION_FAILED 6
#define TNS_ERR_ENV_NOT_SET 7
#define TNS_ERR_CURL 9
#define TNS_ERR_BUFFER_TOO_SMALL 10
#define TNS_ERR_SERVER_COM 11
#define TNS_ERR_SIGN_OPERATION_FAILURE 12
#define TNS_UNDEFINED 99

static void err2str(const int err, const char* func)
{
    char *msg;
    switch(err)
    {
        case TNS_ERR_BAD_ARGUMENT:
            msg = "TNS_ERR_BAD_ARGUMENT";
            break;
        case TNS_ERR_MEMORY_ALLOCATION:
            msg = "TNS_ERR_MEMORY_ALLOCATION";
            break;
        case TNS_ERR_BAD_PIN_FORMAT:
            msg = "TNS_ERR_BAD_PIN_FORMAT";
            break;
        case TNS_ERR_INAVLID_JSON:
            msg = "TNS_ERR_INAVLID_JSON";
            break;
        case TNS_ERR_OBJECT_CREATION_FAILED:
            msg = "TNS_ERR_INVALID_OBJECT";
            break;
        case TNS_ERR_ATTRIBUTE_CREATION_FAILED:
            msg = "TNS_ERR_ATTRIBUTE_CREATION_FAILED";
            break;
        case TNS_ERR_ENV_NOT_SET:
            msg = "TNS_ERR_ENV_NOT_SET";
            break;
        case TNS_ERR_CURL:
            msg = "TNS_ERR_CURL";
            break;
        case TNS_ERR_BUFFER_TOO_SMALL:
            msg = "TNS_ERR_BUFFER_TOO_SMALL";
            break;
        case TNS_ERR_SERVER_COM:
            msg = "TNS_ERR_SERVER_COM";
            break;
        case TNS_ERR_SIGN_OPERATION_FAILURE:
            msg = "TNS_ERR_SIGN_OPERATION_FAILURE";
            break;
        case TNS_UNDEFINED:
            msg = "TNS_UNDEFINED";
            break;
        default:
            msg = "TNS_ERR_PKCS11_OR_UNKNOWN";
            break;
    }
    printf("TrustnSign error = %s (%d) in %s\n", msg, err, func);
}

#endif /* #ifndef __REST_INTERFACE_PRIVATE_H__ */
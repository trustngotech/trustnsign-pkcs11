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


/* standard includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

/* json-c (https://github.com/json-c/json-c) */
#include <json-c/json.h>

/* libcurl (http://curl.haxx.se/libcurl/c) */
#include <curl/curl.h>

#include "base64.h"
#include "pkcs11.h"
#include "rest_interface.h"
#include "rest_interface_private.h"

static size_t curl_callback (void *contents, size_t size, size_t nmemb, void *userp) {
    size_t ret = 0;
    size_t realsize = size * nmemb;                             /* calculate buffer size */
    struct curl_fetch_st *p = (struct curl_fetch_st *) userp;   /* cast pointer to fetch struct */

    ENSURE_OR_EXIT(NULL != contents, 0);
    ENSURE_OR_EXIT(NULL != userp, 0);

    /* expand buffer using a temporary pointer to avoid memory leaks */
    char * temp = realloc(p->payload, p->size + realsize + 1);

    ENSURE_OR_EXIT(NULL != temp, 0);

    p->payload = temp;
    memcpy(&(p->payload[p->size]), contents, realsize);
    p->size += realsize;
    p->payload[p->size] = 0;

    ret = realsize;
exit:
    return ret;
}

static int send_remote_call(const char* url, const char* mToServer, struct curl_fetch_st* mFromServer)
{
    int ret = TNS_UNDEFINED;
    struct curl_slist *headers = NULL;

    ENSURE_OR_EXIT(NULL != url, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(NULL != mFromServer, TNS_ERR_BAD_ARGUMENT);

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    if(mToServer != NULL)
    {
        curl_easy_setopt(ctx.hCurl, CURLOPT_CUSTOMREQUEST, "POST");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(ctx.hCurl, CURLOPT_POSTFIELDS, mToServer);
    }
    else
    {
        curl_easy_setopt(ctx.hCurl, CURLOPT_CUSTOMREQUEST, "GET");
    }
    
    /* set curl options */
    curl_easy_setopt(ctx.hCurl, CURLOPT_URL, url);
    curl_easy_setopt(ctx.hCurl, CURLOPT_HTTPHEADER, headers);

    /* init payload */
    mFromServer->payload = NULL;

    /* init size */
    mFromServer->size = 0;

    /* set url to fetch */
    curl_easy_setopt(ctx.hCurl, CURLOPT_URL, url);

    /* set calback function */
    curl_easy_setopt(ctx.hCurl, CURLOPT_WRITEFUNCTION, curl_callback);

    /* pass fetch struct pointer */
    curl_easy_setopt(ctx.hCurl, CURLOPT_WRITEDATA, (void *) mFromServer);

    /* set default user agent */
    curl_easy_setopt(ctx.hCurl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    /* set timeout */
    curl_easy_setopt(ctx.hCurl, CURLOPT_TIMEOUT, 15);

    /* enable location redirects */
    curl_easy_setopt(ctx.hCurl, CURLOPT_FOLLOWLOCATION, 1);

    /* set maximum allowed redirects */
    curl_easy_setopt(ctx.hCurl, CURLOPT_MAXREDIRS, 1);

    /* fetch the url */
    CURLcode rcode = curl_easy_perform(ctx.hCurl);
    ENSURE_OR_EXIT(rcode == CURLE_OK, TNS_ERR_CURL);

    ret = TNS_OK;
exit:
    /* free headers */
    curl_slist_free_all(headers);
    return ret;
}

static int get_attribute_template(char* key, attribute_template_t **ppTemplate)
{ 
    int ret = TNS_UNDEFINED;
    const char *template_key;

    ENSURE_OR_EXIT(NULL != key, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(NULL != ppTemplate, TNS_ERR_BAD_ARGUMENT);

    *ppTemplate = NULL;

    for(size_t i=0; i<ATTRIBUTE_TABLE_LEN; i++)
    {
        template_key = ATTRIBUTE_TABLE[i].key;
        if(!strcmp(key, template_key))
        {
            *ppTemplate = &ATTRIBUTE_TABLE[i];
            ret = TNS_OK;
            goto exit;
        }
    }
    /* Should not reach this line */
    ret = -TNS_ERR_INAVLID_JSON;
    printf("Invalid key: %s\n", key);
exit:
    return ret;
}
 
static int set_attribute_value(const json_object *jobj, attribute_template_t *pTemplate, CK_ATTRIBUTE_PTR pAttribute)
{
    void *pValue = NULL;
    size_t valueLen = 0;
    int ret = TNS_UNDEFINED;

    ENSURE_OR_EXIT(NULL != jobj, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(NULL != pTemplate, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(NULL != pAttribute, TNS_ERR_BAD_ARGUMENT);

    int type_check = json_object_is_type(jobj, TYPE_MAPPING[pTemplate->dtype].json);
    ENSURE_OR_EXIT(0 != type_check, TNS_ERR_INAVLID_JSON);

    switch (pTemplate->dtype)
    {
        case PKCS11_ULONG:
            unsigned long valueUl = json_object_get_uint64(jobj);
            valueLen = sizeof(valueUl);
            pValue = &valueUl;
            break;

        case PKCS11_STRING:
            const char *valueStr = json_object_get_string(jobj);
            valueLen = json_object_get_string_len(jobj);
            pValue = valueStr;
            break;

        case PKCS11_BOOL:
            unsigned char valueUc = json_object_get_boolean(jobj);
            valueLen = sizeof(valueUc);
            pValue = &valueUc;
            break;

        case PKCS11_UCHAR_ARRAY:
            char *valueBase64 = json_object_get_string(jobj);
            ret = base64_decode(valueBase64, (unsigned char**)&pValue, &valueLen);
            ENSURE_OR_EXIT(0 == ret, TNS_ERR_INAVLID_JSON);
            break;

        default:
            ret = TNS_UNDEFINED;
            goto exit;
    }

    pAttribute->type = pTemplate->type;
    if (pAttribute->pValue != NULL)
    {
        memcpy(pAttribute->pValue, pValue, valueLen);
    }
    pAttribute->ulValueLen = valueLen;

    ret = TNS_OK;
exit:
    if (pValue)
    {
        if (pTemplate->dtype == PKCS11_UCHAR_ARRAY)
        {
            free(pValue);
        }
    }
    return ret;
}

static void free_attribute(CK_ATTRIBUTE_PTR pAttr)
{
    if(NULL != pAttr)
    {
        if (pAttr->pValue != NULL)
        {
            memset(pAttr->pValue, 0, pAttr->ulValueLen);
            free(pAttr->pValue);
        }
        memset(pAttr, 0, sizeof(CK_ATTRIBUTE));
    }
}

static int get_object_from_json(json_object *jobj, ck_object_t *object)
{
    CK_ATTRIBUTE_PTR pAttributes = object->pAttributes;
    size_t *pAttributesLen = &object->len;
    int ret = TNS_UNDEFINED;
    attribute_template_t *pTemplate = NULL;
    size_t keyIdx = 0;
    json_object_object_foreach(jobj, key, val)
    {
        ENSURE_OR_EXIT(keyIdx < *pAttributesLen, TNS_ERR_BUFFER_TOO_SMALL)
        /* Ignore the key if there is no matching template */
        if(0>get_attribute_template(key, &pTemplate))
            continue;
        /* Request buffer size  and allocate buffer */
        if(0>set_attribute_value(val, pTemplate, &pAttributes[keyIdx]))
            continue;
        pAttributes[keyIdx].pValue = malloc(pAttributes[keyIdx].ulValueLen);
        /* Populate attribute structure */
        if(0>set_attribute_value(val, pTemplate, &pAttributes[keyIdx]))
        {
            free_attribute(&pAttributes[keyIdx]);
            continue;
        }
        keyIdx++;
    }
    *pAttributesLen = keyIdx;
    ret = TNS_OK;
exit:
    return ret;
}

static int allocate_object_from_json(json_object * jobj, ck_object_t *pObject)
{
    int ret = TNS_UNDEFINED;
    ENSURE_OR_EXIT(NULL != jobj, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(NULL != pObject, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(NULL == pObject->pAttributes, TNS_ERR_BAD_ARGUMENT);

    pObject->len = 0;
    json_object_object_foreach(jobj, key, val)
    {
        (void) key;
        pObject->len++;
    }
    pObject->pAttributes = calloc(pObject->len, sizeof(CK_ATTRIBUTE));
    ENSURE_OR_EXIT(NULL != pObject->pAttributes, TNS_ERR_MEMORY_ALLOCATION);

    ret = TNS_OK;
exit:
    if (ret != 0)
    {
        pObject->pAttributes = NULL;
        pObject->len = 0;
    }
    return ret;
}

static void free_object(ck_object_t *pObj)
{
    if(NULL != pObj)
    {
        for(size_t i=0; i<pObj->len; i++)
        {
            free_attribute(&pObj->pAttributes[i]);
        }
        free(pObj->pAttributes);
        memset(pObj, 0, sizeof(ck_object_t));
    }
}

static int get_object_list_from_json(json_object * jarray, ck_object_list_t *pObjList)
{
    int ret = TNS_UNDEFINED;

    /* Populate list */
    size_t i, j;
    for (i=0, j=0; i<pObjList->len; i++)
    {
        json_object * jobj = json_object_array_get_idx(jarray, i);
        memset(&pObjList->pObjects[j], 0, sizeof(ck_object_t));
        ENSURE_OR_EXIT(0 == allocate_object_from_json(jobj, &pObjList->pObjects[j]), TNS_ERR_OBJECT_CREATION_FAILED);
        ENSURE_OR_EXIT(TNS_OK == get_object_from_json(jobj, &pObjList->pObjects[j]), TNS_ERR_OBJECT_CREATION_FAILED);
        j++;
    }
    pObjList->len = j;
    ret = TNS_OK;
exit:
    if (TNS_OK != ret)
    {
        free_object(&pObjList->pObjects[j]);
    }
    return ret;
}

static int allocate_object_list_from_json(json_object * jarray, ck_object_list_t *pObjList)
{
    int ret = TNS_UNDEFINED;

    ENSURE_OR_EXIT(NULL != jarray, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(NULL != pObjList, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(NULL == pObjList->pObjects, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(0 == pObjList->len, TNS_ERR_BAD_ARGUMENT);

    ENSURE_OR_EXIT(json_object_is_type(jarray, json_type_array), TNS_ERR_INAVLID_JSON);

    pObjList->len = json_object_array_length(jarray);
    pObjList->pObjects = calloc(pObjList->len, sizeof(ck_object_t));
    ENSURE_OR_EXIT(NULL != pObjList->pObjects, TNS_ERR_MEMORY_ALLOCATION);

    ret = TNS_OK;
exit:
    if (TNS_OK != ret) 
    {
        pObjList->pObjects = NULL;
        pObjList->len = 0;
    }
    return ret;
}

static void free_object_list(ck_object_list_t *pObjList)
{
    if (NULL != pObjList)
    {
        for (size_t i=0; i<pObjList->len; i++)
        {
            free_object(&pObjList->pObjects[i]);
        }
        free(pObjList->pObjects);
        memset(pObjList, 0, sizeof(ck_object_list_t));
    }

}

static int build_object_list_from_json(json_object *jarray)
{
    int ret = TNS_UNDEFINED;

    ENSURE_OR_EXIT(jarray != NULL, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(ctx.objList.pObjects == NULL, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(ctx.objList.len == 0, TNS_ERR_BAD_ARGUMENT);
    
    ENSURE_OR_EXIT(TNS_OK == allocate_object_list_from_json(jarray, &ctx.objList), TNS_ERR_OBJECT_CREATION_FAILED);
    ENSURE_OR_EXIT(TNS_OK == get_object_list_from_json(jarray, &ctx.objList), TNS_ERR_OBJECT_CREATION_FAILED);

    ret = TNS_OK;
exit:
    return ret;
}

static int parse_and_free_payload(struct curl_fetch_st *cf, json_object **jobj)
{
    int ret = TNS_UNDEFINED;
    *jobj = NULL;

    ENSURE_OR_EXIT(cf != NULL, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(jobj != NULL, TNS_ERR_BAD_ARGUMENT);
    
    ENSURE_OR_EXIT(0 != strcmp(cf->payload, "Unauthorized"), CKR_PIN_INCORRECT);
    *jobj = json_tokener_parse(cf->payload);
    ENSURE_OR_EXIT(NULL != *jobj, TNS_ERR_INAVLID_JSON);
    free(cf->payload);
    cf->payload = NULL;
    cf->size = 0;
    ret = TNS_OK;
exit:
    if (0 != ret)
    {
        if (NULL != *jobj)
        {
            json_object_put(*jobj);
            *jobj = NULL;
        }
    }
    return ret;
}

static int is_object_match_template(ck_object_t *pObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_BBOOL *pResult)
{
    int ret = TNS_UNDEFINED;

    ENSURE_OR_EXIT(NULL != pObject, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(NULL != pResult, TNS_ERR_BAD_ARGUMENT);

    *pResult = CK_TRUE;

    if(!pTemplate && !ulCount)
    {
        ret = TNS_OK;
        goto exit;
    }

    ENSURE_OR_EXIT( (NULL != pTemplate) && (0 != ulCount), TNS_ERR_BAD_ARGUMENT);

    for(size_t j=0; j<ulCount; j++)
    {
        CK_ATTRIBUTE template = pTemplate[j];
        size_t i;
        for(i=0; i<pObject->len; i++)
        {
            CK_ATTRIBUTE attribute = pObject->pAttributes[i];
            if (attribute.type == template.type)
            {
                if(attribute.ulValueLen != template.ulValueLen)
                {
                    *pResult = CK_FALSE;
                    break;
                }
                if(0 != memcmp(attribute.pValue, template.pValue, attribute.ulValueLen))
                {
                    *pResult = CK_FALSE;
                    break;
                }
            }
        }
    }
    ret = TNS_OK;
exit:
    return ret;
}

static char* get_full_url(char* cmd)
{
    char *url = malloc(strlen(ctx.urlBase) + strlen(cmd) + 1);
    strcpy(url, ctx.urlBase);
    strcat(url, cmd);
    return url;
}

int interface_init()
{
    int ret = TNS_UNDEFINED;

    ENSURE_OR_EXIT(0 == ctx.isCurlGlobalInit, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(NULL == ctx.urlBase, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(NULL == ctx.hCurl, TNS_ERR_BAD_ARGUMENT);

    const char* baseUrl = getenv("TNS_URL");
    ENSURE_OR_EXIT(NULL != baseUrl, TNS_ERR_ENV_NOT_SET);
    size_t baseUrlLen = strlen(baseUrl);

    CURLcode cc = curl_global_init(CURL_GLOBAL_ALL);
    ENSURE_OR_EXIT(CURLE_OK == cc, cc );
    ctx.isCurlGlobalInit = 1;

    ctx.urlBase = calloc(baseUrlLen + 1, sizeof(char));
    ENSURE_OR_EXIT(NULL != ctx.urlBase, TNS_ERR_MEMORY_ALLOCATION);
    ctx.urlBase[0] = '\0';
    strncat(ctx.urlBase, baseUrl, baseUrlLen);

    ctx.hCurl = curl_easy_init();
    ENSURE_OR_EXIT(NULL != ctx.hCurl, TNS_ERR_CURL);

    ret = TNS_OK;
exit:
    //if (TNS_OK != ret) interface_deinit();
    return ret;
}

int interface_login(char *user, char* password)
{
    int ret = TNS_UNDEFINED;
    ENSURE_OR_EXIT(ctx.hCurl != NULL, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(user != NULL, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(password != NULL, TNS_ERR_BAD_ARGUMENT);
    curl_easy_setopt(ctx.hCurl, CURLOPT_USERNAME, user);
    curl_easy_setopt(ctx.hCurl, CURLOPT_PASSWORD, password);
    ret = TNS_OK;
exit:
    return ret;
}

void interface_deinit()
{
    /* cleanup curl handle */
    if(ctx.isCurlGlobalInit)
    {
        curl_global_cleanup();
    }
    ctx.isCurlGlobalInit = 0;

    ctx.hObject = 0;

    if(ctx.hCurl)
    {
        curl_easy_cleanup(ctx.hCurl);
        ctx.hCurl = NULL;
    } 

    free(ctx.urlBase);
    ctx.urlBase = NULL;

    free_object_list(&ctx.objList);
    ctx.objList.pObjects = NULL;
    ctx.objList.len = 0;
}

int get_object_attributes(CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    int ret = TNS_UNDEFINED;

    ENSURE_OR_EXIT(0 < hObject, CKR_OBJECT_HANDLE_INVALID);
    ENSURE_OR_EXIT(NULL != pTemplate, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(0 < ulCount, TNS_ERR_BAD_ARGUMENT);

    ENSURE_OR_EXIT(hObject <= ctx.objList.len, CKR_OBJECT_HANDLE_INVALID);
    ENSURE_OR_EXIT(NULL != ctx.objList.pObjects, TNS_ERR_BAD_ARGUMENT);
    ENSURE_OR_EXIT(0 != ctx.objList.len, TNS_ERR_BAD_ARGUMENT);

    ck_object_t object = ctx.objList.pObjects[hObject-1];

    for (size_t i=0; i<ulCount; i++)
    {
        for (size_t j=0; j<object.len; j++)
        {
            if (pTemplate[i].type == object.pAttributes[j].type)
            {
                if(pTemplate[i].pValue)
                {
                    memcpy(pTemplate[i].pValue, object.pAttributes[j].pValue, object.pAttributes[j].ulValueLen);
                }
                pTemplate[i].ulValueLen = object.pAttributes[j].ulValueLen;
            }
        }
    }
    ret = TNS_OK;
exit:
    return ret;
}

int get_object_list(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pList, size_t maxCnt)
{
    int ret = TNS_UNDEFINED;
    char *url = get_full_url("/getObjects");
    struct curl_fetch_st curl_fetch = {0};

    if(ctx.objList.pObjects == NULL)
    {
        ENSURE_OR_EXIT(0 == send_remote_call(url, NULL, &curl_fetch), TNS_ERR_CURL);
        json_object *jobj;
        ret = parse_and_free_payload(&curl_fetch, &jobj);
        ENSURE_OR_EXIT(TNS_OK == ret, ret);
        ret = build_object_list_from_json(jobj);
        json_object_put(jobj);
        ENSURE_OR_EXIT(TNS_OK == ret, ret);
    }
    
    if ((ctx.objList.pObjects == NULL) || (ctx.objList.len == 0))
    {
        ret = TNS_ERR_BAD_ARGUMENT;
        goto exit;
    }

    if (ctx.objList.len > maxCnt)
    {
        ret = TNS_ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    memset(pList, 0, maxCnt*sizeof(CK_OBJECT_HANDLE));

    size_t i, j;
    for (i=0, j=0; i<ctx.objList.len; i++)
    {
        CK_BBOOL result = CK_FALSE;
        ret = is_object_match_template(&ctx.objList.pObjects[i], pTemplate, ulCount, &result);
        if (TNS_OK != ret)
        {
            goto exit;
        }
        
        if (result == CK_TRUE)
        {
            pList[j++] = i+1;
        }
    }
    ret = TNS_OK;
exit:
    free(url);
    return ret;
}

void sign_init(CK_OBJECT_HANDLE hKey)
{
    ctx.hObject = hKey;
}

int sign(CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    int ret = TNS_UNDEFINED;
    struct curl_fetch_st curl_fetch;
    CK_BYTE_PTR pSigBuff = NULL;
    char *url = get_full_url("/sign");
    CK_ATTRIBUTE	attr = { CKA_LABEL, NULL, 0 };
    char *key_label = NULL;
    char *encoded_data = NULL;
    json_object *request = NULL;
    json_object *response = NULL;
    json_object *jobj = NULL;
    char *status = NULL;
    char *encoded_signature =NULL;
    size_t sigBuffLen = 0;

    ret = get_object_attributes(ctx.hObject, &attr, 1);
    ENSURE_OR_EXIT(TNS_OK == ret, ret);
    attr.pValue = calloc(attr.ulValueLen + 1, 1);
    ret = get_object_attributes(ctx.hObject, &attr, 1);
    ENSURE_OR_EXIT(TNS_OK == ret, ret);
    key_label = attr.pValue;
    base64_encode(pData, ulDataLen, &encoded_data);

    /* build JSON and send post data */
    request = json_object_new_object();

    json_object_object_add(request, "key", json_object_new_string(key_label));
    json_object_object_add(request, "hash", json_object_new_string(encoded_data));
    ENSURE_OR_EXIT(TNS_OK == send_remote_call(url, json_object_to_json_string(request), &curl_fetch), TNS_ERR_SERVER_COM);
    
    ret = parse_and_free_payload(&curl_fetch, &response);
    ENSURE_OR_EXIT(TNS_OK == ret, ret);
    
    jobj = json_object_object_get(response, "status");
    ENSURE_OR_EXIT(NULL != jobj, TNS_ERR_INAVLID_JSON);
    status = json_object_get_string(jobj);
    ENSURE_OR_EXIT(NULL != status, TNS_ERR_INAVLID_JSON);
    ENSURE_OR_EXIT(0 == strcmp(status, "OK"), TNS_ERR_SIGN_OPERATION_FAILURE);
   
    jobj = json_object_object_get(response, "signature");
    ENSURE_OR_EXIT(NULL != jobj, TNS_ERR_INAVLID_JSON);
    encoded_signature = json_object_get_string(jobj);
    ENSURE_OR_EXIT(NULL != status, TNS_ERR_INAVLID_JSON);

    ENSURE_OR_EXIT(0 == base64_decode(encoded_signature, &pSigBuff, &sigBuffLen), TNS_ERR_INAVLID_JSON);
    ENSURE_OR_EXIT(sigBuffLen <= *pulSignatureLen, CKR_BUFFER_TOO_SMALL);

    memcpy(pSignature, pSigBuff, sigBuffLen);
    *pulSignatureLen = sigBuffLen;

    ret = TNS_OK;   
exit:
    free(url);
    json_object_put(request);
    json_object_put(response);
    free(pSigBuff);
    free(attr.pValue);
    free(encoded_data);
    return ret;
}
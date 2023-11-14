/*
 *  Copyright 2023-2024 TrustnGo S.A.S
 *	Copyright 2011-2016 The Pkcs11Interop Project
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

#include <stdlib.h>

#include "pkcs11.h"
#include "rest_interface.h"

CK_BBOOL pkcs11_initialized = CK_FALSE;
CK_BBOOL pkcs11_session_opened = CK_FALSE;
CK_ULONG pkcs11_session_state = CKS_RO_PUBLIC_SESSION;
PKCS11_CK_OPERATION pkcs11_active_operation = PKCS11_CK_OPERATION_NONE;
CK_OBJECT_HANDLE pkcs11_find_results[64];

CK_FUNCTION_LIST empty_pkcs11_functions = 
{
	{2, 20},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};

#define ATTR_METHOD(ATTR, TYPE) \
static TYPE \
get##ATTR(CK_OBJECT_HANDLE obj, TYPE *type) \
{ \
	CK_ATTRIBUTE	attr = { CKA_##ATTR, type, sizeof(TYPE) }; \
 \
	CK_RV rv = get_object_attributes(obj, &attr, 1); \
	return rv; \
}

/*
 * Define attribute accessors
 */
ATTR_METHOD(CLASS, CK_OBJECT_CLASS);			/* getCLASS */
ATTR_METHOD(ALWAYS_AUTHENTICATE, CK_BBOOL); 		/* getALWAYS_AUTHENTICATE */
ATTR_METHOD(PRIVATE, CK_BBOOL); 			/* getPRIVATE */
ATTR_METHOD(MODIFIABLE, CK_BBOOL);			/* getMODIFIABLE */
ATTR_METHOD(ENCRYPT, CK_BBOOL);				/* getENCRYPT */
ATTR_METHOD(DECRYPT, CK_BBOOL);				/* getDECRYPT */
ATTR_METHOD(SIGN, CK_BBOOL);				/* getSIGN */
ATTR_METHOD(VERIFY, CK_BBOOL);				/* getVERIFY */
ATTR_METHOD(WRAP, CK_BBOOL);				/* getWRAP */
ATTR_METHOD(UNWRAP, CK_BBOOL);				/* getUNWRAP */
ATTR_METHOD(DERIVE, CK_BBOOL);				/* getDERIVE */
ATTR_METHOD(SENSITIVE, CK_BBOOL);			/* getSENSITIVE */
ATTR_METHOD(ALWAYS_SENSITIVE, CK_BBOOL);		/* getALWAYS_SENSITIVE */
ATTR_METHOD(EXTRACTABLE, CK_BBOOL);			/* getEXTRACTABLE */
ATTR_METHOD(NEVER_EXTRACTABLE, CK_BBOOL);		/* getNEVER_EXTRACTABLE */
ATTR_METHOD(LOCAL, CK_BBOOL);				/* getLOCAL */
ATTR_METHOD(KEY_TYPE, CK_KEY_TYPE);			/* getKEY_TYPE */
ATTR_METHOD(CERTIFICATE_TYPE, CK_CERTIFICATE_TYPE);	/* getCERTIFICATE_TYPE */
ATTR_METHOD(MODULUS_BITS, CK_ULONG);			/* getMODULUS_BITS */
ATTR_METHOD(VALUE_LEN, CK_ULONG);			/* getVALUE_LEN */

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	if (CK_TRUE == pkcs11_initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	IGNORE(pInitArgs);

	pkcs11_initialized = CK_TRUE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	IGNORE(pReserved);

	pkcs11_initialized = CK_FALSE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_CK_INFO_MANUFACTURER_ID, strlen(PKCS11_CK_INFO_MANUFACTURER_ID));
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
	memcpy(pInfo->libraryDescription, PKCS11_CK_INFO_LIBRARY_DESCRIPTION, strlen(PKCS11_CK_INFO_LIBRARY_DESCRIPTION));
	pInfo->libraryVersion.major = PKCS11_CK_INFO_LIBRARY_VERSION_MAJOR;
	pInfo->libraryVersion.minor = PKCS11_CK_INFO_LIBRARY_VERSION_MINOR;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &empty_pkcs11_functions;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	IGNORE(tokenPresent);

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSlotList)
	{
		*pulCount = 1;
	}
	else
	{
		if (0 == *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		pSlotList[0] = PKCS11_CK_SLOT_ID;
		*pulCount = 1;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memcpy(pInfo->slotDescription, PKCS11_CK_SLOT_INFO_SLOT_DESCRIPTION, strlen(PKCS11_CK_SLOT_INFO_SLOT_DESCRIPTION));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_CK_SLOT_INFO_MANUFACTURER_ID, strlen(PKCS11_CK_SLOT_INFO_MANUFACTURER_ID));
	pInfo->flags = CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo->label, ' ', sizeof(pInfo->label));
	memcpy(pInfo->label, PKCS11_CK_TOKEN_INFO_LABEL, strlen(PKCS11_CK_TOKEN_INFO_LABEL));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_CK_TOKEN_INFO_MANUFACTURER_ID, strlen(PKCS11_CK_TOKEN_INFO_MANUFACTURER_ID));
	memset(pInfo->model, ' ', sizeof(pInfo->model));
	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
	pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulSessionCount = (CK_TRUE == pkcs11_session_opened) ? 1 : 0;
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulRwSessionCount = ((CK_TRUE == pkcs11_session_opened) && ((CKS_RO_PUBLIC_SESSION != pkcs11_session_state) || (CKS_RO_USER_FUNCTIONS != pkcs11_session_state))) ? 1 : 0;
	pInfo->ulMaxPinLen = PKCS11_CK_TOKEN_INFO_MAX_PIN_LEN;
	pInfo->ulMinPinLen = PKCS11_CK_TOKEN_INFO_MIN_PIN_LEN;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = 0x00;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x00;
	pInfo->firmwareVersion.minor = 0x00;
	memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pMechanismList)
	{
		*pulCount = 2;
	}
	else
	{
		if (2 > *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		pMechanismList[0] = CKM_ECDSA;
		pMechanismList[1] = CKM_RSA_PKCS_PSS;

		*pulCount = 2;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	switch (type)
	{
		case CKM_ECDSA:
			pInfo->ulMinKeySize = 256;
			pInfo->ulMaxKeySize = 521;
			pInfo->flags = CKF_SIGN;
			break;

		case CKM_RSA_PKCS_PSS:
			pInfo->ulMinKeySize = 2048;
			pInfo->ulMaxKeySize = 4096;
			pInfo->flags = CKF_SIGN;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV ret;
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (CK_TRUE == pkcs11_session_opened)
		return CKR_SESSION_COUNT;

	if (PKCS11_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	IGNORE(pApplication);

	IGNORE(Notify);

	if (NULL == phSession)
		return CKR_ARGUMENTS_BAD;

	if(0 == interface_init())
	{
		pkcs11_session_opened = CK_TRUE;
		pkcs11_session_state = CKS_RO_PUBLIC_SESSION;
		*phSession = PKCS11_CK_SESSION_ID;	
		ret = CKR_OK;	
	}
	else
	{
		pkcs11_session_opened = CK_FALSE;
		ret = CKR_DEVICE_ERROR;
	}

	return ret;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	interface_deinit();

	pkcs11_session_opened = CK_FALSE;
	pkcs11_session_state = CKS_RO_PUBLIC_SESSION;
	pkcs11_active_operation = PKCS11_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	pInfo->slotID = PKCS11_CK_SLOT_ID;
	pInfo->state = pkcs11_session_state;
	pInfo->flags = CKF_SERIAL_SESSION;
	if ((pkcs11_session_state != CKS_RO_PUBLIC_SESSION) && (pkcs11_session_state != CKS_RO_USER_FUNCTIONS))
		pInfo->flags = pInfo->flags | CKF_RW_SESSION;
	pInfo->ulDeviceError = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	char *buf = malloc(ulPinLen+1);
	if (NULL == buf)
		goto exit;
	memcpy(buf, pPin, ulPinLen);
	buf[ulPinLen] = '\0';
	char *delimiter = strchr(buf, ':');
	if(NULL == delimiter)
	{
		ret = CKR_PIN_INVALID;
	}
	else
	{
		char *user = strtok(buf, ":");
		char *password = strtok(NULL, ":");
		if(0 == interface_login(user, password))
		{
			ret = CKR_OK;
		}
		else
		{
			ret = CKR_DEVICE_ERROR;
		}
		
	}
exit:
	if(buf) free(buf);
	return ret;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	// TODO: TBD
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	CK_RV ret = get_object_attributes(hObject, pTemplate, ulCount);
	if(0 != ret)
	{
		if (CKR_OBJECT_HANDLE_INVALID != ret)
		{
			ret = CKR_DEVICE_ERROR;
		}
	}
	return ret;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	int ret;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CK_OPERATION_NONE != pkcs11_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	memset(pkcs11_find_results, 0, sizeof(pkcs11_find_results));
	ret = get_object_list(
		pTemplate, 
		ulCount, 
		pkcs11_find_results, 
		sizeof(pkcs11_find_results)/sizeof(pkcs11_find_results[0]));
	if (ret != CKR_OK)
		return ret;

	pkcs11_active_operation = PKCS11_CK_OPERATION_FIND;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	static size_t idx = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CK_OPERATION_FIND != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == phObject)
		return CKR_ARGUMENTS_BAD;

	if ((NULL == pulObjectCount) && (1 > ulMaxObjectCount))
		return CKR_ARGUMENTS_BAD;

	if (pkcs11_find_results[idx] == 0)
	{
		idx = 0;
		*pulObjectCount = 0;
	}
	else
	{
		*pulObjectCount = 1;
		phObject[0] = pkcs11_find_results[idx++];
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CK_OPERATION_FIND != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	pkcs11_active_operation = PKCS11_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CK_OPERATION_NONE != pkcs11_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	CK_OBJECT_CLASS class;
	rv = getCLASS(hKey, &class);
	if (rv != CKR_OK)
		return rv;
	if (class != CKO_PRIVATE_KEY)
		return CKR_KEY_TYPE_INCONSISTENT;

	CK_BBOOL sign;
	rv = getSIGN(hKey, &sign);
	if (rv != CKR_OK)
		return rv;
	if (sign != CK_TRUE)
		return CKR_MECHANISM_INVALID;

	CK_KEY_TYPE type;
	rv = getKEY_TYPE(hKey, &type);
	if (rv != CKR_OK)
		return rv;
	if ((CKM_ECDSA == pMechanism->mechanism) && (type != CKK_EC))
	{
		return CKR_KEY_TYPE_INCONSISTENT;
	}

	if ((CKM_RSA_PKCS_PSS == pMechanism->mechanism) && (type != CKK_RSA))
	{
		return CKR_KEY_TYPE_INCONSISTENT;
	}

	sign_init(hKey);

	pkcs11_active_operation = PKCS11_CK_OPERATION_SIGN;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	int rv;
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CK_OPERATION_SIGN != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pSignature)
	{
		rv = sign(pData, ulDataLen, pSignature, pulSignatureLen);
		if (0 != rv)
		{
			return rv;
		}
		pkcs11_active_operation = PKCS11_CK_OPERATION_NONE;	
	}
	else
	{
		*pulSignatureLen = 0;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

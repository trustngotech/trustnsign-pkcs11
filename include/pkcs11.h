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

#ifndef __PKCS11__
#define __PKCS11__

#include <stdio.h>
#include <string.h>

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#define IGNORE(P) (void)(P)

#define PKCS11_CK_INFO_MANUFACTURER_ID "TrustnGo S.A.S"
#define PKCS11_CK_INFO_LIBRARY_DESCRIPTION "TrustnSign PKCS#11 Interface"
#define PKCS11_CK_INFO_LIBRARY_VERSION_MAJOR 0x01
#define PKCS11_CK_INFO_LIBRARY_VERSION_MINOR 0x00

#define PKCS11_CK_SLOT_ID 1
#define PKCS11_CK_SLOT_INFO_SLOT_DESCRIPTION "TrustnSign slot"
#define PKCS11_CK_SLOT_INFO_MANUFACTURER_ID "TrustnGo S.A.S"

#define PKCS11_CK_TOKEN_INFO_LABEL "TrustnSign token"
#define PKCS11_CK_TOKEN_INFO_MANUFACTURER_ID "TrustnGo S.A.S"
#define PKCS11_CK_TOKEN_INFO_MAX_PIN_LEN 256
#define PKCS11_CK_TOKEN_INFO_MIN_PIN_LEN 4

#define PKCS11_CK_SESSION_ID 1

typedef enum
{
	PKCS11_CK_OPERATION_NONE,
	PKCS11_CK_OPERATION_FIND,
	PKCS11_CK_OPERATION_ENCRYPT,
	PKCS11_CK_OPERATION_DECRYPT,
	PKCS11_CK_OPERATION_DIGEST,
	PKCS11_CK_OPERATION_SIGN,
	PKCS11_CK_OPERATION_SIGN_RECOVER,
	PKCS11_CK_OPERATION_VERIFY,
	PKCS11_CK_OPERATION_VERIFY_RECOVER,
	PKCS11_CK_OPERATION_DIGEST_ENCRYPT,
	PKCS11_CK_OPERATION_DECRYPT_DIGEST,
	PKCS11_CK_OPERATION_SIGN_ENCRYPT,
	PKCS11_CK_OPERATION_DECRYPT_VERIFY
}
PKCS11_CK_OPERATION;

#include "cryptoki/pkcs11.h"

#endif /* __PKCS11__ */
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


#ifndef __REST_INTERFACE_H__
#define __REST_INTERFACE_H__

#include "pkcs11.h"

int interface_init();
int interface_login(char *user, char *password);
void interface_deinit();
void sign_init(CK_OBJECT_HANDLE hKey);
int sign(CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
int get_object_attributes(CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
int get_object_list(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR list, size_t maxCnt);

#endif /* __REST_INTERFACE_H__ */
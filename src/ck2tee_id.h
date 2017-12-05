/*
 * ck2tee_id.c
 *
 * Copyright (C) STMicroelectronics SA 2017
 * Author: etienne carriere <etienne.carriere@st.com> for STMicroelectronics.
 */

#ifndef __CK2TEE_ID_H
#define __CK2TEE_ID_H

#include <pkcs11.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

TEE_Result ckr2tee(CK_RV rv);

#endif /*__CK2TEE_ID_H*/


/*
 * ck2tee_id.c
 *
 * Copyright (C) STMicroelectronics SA 2017
 * Author: etienne carriere <etienne.carriere@st.com> for STMicroelectronics.
 */

#include <pkcs11.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ck2tee_id.h"

TEE_Result ckr2tee(CK_RV rv)
{
	switch (rv) {
	case CKR_OK:
		return TEE_SUCCESS;
	case CKR_DEVICE_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;
	case CKR_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;
	default:
		return TEE_ERROR_GENERIC;
	}
}

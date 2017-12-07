/*
 * ck2tee_id.c
 *
 * Copyright (C) STMicroelectronics SA 2017
 * Author: etienne carriere <etienne.carriere@st.com> for STMicroelectronics.
 */

#include <pkcs11.h>
#include <sks_abi.h>
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

const char *cka2str(CK_ATTRIBUTE_TYPE id)
{
	static char ckastr_undefined[] = "reserved-undefined";
	static char ckastr_invalid[] = "unknown-id";
	static char ckastr_token[] = "CKA_TOKEN";
	static char ckastr_private[] = "CKA_PRIVATE";
	static char ckastr_modifiable[] = "CKA_MODIFIABLE";
	static char ckastr_copyable[] = "CKA_COPYABLE";
	static char ckastr_destroyable[] = "CKA_DESTROYABLE";
	static char ckastr_derive[] = "CKA_DERIVE";
	static char ckastr_local[] = "CKA_LOCAL";
	static char ckastr_sensitive[] = "CKA_SENSITIVE";
	static char ckastr_encrypt[] = "CKA_ENCRYPT";
	static char ckastr_decrypt[] = "CKA_DECRYPT";
	static char ckastr_sign[] = "CKA_SIGN";
	static char ckastr_verify[] = "CKA_VERIFY";
	static char ckastr_wrap[] = "CKA_WRAP";
	static char ckastr_unwrap[] = "CKA_UNWRAP";
	static char ckastr_extractable[] = "CKA_EXTRACTABLE";
	static char ckastr_always_sensitive[] = "CKA_ALWAYS_SENSITIVE";
	static char ckastr_never_extractable[] = "CKA_NEVER_EXTRACTABLE";
	static char ckastr_wrap_with_trusted[] = "CKA_WRAP_WITH_TRUSTED";
	static char ckastr_trusted[] = "CKA_TRUSTED";
	static char ckastr_value[] = "CKA_VALUE";

	switch (id) {
	case CKA_TOKEN:
		return ckastr_token;
	case CKA_PRIVATE:
		return ckastr_private;
	case CKA_MODIFIABLE:
		return ckastr_modifiable;
	case CKA_COPYABLE:
		return ckastr_copyable;
	case CKA_DESTROYABLE:
		return ckastr_destroyable;
	case CKA_DERIVE:
		return ckastr_derive;
	case CKA_LOCAL:
		return ckastr_local;
	case CKA_SENSITIVE:
		return ckastr_sensitive;
	case CKA_ENCRYPT:
		return ckastr_encrypt;
	case CKA_DECRYPT:
		return ckastr_decrypt;
	case CKA_SIGN:
		return ckastr_sign;
	case CKA_VERIFY:
		return ckastr_verify;
	case CKA_WRAP:
		return ckastr_wrap;
	case CKA_UNWRAP:
		return ckastr_unwrap;
	case CKA_EXTRACTABLE:
		return ckastr_extractable;
	case CKA_ALWAYS_SENSITIVE:
		return ckastr_always_sensitive;
	case CKA_NEVER_EXTRACTABLE:
		return ckastr_never_extractable;
	case CKA_WRAP_WITH_TRUSTED:
		return ckastr_wrap_with_trusted;
	case CKA_TRUSTED:
		return ckastr_trusted;
	case CKA_VALUE:
		return ckastr_value;
	case CK_VENDOR_UNDEFINED_ID:
		return ckastr_undefined;
	default:
		return ckastr_invalid;
	}
}


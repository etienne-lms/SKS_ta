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

/*
 * Convert a CK return value ID into a TEE Internal Core API return value ID.
 * This supports only a reduced set of IDs as such conversion is prone to
 * error. Supported IDs are CKR_OK, CKR_TOO_SMALL_BUFFER, CKR_DEVICE_MEMORY,
 * etc...
 */
TEE_Result ckr2tee(CK_RV rv);

/* Return a pointer to a string buffer of "CKA_xxx" attribute ID */
const char *cka2str(uint32_t id);

#endif /*__CK2TEE_ID_H*/


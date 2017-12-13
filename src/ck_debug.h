/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_CK_DEBUG_H
#define __SKS_CK_DEBUG_H

#include <pkcs11.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/* Return a pointer to a string buffer of "CKA_xxx\0" attribute ID */
const char *cka2str(CK_ATTRIBUTE_TYPE id);

/* Return a pointer to a string buffer of "CKR_xxx\0" attribute ID */
const char *ckr2str(CK_RV id);

/*
 * Convert a CK return value ID into a TEE Internal Core API return value ID.
 * This supports only a reduced set of IDs as such conversion is prone to
 * error. Supported IDs are CKR_OK, CKR_TOO_SMALL_BUFFER, CKR_DEVICE_MEMORY,
 * etc...
 */
TEE_Result ckr2tee(CK_RV rv);

/* Return a pointer to a string buffer of "SKS_TA_CMD_xxx\0" */
const char *skscmd2str(uint32_t id);

/* Allocate and return a string descripbing the enabled flags */
char *ck_slot_flag2str(CK_ULONG flags);
char *ck_token_flag2str(CK_ULONG flags);
char *ck_mecha_flag2str(CK_ULONG flags);

#endif /*__SKS_CK_DEBUG_H*/

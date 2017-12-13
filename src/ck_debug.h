/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_CK_DEBUG_H
#define __SKS_CK_DEBUG_H

#include <pkcs11.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/* Return a pointer to a string buffer "CKA_xxx\0" for an attribute ID */
const char *cka2str(CK_ATTRIBUTE_TYPE id);

/* Return a pointer to a string buffer "CKR_xxx\0" for a return value ID */
const char *ckr2str(CK_RV id);

/*
 * Convert a CK return value ID into a TEE Internal Core API return value ID.
 * This supports only a reduced set of IDs as such conversion is prone to
 * error. Supported IDs are CKR_OK, CKR_TOO_SMALL_BUFFER, CKR_DEVICE_MEMORY,
 * etc...
 */
TEE_Result ckr2tee(CK_RV rv);

/* Return a pointer to a string buffer "SKS_TA_CMD_xxx\0" for a command ID */
const char *skscmd2str(uint32_t id);

/* Allocate and return a string describing the enabled flags */
char *ck_slot_flag2str(CK_ULONG flags);
char *ck_token_flag2str(CK_ULONG flags);
char *ck_mecha_flag2str(CK_ULONG flags);

/* Return a pointer to a string buffer "CKO_xxx\0" for a object class ID */
const char *ckclass2str(CK_ULONG id);

/* Return a pointer to a string buffer "CKx_xxx\0" for a type-in-class ID */
const char *cktype2str(CK_ULONG id, CK_ULONG class);

#endif /*__SKS_CK_DEBUG_H*/

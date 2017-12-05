/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */


#include <sks_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "pkcs11_object.h"
#include "pkcs11_token.h"
#include "processing.h"

TEE_Result TA_CreateEntryPoint(void)
{
	if (pkcs11_token_init())
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __maybe_unused param_types,
				    TEE_Param __maybe_unused params[4],
				    void __maybe_unused **session)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *session)
{
}

/*
 * The session handle here may be useless. Drop it...
 */
TEE_Result TA_InvokeCommandEntryPoint(void __unused *session, uint32_t cmd,
				      uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Param *ctrl = NULL;
	TEE_Param *in = NULL;
	TEE_Param *out = NULL;

	if (TEE_PARAM_TYPE_GET(ptypes, 0) == TEE_PARAM_TYPE_MEMREF_INPUT)
		ctrl = &params[0];
	else if (TEE_PARAM_TYPE_GET(ptypes, 0) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	if (TEE_PARAM_TYPE_GET(ptypes, 1) == TEE_PARAM_TYPE_MEMREF_INPUT)
		in = &params[2];
	else if (TEE_PARAM_TYPE_GET(ptypes, 1) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	if (TEE_PARAM_TYPE_GET(ptypes, 2) == TEE_PARAM_TYPE_MEMREF_OUTPUT)
		out = &params[2];
	else if (TEE_PARAM_TYPE_GET(ptypes, 2) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	if (TEE_PARAM_TYPE_GET(ptypes, 3) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	switch (cmd) {
	case SKS_CMD_CK_PING:
		return TEE_SUCCESS;
	case SKS_CMD_CK_SLOTS_INFO:
		/* TA is a slot provider? inside a slot? */
		return TEE_ERROR_NOT_SUPPORTED;
	case SKS_CMD_CK_TOKEN_INFO:
		return ck_token_info(ctrl, in, out);

	case SKS_CMD_CK_MECHANISM_IDS:
		return ck_token_mecha_ids(ctrl, in, out);
	case SKS_CMD_CK_MECHANISM_INFO:
		return ck_token_mecha_info(ctrl, in, out);

	case SKS_CMD_CK_OPEN_RO_SESSION:
		return ck_token_ro_session(ctrl, in, out);
	case SKS_CMD_CK_OPEN_RW_SESSION:
		return ck_token_rw_session(ctrl, in, out);
	case SKS_CMD_CK_CLOSE_SESSION:
		return ck_token_close_session(ctrl, in, out);

	case SKS_CMD_CK_CREATE_OBJECT:
		return entry_create_object(ctrl, in, out);
	case SKS_CMD_CK_DESTROY_OBJECT:
		return entry_destroy_object(ctrl, in, out);

	case SKS_CMD_CK_ENCRYPT_INIT:
	case SKS_CMD_CK_DECRYPT_INIT:
		return entry_cipher_init(ctrl, in, out,
					 cmd == SKS_CMD_CK_DECRYPT_INIT);
	case SKS_CMD_CK_ENCRYPT_UPDATE:
	case SKS_CMD_CK_DECRYPT_UPDATE:
		return entry_cipher_update(ctrl, in, out,
					   cmd == SKS_CMD_CK_DECRYPT_UPDATE);
	case SKS_CMD_CK_ENCRYPT_FINAL:
	case SKS_CMD_CK_DECRYPT_FINAL:
		return entry_cipher_final(ctrl, in, out,
					  cmd == SKS_CMD_CK_DECRYPT_FINAL);

	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}

bad_types:
	DMSG("Bad parameter types used at SKS TA entry:");
	DMSG("- parameter #0; formated input request buffer or none");
	DMSG("- parameter #1; processed input data buffer or none");
	DMSG("- parameter #2; processed output data buffer or none");
	DMSG("- parameter #3; none");
	return TEE_ERROR_BAD_PARAMETERS;
}

/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_abi.h>
#include <sks_ta.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "handle.h"
#include "pkcs11_token.h"

struct ck_token_state ck_token_state;

static struct handle_db session_handle_db = HANDLE_DB_INITIALIZER;

struct pkcs11_session *get_pkcs_session(uint32_t ck_handle)
{
	return handle_lookup(&session_handle_db, (int)ck_handle);
}

/*
 * PKCS#11 expects an session must finalize (or cancel) an operation
 * before starting a new one.
 *
 * enum pkcs11_session_processing provides the valid operation states for a
 * PKCS#11 session.
 *
 * set_pkcs_session_processing_state() changes the session operation state.
 *
 * check_pkcs_session_processing_state() checks the session is in the expected
 * operation state.
 */
int set_pkcs_session_processing_state(uint32_t ck_session,
					enum pkcs11_session_processing state)
{
	struct pkcs11_session *pkcs_session = get_pkcs_session(ck_session);

	if (!pkcs_session)
		return 1;

	if (pkcs_session->processing == PKCS11_SESSION_READY ||
	    state == PKCS11_SESSION_READY) {
		pkcs_session->processing = state;
		return 0;
	}

	/* Allowed transitions on dual disgest/cipher or authen/cipher */
	switch (state) {
	case PKCS11_SESSION_DIGESTING_ENCRYPTING:
		if (pkcs_session->processing == PKCS11_SESSION_ENCRYPTING ||
		    pkcs_session->processing == PKCS11_SESSION_DIGESTING) {
			pkcs_session->processing = state;
			return 0;
		}
		break;
	case PKCS11_SESSION_DECRYPTING_DIGESTING:
		if (pkcs_session->processing == PKCS11_SESSION_DECRYPTING ||
		    pkcs_session->processing == PKCS11_SESSION_DIGESTING) {
			pkcs_session->processing = state;
			return 0;
		}
		break;
	case PKCS11_SESSION_SIGNING_ENCRYPTING:
		if (pkcs_session->processing == PKCS11_SESSION_ENCRYPTING ||
		    pkcs_session->processing == PKCS11_SESSION_SIGNING) {
			pkcs_session->processing = state;
			return 0;
		}
		break;
	case PKCS11_SESSION_DECRYPTING_VERIFYING:
		if (pkcs_session->processing == PKCS11_SESSION_DECRYPTING ||
		    pkcs_session->processing == PKCS11_SESSION_VERIFYING) {
			pkcs_session->processing = state;
			return 0;
		}
		break;
	default:
		break;
	}

	/* Transition not allowed */
	return 1;
}

int check_pkcs_session_processing_state(uint32_t ck_session,
					enum pkcs11_session_processing state)
{
	struct pkcs11_session *pkcs_session = get_pkcs_session(ck_session);

	if (!pkcs_session)
		return 1;

	return (pkcs_session->processing == state) ? 0 : 1;
}

/*
 * Initialization routine the the trsuted application.
 */
static int __pkcs11_token_init(void)
{
	char sn[] = SKS_CRYPTOKI_TOKEN_SERAIL_NUMBER;

	/* Let's use a hard coded SN */
	PADDED_STRING_COPY(ck_token_state.serial_number, sn);

	ck_token_state.state = PKCS11_TOKEN_STATE_PUBLIC_SESSIONS;
	return 0;
}
int pkcs11_token_init(void)
{
	if (ck_token_state.state != PKCS11_TOKEN_STATE_INVALID)
		return __pkcs11_token_init();

	return 0;
}

TEE_Result ck_token_info(TEE_Param __unused *ctrl,
			 TEE_Param __unused *in, TEE_Param *out)
{
	struct sks_ck_token_info info;
	const char label[] = SKS_CRYPTOKI_TOKEN_LABEL;
	const char manuf[] = SKS_CRYPTOKI_TOKEN_MANUFACTURER;
	const char model[] = SKS_CRYPTOKI_TOKEN_MODEL;
	const CK_VERSION hwver = SKS_CRYPTOKI_TOKEN_HW_VERSION;
	const CK_VERSION fwver = SKS_CRYPTOKI_TOKEN_FW_VERSION;

	if (ctrl || in || !out)
		return TEE_ERROR_BAD_PARAMETERS;

	if (out->memref.size < sizeof(struct sks_ck_token_info)) {
		out->memref.size = sizeof(struct sks_ck_token_info);
		return TEE_ERROR_SHORT_BUFFER;
	}

	memset(&info, 0, sizeof(info));

	PADDED_STRING_COPY(info.label, label);
	PADDED_STRING_COPY(info.manufacturerID, manuf);
	PADDED_STRING_COPY(info.model, model);
	PADDED_STRING_COPY(info.serialNumber, ck_token_state.serial_number);

	info.flags |= CKF_RNG;

	//TODO: info->flags |= wirte_protect() ? CKF_WRITE_PROTECTED : 0;
	//TODO; info->flags |= login_stored() ? CKF_LOGIN_REQUIRED : 0;
	//TODO; info->flags |= pin_inited() ? CKF_USER_PIN_INITIALIZED : 0;

	/* Archi choice; one can restore a state from an exported blob? */
	//info->flags |= CKF_RESTORE_KEY_NOT_NEEDED

	info.flags |= CKF_CLOCK_ON_TOKEN;
	/* TODO CKF_PROTECTED_AUTHENTICATION_PATH */
	info.flags |= CKF_DUAL_CRYPTO_OPERATIONS;

	// TODO; track token init.
	//	CKF_TOKEN_INITIALIZED
	// TODO: CKF_SECONDARY_AUTHENTICATION
	// TODO; track logins
	//	CKF_USER_PIN_COUNT_LOW
	// TODO; track user PIN:
	//	CKF_USER_PIN_FINAL_TRY
	//	CKF_USER_PIN_LOCKED
	//	CKF_USER_PIN_TO_BE_CHANGED
	// TODO; track secu officer PIN:
	//	CKF_SO_PIN_COUNT_LOW
	//	CKF_SO_PIN_FINAL_TRY
	//	CKF_SO_PIN_LOCKED
	//	CKF_SO_PIN_TO_BE_CHANGED
	{}

	info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	info.ulSessionCount = CK_UNAVAILABLE_INFORMATION;
	info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	info.ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;

	info.ulMaxPinLen = 128;			// TODO: value
	info.ulMinPinLen = 10;			// TODO: value

	info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

	memcpy(&info.hardwareVersion, &hwver, sizeof(hwver));
	memcpy(&info.firmwareVersion, &fwver, sizeof(fwver));

	// TODO: get time and convert from refence into YYYYMMDDhhmmss/UTC
	memset(info.utcTime, 0, sizeof(info.utcTime));

	/* Return to caller with data */
	memcpy(out->memref.buffer, &info, sizeof(info));
	return TEE_SUCCESS;
}

/* TODO: this is a temporary implementation */
TEE_Result ck_token_mecha_ids(TEE_Param __unused *ctrl,
			      TEE_Param __unused *in, TEE_Param *out)
{
	// TODO: get the list of supported mechanism
	const CK_MECHANISM_TYPE mecha_list[] = {
		CKM_MD5, CKM_SHA_1, CKM_SHA256, CKM_SHA224, CKM_SHA384, CKM_SHA512,
		CKM_AES_ECB, CKM_AES_CBC, CKM_AES_MAC, CKM_AES_CBC_PAD,
		CKM_AES_CTR, CKM_AES_GCM, CKM_AES_CCM, CKM_AES_CTS,
	};

	if (ctrl || in || !out)
		return TEE_ERROR_BAD_PARAMETERS;

	if (out->memref.size < sizeof(mecha_list)) {
		out->memref.size = sizeof(mecha_list);
		return TEE_ERROR_SHORT_BUFFER;
	}

	out->memref.size = sizeof(mecha_list);
	memcpy(out->memref.buffer, mecha_list, sizeof(mecha_list));

	return TEE_SUCCESS;
}

/* TODO: this is a temporary implementation */
TEE_Result ck_token_mecha_info(TEE_Param *ctrl,
			       TEE_Param __unused *in, TEE_Param *out)
{
	CK_MECHANISM_INFO info;
	CK_MECHANISM_TYPE type;

	if (!ctrl || in || !out)
		return TEE_ERROR_BAD_PARAMETERS;

	if (out->memref.size < sizeof(info)) {
		out->memref.size = sizeof(info);
		return TEE_ERROR_SHORT_BUFFER;
	}

	memset(&info, 0, sizeof(info));
	memcpy(&type, ctrl->memref.buffer, sizeof(type));

	/* TODO: full list of supported algorithm/mechanism */
	switch (type) {
	case CKM_MD5:
	case CKM_SHA_1:
	case CKM_SHA256:
	case CKM_SHA224:
	case CKM_SHA384:
	case CKM_SHA512:
		info.flags = CKF_DIGEST;
		break;

	case CKM_AES_ECB:
	case CKM_AES_CBC:
	case CKM_AES_MAC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_CTR:
	case CKM_AES_GCM:
	case CKM_AES_CCM:
	case CKM_AES_CTS:
		info.flags = CKF_ENCRYPT | CKF_DECRYPT |
			     CKF_WRAP | CKF_UNWRAP | CKF_DERIVE;
		info.ulMinKeySize =  128;
		info.ulMaxKeySize =  256;
		break;

	default:
		break;
	}

	out->memref.size = sizeof(info);
	memcpy(out->memref.buffer, &info, sizeof(info));

	return TEE_SUCCESS;
}

/* ctrl=unused, in=unused, out=[session-handle] */
TEE_Result ck_token_ro_session(TEE_Param __unused *ctrl,
				TEE_Param __unused *in,
				TEE_Param __unused *out)
{
	struct pkcs11_session *session;

	if (ctrl || in || !out || out->memref.size < sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	session = TEE_Malloc(sizeof(*session), 0);
	if (!session)
		return TEE_ERROR_OUT_OF_MEMORY;

	session->handle = handle_get(&session_handle_db, session);
	session->processing = PKCS11_SESSION_READY;
	session->tee_op_handle = TEE_HANDLE_NULL;

	// TODO: register session handle into the token's session list

	*(uint32_t *)out->memref.buffer = session->handle;
	out->memref.size = sizeof(uint32_t);

	return TEE_SUCCESS;
}

/* ctrl=unused, in=unused, out=[session-handle] */
TEE_Result ck_token_rw_session(TEE_Param __unused *ctrl,
				TEE_Param __unused *in,
				TEE_Param __unused *out)
{
	struct pkcs11_session *session;

	if (ctrl || in || !out || out->memref.size < sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	// TODO: if token is read-only, refuse RW sessions
	// See CKR_SESSION_READ_WRITE_SO_EXISTS

	session = TEE_Malloc(sizeof(*session), 0);
	if (!session)
		return TEE_ERROR_OUT_OF_MEMORY;

	session->handle = handle_get(&session_handle_db, session);
	session->processing = PKCS11_SESSION_READY;
	session->tee_op_handle = TEE_HANDLE_NULL;

	// TODO: register session handle into the token's session list

	*(uint32_t *)out->memref.buffer = session->handle;
	out->memref.size = sizeof(uint32_t);

	return TEE_SUCCESS;
}

/* ctrl=[session-handle], in=unused, out=unused */
TEE_Result ck_token_close_session(TEE_Param __unused *ctrl,
				  TEE_Param __unused *in,
				  TEE_Param __unused *out)
{
	struct pkcs11_session *session;
	uint32_t handle;

	if (!ctrl || in || out || ctrl->memref.size < sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(&handle, ctrl->memref.buffer, sizeof(uint32_t));
	session = handle_put(&session_handle_db, handle);
	if (!session)
		return TEE_ERROR_BAD_PARAMETERS;

	if (session->tee_op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(session->tee_op_handle);
	TEE_Free(session);

	// TODO: destroy all non-persistent objects owned by the session

	// TODO: unregister session handle from the token's session list

	// TODO: if last session closed, token moves to Public state

	return TEE_SUCCESS;
}


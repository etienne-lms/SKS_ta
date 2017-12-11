/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ck_debug.h"
#include "object.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"

// FIXME: temporary until the IV is properly handled
#define DUMMY_NULL_AES_IV_SIZE		16
static const char dummy_null_aes_iv[DUMMY_NULL_AES_IV_SIZE];

/*
 * ctrl = [session-handle][key-handle][serialized-mechanism-blob]
 * in = none
 * out = none
 */
TEE_Result entry_cipher_init(TEE_Param *ctrl,
				TEE_Param *in,
				TEE_Param *out,
				int decrypt)
{
	CK_RV rv;
	TEE_Result res;
	uint32_t session;
	uint32_t key_handle;
	char *ctrl2 = ctrl->memref.buffer;
	size_t ctrl2_size = ctrl->memref.size;
	struct sks_key_object *sks_key;
	CK_MECHANISM ck_mechanism;
	CK_KEY_TYPE key_type;
	struct pkcs11_session *pkcs_session;
	uint32_t tee_algo;
	uint32_t tee_algo_mode;
	size_t key_size;

	if (!ctrl || in || out || ctrl->memref.size < 2 * sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	session = *(uint32_t *)(void *)ctrl2;
	ctrl2 += sizeof(uint32_t);
	ctrl2_size -= sizeof(uint32_t);

	/* Update session state */
	if (set_pkcs_session_processing_state(session,
					      PKCS11_SESSION_ENCRYPTING))
		return TEE_ERROR_BAD_STATE;

	pkcs_session = get_pkcs_session(session);
	if (!pkcs_session) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto error;
	}

	key_handle = *(uint32_t *)(void *)ctrl2;
	ctrl2 += sizeof(uint32_t);
	ctrl2_size -= sizeof(uint32_t);

	sks_key = object_get_tee_handle(key_handle);
	if (!sks_key) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto error;
	}

	rv = serial_get_attribute(sks_key->attributes, CKA_KEY_TYPE,
				  &key_type, NULL);
	if (rv)
		TEE_Panic(0);


	memcpy(&ck_mechanism, ctrl2, sizeof(ck_mechanism));

	/* Check key main attribute (class/type) match algorithm */
	switch (key_type) {
	case CKK_AES:
		tee_algo_mode = decrypt ? TEE_MODE_DECRYPT : TEE_MODE_ENCRYPT;
		key_size = 16; // TODO: get size from the key attributes

		switch (ck_mechanism.mechanism) {
		case CKM_AES_ECB:
			tee_algo = TEE_ALG_AES_ECB_NOPAD;
			break;
		case CKM_AES_CBC:
			tee_algo = TEE_ALG_AES_CBC_NOPAD;
			break;
		case CKM_AES_CBC_PAD:
			res = TEE_ERROR_NOT_SUPPORTED;
			goto error;
		case CKM_AES_CTS:
		case CKM_AES_CTR:
		case CKM_AES_GCM:
		case CKM_AES_CCM:
			res = TEE_ERROR_NOT_SUPPORTED;
			goto error;
		default:
			res = TEE_ERROR_BAD_PARAMETERS;
			goto error;
		}
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Check the key attributes */
	if (!serial_boolean_attribute_matches(sks_key->attributes, decrypt ?
					      CKA_DECRYPT : CKA_ENCRYPT,
					      CK_TRUE)) {
		/* TODO: expected CK retval CKR_KEY_FUNCTION_NOT_PERMITTED */
		MSG("Operation not permited: key is not allowed for %scryption",
						decrypt ? "de" : "en");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto error;
	}

	if (pkcs_session->tee_op_handle != TEE_HANDLE_NULL)
		TEE_Panic(0);

	/* Allocate operation: AES/CTR, mode and size from params */
	res = TEE_AllocateOperation(&pkcs_session->tee_op_handle,
				    tee_algo, tee_algo_mode, key_size * 8);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		goto error;
	}

	res = TEE_SetOperationKey(pkcs_session->tee_op_handle,
				  sks_key->key_handle);
	if (res) {
		EMSG("TEE_SetOperationKey failed %x", res);
		goto error;
	}


	/* Specifc cipher initialization */
	switch (key_type) {
	case CKK_AES:
		switch (ck_mechanism.mechanism) {
		case CKM_AES_CBC:
			/* TODO: check in PKCS#11 where AES_CBC IV comes from */
			TEE_CipherInit(pkcs_session->tee_op_handle,
					&dummy_null_aes_iv,
					DUMMY_NULL_AES_IV_SIZE);
			break;
		default:
			break;
		}
	default:
		break;
	}

	return TEE_SUCCESS;

error:
	if (set_pkcs_session_processing_state(session, PKCS11_SESSION_READY))
		TEE_Panic(0);

	return res;
}

/*
 * ctrl = [session-handle]
 * in = data buffer
 * out = data buffer
 */
TEE_Result entry_cipher_update(TEE_Param *ctrl,
				TEE_Param *in,
				TEE_Param *out,
				int decrypt)
{
	uint32_t session;
	struct pkcs11_session *pkcs_session;

	if (!ctrl || ctrl->memref.size < sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	session = *(uint32_t *)(void *)ctrl->memref.buffer;;

	pkcs_session = get_pkcs_session(session);
	if (!pkcs_session)
		return TEE_ERROR_BAD_PARAMETERS;

	if (check_pkcs_session_processing_state(session, decrypt ?
						PKCS11_SESSION_DECRYPTING :
						PKCS11_SESSION_ENCRYPTING))
		return TEE_ERROR_BAD_STATE;

	return TEE_CipherUpdate(pkcs_session->tee_op_handle,
				in->memref.buffer, in->memref.size,
				out->memref.buffer, &out->memref.size);
}

/*
 * ctrl = [session-handle]
 * in = none
 * out = data buffer
 */
TEE_Result entry_cipher_final(TEE_Param *ctrl,
				TEE_Param *in,
				TEE_Param *out,
				int __unused decrypt)
{
	TEE_Result res;
	uint32_t session;
	struct pkcs11_session *pkcs_session;
	size_t dumm_length = 0;

	if (!ctrl || ctrl->memref.size < sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	session = *(uint32_t *)(void *)ctrl->memref.buffer;;

	pkcs_session = get_pkcs_session(session);
	if (!pkcs_session)
		return TEE_ERROR_BAD_PARAMETERS;

	if (check_pkcs_session_processing_state(session, decrypt ?
						PKCS11_SESSION_DECRYPTING :
						PKCS11_SESSION_ENCRYPTING))
		return TEE_ERROR_BAD_STATE;

	res = TEE_CipherDoFinal(pkcs_session->tee_op_handle,
				in ? in->memref.buffer : NULL,
				in ? in->memref.size : 0,
				out ? out->memref.buffer : NULL,
				out ? &out->memref.size : &dumm_length);

	if (set_pkcs_session_processing_state(session,
					      PKCS11_SESSION_READY))
		TEE_Panic(0);

	TEE_FreeOperation(pkcs_session->tee_op_handle);
	pkcs_session->tee_op_handle = TEE_HANDLE_NULL;

	return res;
}


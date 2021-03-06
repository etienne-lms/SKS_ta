/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ck_debug.h"
#include "ck_helpers.h"
#include "object.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"

// FIXME: temporary until the IV is properly handled
#define DUMMY_NULL_AES_IV_SIZE		16
static const char dummy_null_aes_iv[DUMMY_NULL_AES_IV_SIZE];

/* TODO: get a Cryptoki return value out of this */
static bool key_matches_cipher(CK_MECHANISM_PTR ck_mechanism,
				  struct sks_object *sks_key,
				  bool decrypt)
{
	uint32_t key_class;
	uint32_t key_type;

	/* expect a class and a type */
	if (serial_get_attribute(sks_key->attributes, CKA_CLASS,
				 &key_class, NULL) ||
	    serial_get_attribute(sks_key->attributes, CKA_KEY_TYPE,
				  &key_type, NULL))
		return false;

	/* Check key against mechanism */
	if (key_class != CKO_SECRET_KEY)
		return false;

	switch (key_type) {
	case CKK_AES:
		switch (ck_mechanism->mechanism) {
		case CKM_AES_ECB:
		case CKM_AES_CBC:
			break;
		case CKM_AES_CBC_PAD:
		case CKM_AES_CTS:
		case CKM_AES_CTR:
		case CKM_AES_GCM:
		case CKM_AES_CCM:
		default:
			return false;
		}
		break;
	default:
		return false;
	}

	if (!serial_boolean_attribute_matches(sks_key->attributes, decrypt ?
					      CKA_DECRYPT : CKA_ENCRYPT,
					      CK_TRUE))
		return false;

	/* TODO: lots of other attributes.... */
	return true;
}

struct tee_operation_params {
	uint32_t algo;
	uint32_t mode;
	uint32_t size;
};

/* TODO: get a Cryptoki return value out of this */
static CK_RV tee_operarion_params(struct tee_operation_params *params,
				CK_MECHANISM_PTR ck_mechanism,
				struct sks_object *sks_key,
				bool decrypt)
{
	uint32_t key_type;

	if (serial_get_attribute(sks_key->attributes, CKA_KEY_TYPE,
				  &key_type, NULL))
		return CKR_GENERAL_ERROR;

	switch (key_type) {
	case CKK_AES:
		params->mode = decrypt ? TEE_MODE_DECRYPT : TEE_MODE_ENCRYPT;
		params->size = 16; // TODO: get size from the key attributes

		switch (ck_mechanism->mechanism) {
		case CKM_AES_ECB:
			params->algo = TEE_ALG_AES_ECB_NOPAD;
			break;
		case CKM_AES_CBC:
			params->algo = TEE_ALG_AES_CBC_NOPAD;
			break;
		case CKM_AES_CBC_PAD:
			return CKR_FUNCTION_FAILED;
		case CKM_AES_CTS:
		case CKM_AES_CTR:
		case CKM_AES_GCM:
		case CKM_AES_CCM:
			return CKR_FUNCTION_FAILED;
		default:
			return CKR_KEY_TYPE_INCONSISTENT;
		}
		break;
	default:
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}


/*
 * ctrl = [session-handle][key-handle][serialized-mechanism-blob]
 * in = none
 * out = none
 */
CK_RV entry_cipher_init(int teesess, TEE_Param *ctrl,
			TEE_Param *in, TEE_Param *out, int decrypt)
{
	CK_RV rv;
	TEE_Result res;
	uint32_t session;
	uint32_t key_handle;
	char *ctrl2 = ctrl->memref.buffer;
	size_t ctrl2_size = ctrl->memref.size;
	struct sks_object *sks_key;
	CK_MECHANISM ck_mechanism;
	struct pkcs11_session *pkcs_session;
	struct tee_operation_params tee_op_params;
	uint32_t key_type;

	/* Arguments */
	if (!ctrl || in || out || ctrl->memref.size < 2 * sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	session = *(uint32_t *)(void *)ctrl2;
	ctrl2 += sizeof(uint32_t);
	ctrl2_size -= sizeof(uint32_t);

	pkcs_session = get_pkcs_session(session);
	if (!pkcs_session || pkcs_session->tee_session != teesess)
		return CKR_SESSION_HANDLE_INVALID;

	key_handle = *(uint32_t *)(void *)ctrl2;
	ctrl2 += sizeof(uint32_t);
	ctrl2_size -= sizeof(uint32_t);

	sks_key = object_get_tee_handle(key_handle);
	if (!sks_key)
		return CKR_KEY_HANDLE_INVALID;

	TEE_MemMove(&ck_mechanism, ctrl2, sizeof(ck_mechanism));

	if (!key_matches_cipher(&ck_mechanism, sks_key, decrypt))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	/* Check pkcs11 token/session states */
	if (set_pkcs_session_processing_state(session,
					      PKCS11_SESSION_ENCRYPTING))
		return CKR_OPERATION_ACTIVE;

	/* Allocate a TEE operation for the target processing */
	rv = tee_operarion_params(&tee_op_params, &ck_mechanism, sks_key,
				   decrypt);
	if (rv)
		goto error;

	if (pkcs_session->tee_op_handle != TEE_HANDLE_NULL)
		TEE_Panic(0);

	res = TEE_AllocateOperation(&pkcs_session->tee_op_handle,
				    tee_op_params.algo, tee_op_params.mode,
				    tee_op_params.size * 8);
	if (res) {
		DMSG("Failed to allocateoperation");
		rv = tee2ckr_error(res);
		goto error;
	}

	res = TEE_SetOperationKey(pkcs_session->tee_op_handle,
				  sks_key->key_handle);
	if (res) {
		DMSG("TEE_SetOperationKey failed %x", res);
		rv = tee2ckr_error(res);
		goto error;
	}

	/* Specifc cipher initialization */
	if (serial_get_attribute(sks_key->attributes, CKA_KEY_TYPE,
				  &key_type, NULL))
		TEE_Panic(0);

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

	return CKR_OK;

error:
	if (set_pkcs_session_processing_state(session,
					      PKCS11_SESSION_READY))
		TEE_Panic(0);

	if (pkcs_session->tee_op_handle != TEE_HANDLE_NULL) {
		TEE_FreeOperation(pkcs_session->tee_op_handle);
		pkcs_session->tee_op_handle = TEE_HANDLE_NULL;
	}

	return rv;
}

/*
 * ctrl = [session-handle]
 * in = data buffer
 * out = data buffer
 */
CK_RV entry_cipher_update(int teesess, TEE_Param *ctrl,
			  TEE_Param *in, TEE_Param *out, int decrypt)
{
	TEE_Result res;
	uint32_t session;
	struct pkcs11_session *pkcs_session;

	if (!ctrl || ctrl->memref.size < sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	session = *(uint32_t *)(void *)ctrl->memref.buffer;;

	pkcs_session = get_pkcs_session(session);
	if (!pkcs_session || pkcs_session->tee_session != teesess)
		return CKR_SESSION_HANDLE_INVALID;

	if (check_pkcs_session_processing_state(session, decrypt ?
						PKCS11_SESSION_DECRYPTING :
						PKCS11_SESSION_ENCRYPTING))
		return CKR_OPERATION_NOT_INITIALIZED;

	res = TEE_CipherUpdate(pkcs_session->tee_op_handle,
				in->memref.buffer, in->memref.size,
				out->memref.buffer, &out->memref.size);

	if (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
		if (set_pkcs_session_processing_state(session,
						      PKCS11_SESSION_READY))
			TEE_Panic(0);

		TEE_FreeOperation(pkcs_session->tee_op_handle);
		pkcs_session->tee_op_handle = TEE_HANDLE_NULL;
	}

	return tee2ckr_error(res);
}

/*
 * ctrl = [session-handle]
 * in = none
 * out = data buffer
 */
CK_RV entry_cipher_final(int teesess, TEE_Param *ctrl,
			 TEE_Param *in,	TEE_Param *out,	int decrypt)
{
	TEE_Result res;
	uint32_t session;
	struct pkcs11_session *pkcs_session;
	size_t dumm_length = 0;

	if (!ctrl || ctrl->memref.size < sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	session = *(uint32_t *)(void *)ctrl->memref.buffer;;

	pkcs_session = get_pkcs_session(session);
	if (!pkcs_session || pkcs_session->tee_session != teesess)
		return CKR_SESSION_HANDLE_INVALID;

	if (check_pkcs_session_processing_state(session, decrypt ?
						PKCS11_SESSION_DECRYPTING :
						PKCS11_SESSION_ENCRYPTING))
		return CKR_OPERATION_NOT_INITIALIZED;

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

	return tee2ckr_error(res);
}

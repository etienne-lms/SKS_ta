/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_abi.h>
#include <sks_ta.h>
#include <string.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "ck_debug.h"
#include "handle.h"
#include "pkcs11_token.h"

/* Provide 3 tokens, as a start (9 max :( */
#define TOKEN_COUNT	3
struct ck_token ck_token[TOKEN_COUNT];

static struct handle_db session_handle_db = HANDLE_DB_INITIALIZER;

static struct ck_token *get_token(unsigned int token_id)
{
	if (token_id > TOKEN_COUNT)
		return NULL;

	return &ck_token[token_id];
}

/*
 * Initialization routine for the trsuted application.
 */
static int __pkcs11_token_init(unsigned int id)
{
	char sn[] = SKS_CRYPTOKI_TOKEN_SERIAL_NUMBER;
	struct ck_token *token = get_token(id);

	if (!token)
		return 1;

	if (token->login_state != PKCS11_TOKEN_STATE_INVALID)
		return 0;

	// TODO: get persistent storage of SKS if available.

	/* Let's use a hard coded SN, one per token up to 9 */
	sn[strlen(sn) - 1] += id;
	PADDED_STRING_COPY(token->serial_number, sn);

	LIST_INIT(&token->session_list);
	TEE_MemFill(&token->session_handle_db, 0,
			sizeof(token->session_handle_db));

	token->flags |= CKF_SO_PIN_TO_BE_CHANGED;

	token->flags |= CKF_RNG;

	//TODO: CKF_WRITE_PROTECTED
	//TODO; CKF_LOGIN_REQUIRED
	//TODO; CKF_USER_PIN_INITIALIZED

	/* Archi choice; one can restore a state from an exported blob? */
	//info->flags |= CKF_RESTORE_KEY_NOT_NEEDED

	token->flags |= CKF_CLOCK_ON_TOKEN;
	/* TODO CKF_PROTECTED_AUTHENTICATION_PATH */
	token->flags |= CKF_DUAL_CRYPTO_OPERATIONS;

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

	token->login_state = PKCS11_TOKEN_STATE_PUBLIC_SESSIONS;

	return 0;
}

int pkcs11_init(void)
{
	unsigned int id;

	for (id = 0; id < TOKEN_COUNT; id++)
		if (__pkcs11_token_init(id))
			return 1;

	return 0;
}

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

static void *get_arg(void *dst, size_t size, void *src, size_t *src_size)
{
	char *ptr = src;

	if (src_size && (*src_size < size))
		return NULL;

	if (dst)
		TEE_MemMove(dst, ptr, size);

	if (src_size)
		*src_size -= size;

	return ptr + size;
}

/* ctrl=[slot-id][pin-size][pin], in=unused, out=unused */
CK_RV ck_token_initialize(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	char *ctrl_arg;
	size_t ctrl_size;
	uint32_t token_id;
	struct ck_token *token;
	uint32_t pin_size;
	void *pin;
	char label[32 + 1];

	if (!ctrl || in || out)
		return CKR_ARGUMENTS_BAD;

	ctrl_arg = ctrl->memref.buffer;
	ctrl_size = ctrl->memref.size;

	ctrl_arg = get_arg(&token_id, sizeof(uint32_t), ctrl_arg, &ctrl_size);
	if (!ctrl_arg)
		return CKR_ARGUMENTS_BAD;

	ctrl_arg = get_arg(&pin_size, sizeof(uint32_t), ctrl_arg, &ctrl_size);
	if (!ctrl_arg)
		return CKR_ARGUMENTS_BAD;

	pin = ctrl_arg;
	ctrl_arg = get_arg(NULL, pin_size, ctrl_arg, &ctrl_size);
	if (!ctrl_arg)
		return CKR_ARGUMENTS_BAD;

	ctrl_arg = get_arg(label, 32 * sizeof(char), ctrl_arg, &ctrl_size);
	if (!ctrl_arg)
		return CKR_ARGUMENTS_BAD;

	token = get_token(token_id);
	if (!token)
		return CKR_SLOT_ID_INVALID;

	if (token->flags & CKF_SO_PIN_LOCKED) {
		IMSG("Token SO PIN is locked");
		return CKR_PIN_LOCKED;
	}

	if (!LIST_EMPTY(&token->session_list)) {
		IMSG("SO cannot log in, pending session(s)");
		return CKR_SESSION_EXISTS;
	}

	if (!token->so_pin) {
		uint8_t *so_pin = TEE_Malloc(pin_size, 0);

		if (!so_pin)
			return CKR_DEVICE_MEMORY;

		TEE_MemMove(so_pin, pin, pin_size);
		token->so_pin_size = pin_size;
		token->so_pin = so_pin;

	} else {
		int pin_rc;

		/*  TODO: compare more if client pin is bigger than expected */
		pin_size = MIN(token->so_pin_size, pin_size);
		pin_rc = buf_compare_ct(token->so_pin, pin, pin_size);

		if (pin_rc || pin_size != token->so_pin_size) {
			token->flags |= CKF_SO_PIN_COUNT_LOW;
			token->so_pin_count++;

			if (token->so_pin_count == 6)
				token->flags |= CKF_SO_PIN_FINAL_TRY;
			if (token->so_pin_count == 7)
				token->flags |= CKF_SO_PIN_LOCKED;

			return CKR_PIN_INCORRECT;
		} else {
			token->flags &= (CKF_SO_PIN_COUNT_LOW |
					 CKF_SO_PIN_FINAL_TRY);
			token->so_pin_count = 0;
		}
	}

	TEE_MemMove(token->label, label, 32 * sizeof(char));
	token->flags |= CKF_TOKEN_INITIALIZED;

	label[32] = '\0';
	IMSG("Token \"%s\" is happy to be initilialized", label);

	return CKR_OK;
}

CK_RV ck_slot_list(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	const size_t out_size = sizeof(uint32_t) * TOKEN_COUNT;
	uint32_t *id;
	unsigned int n;

	if (ctrl || in || !out)
		return CKR_ARGUMENTS_BAD;

	if (out->memref.size < out_size) {
		out->memref.size = out_size;
		return CKR_BUFFER_TOO_SMALL;
	}

	for (id = out->memref.buffer, n = 0; n < TOKEN_COUNT; n++, id++)
		*id = (uint32_t)n;

	out->memref.size = out_size;
	return CKR_OK;
}

CK_RV ck_slot_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	const char desc[] = SKS_CRYPTOKI_SLOT_DESCRIPTION;
	const char manuf[] = SKS_CRYPTOKI_SLOT_MANUFACTURER;
	const CK_VERSION hwver = SKS_CRYPTOKI_SLOT_HW_VERSION;
	const CK_VERSION fwver = SKS_CRYPTOKI_SLOT_FW_VERSION;
	struct sks_ck_slot_info *info;
	uint32_t token_id;
	struct ck_token *token;

	if (!ctrl || in || !out)
		return CKR_ARGUMENTS_BAD;

	if (ctrl->memref.size != sizeof(token_id))
		return CKR_ARGUMENTS_BAD;

	TEE_MemMove(&token_id, ctrl->memref.buffer, sizeof(token_id));

	if (out->memref.size < sizeof(struct sks_ck_slot_info)) {
		out->memref.size = sizeof(struct sks_ck_slot_info);
		return CKR_BUFFER_TOO_SMALL;
	}

	token = get_token(token_id);
	if (!token)
		return CKR_SLOT_ID_INVALID;

	/* TODO: prevent crash on unaligned buffers */
	info = (void *)out->memref.buffer;

	TEE_MemFill(info, 0, sizeof(*info));

	PADDED_STRING_COPY(info->slotDescription, desc);
	PADDED_STRING_COPY(info->manufacturerID, manuf);

	info->flags |= CKF_TOKEN_PRESENT;
	info->flags |= CKF_REMOVABLE_DEVICE;	/* TODO: removeable? */
	info->flags &= ~CKF_HW_SLOT;		/* are we a HW slot? */

	TEE_MemMove(&info->hardwareVersion, &hwver, sizeof(hwver));
	TEE_MemMove(&info->firmwareVersion, &fwver, sizeof(fwver));

	out->memref.size = sizeof(struct sks_ck_slot_info);

	return CKR_OK;
}

CK_RV ck_token_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	const char manuf[] = SKS_CRYPTOKI_TOKEN_MANUFACTURER;
	const char model[] = SKS_CRYPTOKI_TOKEN_MODEL;
	const CK_VERSION hwver = SKS_CRYPTOKI_TOKEN_HW_VERSION;
	const CK_VERSION fwver = SKS_CRYPTOKI_TOKEN_FW_VERSION;
	struct sks_ck_token_info info;
	uint32_t token_id;
	struct ck_token *token;

	if (!ctrl || in || !out)
		return CKR_ARGUMENTS_BAD;

	if (ctrl->memref.size != sizeof(token_id))
		return CKR_ARGUMENTS_BAD;

	TEE_MemMove(&token_id, ctrl->memref.buffer, sizeof(token_id));

	if (out->memref.size < sizeof(struct sks_ck_token_info)) {
		out->memref.size = sizeof(struct sks_ck_token_info);
		return CKR_BUFFER_TOO_SMALL;
	}

	token = get_token(token_id);
	if (!token)
		return CKR_SLOT_ID_INVALID;

	TEE_MemFill(&info, 0, sizeof(info));

	PADDED_STRING_COPY(info.label, token->label);
	PADDED_STRING_COPY(info.manufacturerID, manuf);
	PADDED_STRING_COPY(info.model, model);
	PADDED_STRING_COPY(info.serialNumber, token->serial_number);

	info.flags = token->flags;

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

	TEE_MemMove(&info.hardwareVersion, &hwver, sizeof(CK_VERSION));
	TEE_MemMove(&info.firmwareVersion, &fwver, sizeof(CK_VERSION));

	// TODO: get time and convert from refence into YYYYMMDDhhmmss/UTC
	TEE_MemFill(info.utcTime, 0, sizeof(info.utcTime));

	/* Return to caller with data */
	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	return CKR_OK;
}

/* TODO: this is a temporary implementation */
CK_RV ck_token_mecha_ids(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	// TODO: get the list of supported mechanism
	const CK_MECHANISM_TYPE mecha_list[] = {
		CKM_MD5, CKM_SHA_1, CKM_SHA256, CKM_SHA224, CKM_SHA384, CKM_SHA512,
		CKM_AES_ECB, CKM_AES_CBC, CKM_AES_MAC, CKM_AES_CBC_PAD,
		CKM_AES_CTR, CKM_AES_GCM, CKM_AES_CCM, CKM_AES_CTS,
	};
	uint32_t token_id;
	struct ck_token *token;

	if (!ctrl || in || !out)
		return CKR_ARGUMENTS_BAD;

	if (out->memref.size < sizeof(mecha_list)) {
		out->memref.size = sizeof(mecha_list);
		return CKR_BUFFER_TOO_SMALL;
	}

	if (ctrl->memref.size != sizeof(token_id))
		return CKR_ARGUMENTS_BAD;

	TEE_MemMove(&token_id, ctrl->memref.buffer, sizeof(token_id));

	token = get_token(token_id);
	if (!token)
		return CKR_SLOT_ID_INVALID;

	/* TODO: can a token support a restricted mechanism list */
	out->memref.size = sizeof(mecha_list);
	TEE_MemMove(out->memref.buffer, mecha_list, sizeof(mecha_list));

	return CKR_OK;
}

/* TODO: this is a temporary implementation */
CK_RV ck_token_mecha_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	CK_MECHANISM_INFO info;
	CK_MECHANISM_TYPE type;
	uint32_t token_id;
	struct ck_token *token;
	char *ctrl_ptr;

	if (!ctrl || in || !out)
		return CKR_ARGUMENTS_BAD;

	if (out->memref.size < sizeof(info)) {
		out->memref.size = sizeof(info);
		return CKR_BUFFER_TOO_SMALL;
	}

	if (ctrl->memref.size != 2 * sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	ctrl_ptr = ctrl->memref.buffer;
	TEE_MemMove(&token_id, ctrl_ptr, sizeof(uint32_t));
	ctrl_ptr += sizeof(uint32_t);
	TEE_MemMove(&type, ctrl_ptr, sizeof(uint32_t));

	token = get_token(token_id);
	if (!token)
		return CKR_SLOT_ID_INVALID;

	TEE_MemFill(&info, 0, sizeof(info));

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
	TEE_MemMove(out->memref.buffer, &info, sizeof(info));

	return CKR_OK;
}

/* ctrl=[slot-id], in=unused, out=[session-handle] */
static CK_RV ck_token_session(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out, bool ro)
{
	struct pkcs11_session *session;
	uint32_t token_id;
	struct ck_token *token;

	if (!ctrl || in || !out)
		return CKR_ARGUMENTS_BAD;

	if (out->memref.size < sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	if (ctrl->memref.size != sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	TEE_MemMove(&token_id, ctrl->memref.buffer, sizeof(uint32_t));
	token = get_token(token_id);
	if (!token)
		return CKR_SLOT_ID_INVALID;

	if (!ro && token->session_state == PKCS11_TOKEN_STATE_READ_ONLY) {
		// TODO: if token is read-only, refuse RW sessions
		// See CKR_SESSION_READ_WRITE_SO_EXISTS
		return CKR_SESSION_READ_WRITE_SO_EXISTS;
	}

	session = TEE_Malloc(sizeof(*session), 0);
	if (!session)
		return CKR_DEVICE_MEMORY;

	session->handle = handle_get(&session_handle_db, session);
	session->tee_session = teesess;
	session->processing = PKCS11_SESSION_READY;
	session->tee_op_handle = TEE_HANDLE_NULL;
	LIST_INIT(&session->object_list);
	session->token = token;

	LIST_INSERT_HEAD(&token->session_list, session, link);

	*(uint32_t *)out->memref.buffer = session->handle;
	out->memref.size = sizeof(uint32_t);

	return CKR_OK;
}

/* ctrl=[slot-id], in=unused, out=[session-handle] */
CK_RV ck_token_ro_session(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out)
{
	return ck_token_session(teesess, ctrl, in, out, true);
}

/* ctrl=[slot-id], in=unused, out=[session-handle] */
CK_RV ck_token_rw_session(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out)
{
	return ck_token_session(teesess, ctrl, in, out, false);
}

static void close_ck_session(struct pkcs11_session *session)
{
	(void)handle_put(&session_handle_db, session->handle);

	if (session->tee_op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(session->tee_op_handle);

	while (!LIST_EMPTY(&session->object_list)) {
		destroy_object(session, LIST_FIRST(&session->object_list), true);
	}

	LIST_REMOVE(session, link);

	if (LIST_EMPTY(&session->token->session_list)) {
		// TODO: if last session closed, token moves to Public state
	}

	TEE_Free(session);
}

/* ctrl=[session-handle], in=unused, out=unused */
CK_RV ck_token_close_session(int teesess, TEE_Param *ctrl,
				  TEE_Param *in, TEE_Param *out)
{
	struct pkcs11_session *session;
	uint32_t handle;

	if (!ctrl || in || out || ctrl->memref.size < sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	TEE_MemMove(&handle, ctrl->memref.buffer, sizeof(uint32_t));
	session = get_pkcs_session(handle);
	if (!session)
		return CKR_SESSION_HANDLE_INVALID;

	if (session->tee_session != teesess)
		return CKR_SESSION_HANDLE_INVALID;

	close_ck_session(session);

	return CKR_OK;
}

CK_RV ck_token_close_all(int teesess, TEE_Param *ctrl,
			      TEE_Param *in, TEE_Param *out)
{
	uint32_t token_id;
	struct ck_token *token;
	struct pkcs11_session *session;

	if (!ctrl || in || out)
		return CKR_ARGUMENTS_BAD;

	if (out->memref.size < sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	if (ctrl->memref.size != sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	TEE_MemMove(&token_id, ctrl->memref.buffer, sizeof(uint32_t));
	token = get_token(token_id);
	if (!token)
		return CKR_SLOT_ID_INVALID;

	LIST_FOREACH(session, &token->session_list, link) {
		if (session->tee_session != teesess)
			continue;

		close_ck_session(session);
	}

	return CKR_OK;
}

/*
 * Parse all tokens and all session. Close all session that are relying on
 * the target TEE session ID which is being closed by caller.
 */
void ck_token_close_tee_session(int tee_session)
{
	struct ck_token *token;
	struct pkcs11_session *session;
	int n;

	for (n = 0; n < TOKEN_COUNT; n++) {
		token = get_token(n);
		if (!token)
			continue;

		LIST_FOREACH(session, &token->session_list, link) {
			if (session->tee_session != tee_session)
				continue;

			close_ck_session(session);
		}
	}
}

/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_TA_PKCS11_TOKEN_H
#define __SKS_TA_PKCS11_TOKEN_H

#include <pkcs11.h>
#include <tee_internal_api.h>

/* Hard coded description */
#define SKS_CRYPTOKI_TOKEN_LABEL		"op-tee pkcs#11 token (dev...)"
#define SKS_CRYPTOKI_TOKEN_MANUFACTURER		"Linaro"
#define SKS_CRYPTOKI_TOKEN_MODEL		"SKS TA"
#define SKS_CRYPTOKI_TOKEN_SERAIL_NUMBER	"00000000000"
#define SKS_CRYPTOKI_TOKEN_HW_VERSION		{ 0, 0 }
#define SKS_CRYPTOKI_TOKEN_FW_VERSION		{ 0, 0 }

#define PADDED_STRING_COPY(_dst, _src) \
	do { \
		TEE_MemFill((char *)(_dst), ' ', sizeof(_dst)); \
		TEE_MemMove((char *)(_dst), (_src), \
			    MIN(strlen((char *)(_src)), sizeof(_dst))); \
	} while (0)


enum pkcs11_token_login_state {
	PKCS11_TOKEN_STATE_INVALID = 0,
	PKCS11_TOKEN_STATE_PUBLIC_SESSIONS,
	PKCS11_TOKEN_STATE_SECURITY_OFFICER,
	PKCS11_TOKEN_STATE_USER_SESSIONS,
	PKCS11_TOKEN_STATE_CONTEXT_SPECIFIC,
};

/*
 * State of the PKCS#11 token
 *
 * @label = see PKCS#11
 * @serial_numnber
 * @session_counter;
 * @rw_session_counter;
 * @min_pin_len;
 * @max_pin_len;
 * @state - see PKCS11_TOKEN_STATE_XXX
 */
struct ck_token_state {
	uint8_t label[32];			/* set by the client */
	uint8_t serial_number[16];		/* shall be provisioned somewhere */

	uint32_t session_counter;
	uint32_t rw_session_counter;

	uint32_t min_pin_len;
	uint32_t max_pin_len;

	CK_USER_TYPE user_type;			/* SecurityOfficer, User or Public */
	enum pkcs11_token_login_state state;	/* State of who logged and how */

	// TODO list of the sessions
};

/*
 * A session can enter a processing state (encrypt, decrypt, disgest, ...
 * ony from  the inited state. A sesion must return the the inited
 * state (from a processing finalization request) before entering another
 * processing state.
 */
enum pkcs11_session_processing {
	PKCS11_SESSION_READY,
	PKCS11_SESSION_ENCRYPTING,
	PKCS11_SESSION_DECRYPTING,
	PKCS11_SESSION_DIGESTING,
	PKCS11_SESSION_DIGESTING_ENCRYPTING,	/* case C_DigestEncryptUpdate */
	PKCS11_SESSION_DECRYPTING_DIGESTING,	/* case C_DecryptDigestUpdate */
	PKCS11_SESSION_SIGNING,
	PKCS11_SESSION_SIGNING_ENCRYPTING,	/* case C_SignEncryptUpdate */
	PKCS11_SESSION_VERIFYING,
	PKCS11_SESSION_DECRYPTING_VERIFYING,	/* case C_DecryptVerifyUpdate */
	PKCS11_SESSION_SIGNING_RECOVER,
	PKCS11_SESSION_VERIFYING_RECOVER,
};

/*
 * Structure tracing the PKCS#11 sessions
 *
 * @tee_session - TEE session use to create the PLCS session
 * @handle - identifier of the session
 * @read_only - true if the session is read-only, false if read/write
 * @state - R/W SO, R/W user, RO user, R/W public, RO public. See PKCS11.
 */
struct pkcs11_session {
	void *tee_session;
	int handle;
	CK_STATE state;
	enum pkcs11_session_processing processing;
	TEE_OperationHandle tee_op_handle;	// HANDLE_NULL or on-going operation
};

int pkcs11_token_init(void);

TEE_Result ck_token_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
TEE_Result ck_token_mecha_ids(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
TEE_Result ck_token_mecha_info(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);

TEE_Result ck_token_ro_session(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
TEE_Result ck_token_rw_session(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
TEE_Result ck_token_close_session(TEE_Param *ctrl, TEE_Param *i, TEE_Param *o);

struct pkcs11_session *get_pkcs_session(uint32_t ck_handle);
int set_pkcs_session_processing_state(uint32_t ck_session,
				      enum pkcs11_session_processing state);
int check_pkcs_session_processing_state(uint32_t ck_session,
					enum pkcs11_session_processing state);

#endif /*__SKS_TA_PKCS11_TOKEN_H*/

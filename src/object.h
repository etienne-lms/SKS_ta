/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_OBJECT_H
#define __SKS_OBJECT_H

#include <sys/queue.h>
#include <tee_internal_api.h>

struct pkcs11_session;

struct sks_key_object {
	LIST_ENTRY(sks_key_object) link;
	void *session_owner;
	uint32_t ck_handle;
	/* poitner tho the serialized key attributes */
	void *attributes;
	TEE_ObjectHandle key_handle;
	/* These are for persistent/token objects */
	void *id;
	size_t id_size;
};

LIST_HEAD(object_list, sks_key_object);

struct sks_key_object *object_get_tee_handle(uint32_t ck_handle);

CK_RV entry_create_object(int teesess, TEE_Param *ctrl,
			  TEE_Param *in, TEE_Param *out);

CK_RV entry_destroy_object(int teesess, TEE_Param *ctrl,
			   TEE_Param *in, TEE_Param *out);

CK_RV destroy_object(struct pkcs11_session *session,
		     struct sks_key_object *object,
		     bool session_object_only);

#endif /*__SKS_OBJECT_H*/

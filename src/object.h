/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_OBJECT_H
#define __SKS_OBJECT_H

#include <tee_internal_api.h>

struct sks_key_object {
	uint32_t session_owner;
	uint32_t ck_handle;
	/* poitner tho the serialized key attributes */
	void *attributes;
	TEE_ObjectHandle key_handle;
	/* These are for persistent/token objects */
	void *id;
	size_t id_size;
	/* This is AES key specific (TODO: move to a sub structure) */
	size_t key_size;
	uint32_t tee_algo;
	// TODO: list of the session currently processing with the key.
	// These should not continue processing if the session owning
	// key creation is closed (applicabble to volatile/non-token ojbects)
};

struct sks_key_object *object_get_tee_handle(uint32_t ck_handle);

TEE_Result entry_create_object(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);
TEE_Result entry_destroy_object(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out);

#endif /*__SKS_OBJECT_H*/

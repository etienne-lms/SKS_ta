/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_OBJECT_H
#define __SKS_OBJECT_H

#include <sys/queue.h>
#include <tee_internal_api.h>

struct pkcs11_session;

struct sks_object {
	LIST_ENTRY(sks_object) link;
	void *session_owner;
	uint32_t ck_handle;
	/* poitner tho the serialized key attributes */
	void *attributes;
	TEE_ObjectHandle key_handle;
	/* These are for persistent/token objects */
	void *id;
	size_t id_size;
	/* These are for session raw object, not as TEE tranisient object */
	void *data;
	size_t data_size;
};

LIST_HEAD(object_list, sks_object);

struct sks_object *object_get_tee_handle(uint32_t ck_handle);

/*
 * create_object - create an SKS object from its attributes and value
 *
 * @session - session requesting object creation
 * @attribute - reference to serialized attributes
 * @data - reference to object value
 * @data_size - byte size of the object value
 * @handle - generated handle for the created object
 */
CK_RV create_object(void *session, void *attribute,
		    void *data, size_t data_size,
		    uint32_t *handle);

/*
 * destroy_object - destroy an SKS object
 *
 * @session - session requesting object destruction
 * @object - reference to the sks object
 * @session_object_only - true is only session object shall be destroyed
 */
CK_RV destroy_object(struct pkcs11_session *session,
		     struct sks_object *object,
		     bool session_object_only);

/*
 * Entry points for SKS object client commands
 */
CK_RV entry_create_object(int teesess, TEE_Param *ctrl,
			  TEE_Param *in, TEE_Param *out);

CK_RV entry_destroy_object(int teesess, TEE_Param *ctrl,
			   TEE_Param *in, TEE_Param *out);


#endif /*__SKS_OBJECT_H*/

/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <pkcs11.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ck2tee_id.h"
#include "handle.h"
#include "pkcs11_object.h"
#include "sanitize_object.h"
#include "serializer.h"

static struct handle_db object_handle_db = HANDLE_DB_INITIALIZER;

struct sks_key_object *object_get_tee_handle(uint32_t ck_handle)
{
	int handle = (int)ck_handle;
	struct sks_key_object *obj = handle_lookup(&object_handle_db, handle);

	return obj;
}

/*
 * Create an AES key object
 *
 * @session - session onwing the object creation
 * @head - serialized attributes (incl. CKA_VALUE attribute storing the key)
 * @hld - object handle returned to hte client
 */
static TEE_Result create_aes_key(uint32_t session, struct sks_obj_rawhead *head,
				 uint32_t *hdl)
{
	CK_RV rv;
	TEE_Result res;
	struct sks_key_object *obj;
	char *key_data;
	size_t key_size = 0;
	uint8_t is_persistent;
	TEE_Attribute tee_key_attr;

	obj = TEE_Malloc(sizeof(*obj), 0);
	if (!obj)
		return TEE_ERROR_OUT_OF_MEMORY;

	obj->key_handle = TEE_HANDLE_NULL;
	obj->attributes = head;

	/* Create a unique ID (FIXME; find a better way than RANDOM) */
	obj->id_size = 32;
	obj->id = TEE_Malloc(obj->id_size, 0);
	if (!obj->id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_GenerateRandom(obj->id, obj->id_size);

	/* Get the key data from the serial object */
	rv = serial_get_attribute(head, CKA_VALUE, NULL, &key_size);
	if (rv != CKR_BUFFER_TOO_SMALL)
		return ckr2tee(rv);

	rv = serial_get_attribute_ptr(head, CKA_VALUE,
				      (void **)&key_data, &key_size);
	if (rv)
		TEE_Panic(0);

	/* Create the TEE object */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &obj->key_handle);
	if (res)
		goto bail;

	TEE_InitRefAttribute(&tee_key_attr, TEE_ATTR_SECRET_VALUE,
				key_data, key_size);

	res = TEE_PopulateTransientObject(obj->key_handle, &tee_key_attr, 1);
	if (res) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		goto bail;
	}

	/* Session bound or persistent object? */
	rv = serial_get_attribute(head, CKA_TOKEN, &is_persistent, NULL);
	if (rv)
		TEE_Panic(0);

	if (is_persistent) {
		TEE_ObjectHandle handle = obj->key_handle;

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 obj->id, obj->id_size,
						 TEE_DATA_FLAG_ACCESS_READ |
						 TEE_DATA_FLAG_ACCESS_WRITE |
						 TEE_DATA_FLAG_ACCESS_WRITE_META |
						 TEE_DATA_FLAG_OVERWRITE,
						 handle,
						 key_data, key_size,
						 &obj->key_handle);

		TEE_FreeTransientObject(handle);
		if (res) {
			obj->key_handle = TEE_HANDLE_NULL;
			goto bail;
		}

		//TODO: add the object to the secure storage SKS database

	} else {
		/* Volatile objects are tied to the session that creates them */
		obj->session_owner = session;
	}

	/* TODO: save the struct sks_key_object into the SKS database */

	res = TEE_SUCCESS;

bail:
	if (res) {
		TEE_FreeTransientObject(obj->key_handle);
		TEE_Free(obj);
	} else {
		int ck_handle = handle_get(&object_handle_db, obj);

		if (ck_handle < 0 || ck_handle > 0x7FFFFFFF)
			return TEE_ERROR_GENERIC; // FIXME: errno

		obj->ck_handle = (uint32_t)ck_handle;
		*hdl = obj->ck_handle;
	}

	return res;
}


static TEE_Result create_sym_key(uint32_t session, void *head, uint32_t *hdl)
{
	switch (serial_get_type(head)) {
	case CKK_AES:
		return create_aes_key(session, head, hdl);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result create_data_blob(uint32_t __unused session,
				   void __unused *head, uint32_t __unused *hdl)
{
	// TODO
	// - Create an object reference
	// - Sanitize the properties
	// - Save in secure storage if CKA_TOKEN data == true

	return TEE_ERROR_NOT_SUPPORTED;
}

/*
 * Create an object from a clear content provided by client
 */
TEE_Result entry_create_object(TEE_Param __unused *ctrl,
				TEE_Param __unused *in,
				TEE_Param __unused *out)
{
	TEE_Result res;
	CK_RV rv;
	char *sess_ptr;
	uint32_t session;
	char *head;
	uint32_t obj_handle;
	void *temp;
	size_t temp_size;

	if (!ctrl || in || !out || out->memref.size < sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	/* TODO: check session handle */
	sess_ptr = ctrl->memref.buffer;
	session = *(uint32_t *)(void *)sess_ptr;

	/* Check the attributes */
	temp_size = ctrl->memref.size - sizeof(uint32_t);
	temp = TEE_Malloc(temp_size, 0);
	if (!temp)
		return TEE_ERROR_OUT_OF_MEMORY;

	head = sess_ptr + sizeof(uint32_t);
	memcpy(temp, head, temp_size);
	rv = serial_sanitize_attributes((void **)&head, temp, temp_size);
	if (rv)
		return ckr2tee(rv);

	TEE_Free(temp);

	/* Route to the object manager */
	switch (serial_get_class(head)) {
	case CKO_DATA:
		/* TODO: set/check the attributes for a DATA object */
		res = create_data_blob(session, head, &obj_handle);
		break;
	case CKO_SECRET_KEY:
		/* TODO: set/check the attributes for a SecretKey object */
		if (serial_get_attribute(head, CKA_VALUE, NULL, NULL)) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}

		res = create_sym_key(session, head, &obj_handle);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	memcpy(out->memref.buffer, &obj_handle, sizeof(uint32_t));
	out->memref.size = sizeof(uint32_t);

out:
	if (res)
		TEE_Free(head);
	return res;
}

TEE_Result entry_destroy_object(TEE_Param __unused *ctrl,
				TEE_Param __unused *in,
				TEE_Param __unused *out)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

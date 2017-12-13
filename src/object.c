/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <inttypes.h>
#include <pkcs11.h>
#include <string_ext.h>		// (for buf_compare_ct)
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ck_debug.h"
#include "handle.h"
#include "object.h"
#include "pkcs11_object.h"
#include "pkcs11_token.h"
#include "sanitize_object.h"
#include "serializer.h"

/*
 * A database for the objects loaded in the TA.
 * This is a volatile database. TODO Add support for a persistent database
 */
static struct handle_db object_handle_db = HANDLE_DB_INITIALIZER;

struct sks_key_object *object_get_tee_handle(uint32_t ck_handle)
{
	int handle = (int)ck_handle;
	struct sks_key_object *obj = handle_lookup(&object_handle_db, handle);

	return obj;
}

/*
 * Destroy an object
 *
 * @session - session requesting object destruction
 * @hld - object handle returned to hte client
 */
TEE_Result destroy_object(struct pkcs11_session *session,
			  struct sks_key_object *object,
			  bool session_only)
{
	CK_BBOOL is_persistent;
	struct pkcs11_session *obj_session;

	// TODO: debug trace
	//serial_trace_attributes_from_head("[destroy]", object->attributes);

	/*
	 * Objects are reachable only from their context.
	 * We only support pkcs11 session for now: check object token id.
	 */
	obj_session = object->session_owner;
	if (obj_session->token != session->token)
		return TEE_ERROR_BAD_PARAMETERS;

	if (serial_get_attribute(object->attributes, CKA_TOKEN,
				 &is_persistent, NULL))
		TEE_Panic(0);

	if (is_persistent) {
		if (object->key_handle != TEE_HANDLE_NULL && session_only)
			TEE_CloseObject(object->key_handle);

		if (object->key_handle != TEE_HANDLE_NULL && !session_only)
			TEE_CloseAndDeletePersistentObject1(object->key_handle);

		TEE_Free(object->id);
	} else {
		/* Session object are reacheable only from their session */
		if (obj_session != session)
			return TEE_ERROR_BAD_PARAMETERS;

		if (object->key_handle != TEE_HANDLE_NULL)
			TEE_FreeTransientObject(object->key_handle);
	}

	LIST_REMOVE(object, link);
	TEE_Free(object);

	return TEE_SUCCESS;
}

/*
 * Create an AES key object
 *
 * @session - session onwing the object creation
 * @head - serialized attributes (incl. CKA_VALUE attribute storing the key)
 * @hld - object handle returned to hte client
 */
static TEE_Result create_aes_key(struct pkcs11_session *session,
				 void *head, uint32_t *hdl)
{
	CK_RV rv;
	TEE_Result res;
	struct sks_key_object *obj;
	char *key_data;
	size_t key_size = 0;
	uint8_t is_persistent;
	TEE_Attribute tee_key_attr;

	/*
	 * We do not check the key attributes. At this point, key attributes
	 * are expected consistent and reliable.
	 */
	obj = TEE_Malloc(sizeof(*obj), TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!obj)
		return TEE_ERROR_OUT_OF_MEMORY;

	obj->key_handle = TEE_HANDLE_NULL;
	obj->attributes = head;

	/* Get the key data from the serial object */
	rv = serial_get_attribute(head, CKA_VALUE, NULL, &key_size);
	if (rv != CKR_BUFFER_TOO_SMALL)
		TEE_Panic(CKR_ATTRIBUTE_VALUE_INVALID);

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
		EMSG("TEE_PopulateTransientObject failed, %" PRIx32, res);
		goto bail;
	}

	/* Session bound or persistent object? */
	rv = serial_get_attribute(head, CKA_TOKEN, &is_persistent, NULL);
	if (rv)
		TEE_Panic(0);

	if (is_persistent) {
		TEE_ObjectHandle handle = obj->key_handle;

		/*
		 * Create a unique ID
		 * FIXME; find a better ID scheme than a random number
		 */
		obj->id_size = 32;
		obj->id = TEE_Malloc(obj->id_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!obj->id)
			return TEE_ERROR_OUT_OF_MEMORY;

		TEE_GenerateRandom(obj->id, obj->id_size);

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 obj->id, obj->id_size,
						 TEE_DATA_FLAG_ACCESS_READ |
						 TEE_DATA_FLAG_ACCESS_WRITE |
						 TEE_DATA_FLAG_ACCESS_WRITE_META |
						 TEE_DATA_FLAG_OVERWRITE, /* TODO: don't overwrite! */
						 handle,
						 key_data, key_size,
						 &obj->key_handle);

		TEE_FreeTransientObject(handle);
		if (res) {
			obj->key_handle = TEE_HANDLE_NULL;
			goto bail;
		}

		//TODO: add the object to the secure storage SKS database

	}

	obj->session_owner = session;
	LIST_INSERT_HEAD(&session->object_list, obj, link);

	// TODO: debug trace
	//serial_trace_attributes_from_head("[create]", object->attributes);

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


static TEE_Result create_sym_key(struct pkcs11_session *session,
				 void *head, uint32_t *hdl)
{
	switch (serial_get_type(head)) {
	case CKK_AES:
		return create_aes_key(session, head, hdl);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

/*
 * Create an raw DATA object
 *
 * @session - session onwing the object creation
 * @head - pointer to serialized attributes
 * @hld - object handle returned to hte client
 */
static TEE_Result create_data_blob(struct pkcs11_session __unused *session,
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
TEE_Result entry_create_object(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out)
{
	TEE_Result res;
	CK_RV rv;
	char *ctrl_ptr;
	uint32_t ck_session;
	struct pkcs11_session *session;
	char *head;
	uint32_t obj_handle;
	void *temp;
	size_t temp_size;
	void *obj_head = NULL;

	if (!ctrl || in || !out || out->memref.size < sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	ctrl_ptr = ctrl->memref.buffer;
	ck_session = *(uint32_t *)(void *)ctrl_ptr;

	session = get_pkcs_session(ck_session);
	if (!session || session->tee_session != teesess)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Safely copy and sanitize the client attribute serial object
	 */
	temp_size = ctrl->memref.size - sizeof(uint32_t);
	temp = TEE_Malloc(temp_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!temp)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(temp, ctrl_ptr + sizeof(uint32_t), temp_size);
	rv = serial_sanitize_attributes((void **)&head, temp, temp_size);
	if (rv)
		return ckr2tee(rv);

	TEE_Free(temp);

	/* Route to the object manager */
	switch (serial_get_class(head)) {
	case CKO_DATA:
		res = TEE_ERROR_BAD_PARAMETERS;
		obj_head = set_pkcs11_data_object_attributes(head);
		if (obj_head)
			res = create_data_blob(session, obj_head, &obj_handle);
		break;
	case CKO_SECRET_KEY:
		res = TEE_ERROR_BAD_PARAMETERS;
		obj_head = set_pkcs11_imported_symkey_attributes(head);
		if (obj_head)
			res = create_sym_key(session, obj_head, &obj_handle);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	TEE_Free(head);

	if (res) {
		TEE_Free(obj_head);
		return res;
	}

	/* Return object handle to the client */
	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(uint32_t));
	out->memref.size = sizeof(uint32_t);

	return res;
}

TEE_Result entry_destroy_object(int teesess, TEE_Param *ctrl,
				TEE_Param *in,	TEE_Param *out)
{
	size_t ctrl_size;
	char *ctrl_ptr;
	uint32_t session_handle;
	uint32_t object_handle;
	struct pkcs11_session *session;
	struct sks_key_object *object;

	if (!ctrl || in || out)
		return TEE_ERROR_BAD_PARAMETERS;

	ctrl_size = ctrl->memref.size;
	ctrl_ptr = ctrl->memref.buffer;

	/* First serial arg: [32b-session-handle] */
	if (ctrl_size < sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_MemMove(&session_handle, ctrl_ptr, sizeof(uint32_t));
	ctrl_ptr += sizeof(uint32_t);
	ctrl_size -= sizeof(uint32_t);

	session = get_pkcs_session(session_handle);

	if (!session || session->tee_session != teesess)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Next serial arg: [32b-object-handle] */
	if (ctrl_size < sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_MemMove(&object_handle, ctrl_ptr, sizeof(uint32_t));
	ctrl_ptr += sizeof(uint32_t);
	ctrl_size -= sizeof(uint32_t);

	object = object_get_tee_handle(object_handle);

	if (!object || object->session_owner != session)
		return TEE_ERROR_BAD_PARAMETERS;

	return destroy_object(session, object, false);
}

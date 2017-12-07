/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <inttypes.h>
#include <pkcs11.h>
#include <stdlib.h>	// FIXME: for free, until serializer.c uses TEE_Realloc
#include <string.h>	// FIXME: use TEE_MemCopy(), not memcpy()
#include <string_ext.h>		// (for buf_compare_ct)
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ck2tee_id.h"
#include "handle.h"
#include "pkcs11_object.h"
#include "sanitize_object.h"
#include "serializer.h"

/*
 * Object default boolean attributes as per PKCS#11
 */
static CK_BBOOL *pkcs11_object_default_boolprop(CK_ATTRIBUTE_TYPE attribute)
{
	static const CK_BBOOL bool_true = CK_TRUE;
	static const CK_BBOOL bool_false = CK_FALSE;

	switch (attribute) {
	/* As per PKCS#11 default value */
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_SENSITIVE:  /* symkey false, privkey: token specific */
	case CKA_ALWAYS_SENSITIVE:
		return (CK_BBOOL *)&bool_false;
	case CKA_MODIFIABLE:
	case CKA_COPYABLE:
	case CKA_DESTROYABLE:
		return (CK_BBOOL *)&bool_true;
	/* Token specific default value */
	case CKA_DERIVE:
	case CKA_LOCAL:
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_VERIFY:
	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_EXTRACTABLE:
	case CKA_NEVER_EXTRACTABLE:
	case CKA_WRAP_WITH_TRUSTED:
	case CKA_TRUSTED:
		// TODO: add const to serialize_xxx to remove this cast
		return (CK_BBOOL *)&bool_false;
	default:
		DMSG("Unexpected boolprop attribute %" PRIx32, attribute);
		TEE_Panic(0); // FIXME: errno
	}

	/* Keep compiler happy */
	return NULL;
}

static CK_RV set_object_boolprop(struct serializer *obj,
				 CK_ATTRIBUTE_TYPE attribute, CK_BBOOL value)
{
	CK_BBOOL val = value;

	return serialize_sks_ref(obj, attribute, &val, sizeof(val));
}

static CK_RV import_object_boolprop(struct serializer *obj, void *head,
				    CK_ATTRIBUTE_TYPE attribute)
{
	CK_RV rv;
	CK_BBOOL *attr;
	size_t attr_size;

	rv = serial_get_attribute_ptr(head, attribute, (void **)&attr, &attr_size);

	/* default value if not found or malformed */
	if (rv || attr_size != sizeof(CK_BBOOL))
		attr = pkcs11_object_default_boolprop(attribute);

	/* CK_BBOOL is 1byte, no alignment issue */
	return serialize_sks_ref(obj, attribute, attr, sizeof(CK_BBOOL));
}

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
 * Create an AES key object
 *
 * @session - session onwing the object creation
 * @head - serialized attributes (incl. CKA_VALUE attribute storing the key)
 * @hld - object handle returned to hte client
 */
static TEE_Result create_aes_key(uint32_t session, void *head, uint32_t *hdl)
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
	obj = TEE_Malloc(sizeof(*obj), 0);
	if (!obj)
		return TEE_ERROR_OUT_OF_MEMORY;

	obj->key_handle = TEE_HANDLE_NULL;
	obj->attributes = head;

	/*
	 * Create a unique ID
	 * FIXME; find a better ID scheme than a random number
	 */
	obj->id_size = 32;
	obj->id = TEE_Malloc(obj->id_size, 0);
	if (!obj->id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_GenerateRandom(obj->id, obj->id_size);

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

static void *set_pkcs11_imported_symkey_attributes(void *ref)
{
	CK_RV rv;
	struct serializer obj;
	void *attr;
	size_t size;
	CK_ULONG class = serial_get_class(ref);
	CK_ULONG type = serial_get_type(ref);

	/* TODO: move to keyhead serial object: easier boolprop handling */
	reset_serial_object_rawhead(&obj);

	/* Class and type are mandatory */
	rv = serialize_sks_ref(&obj, CKA_CLASS, &class, sizeof(class));
	if (rv)
		goto bail;

	rv = serialize_sks_ref(&obj, CKA_KEY_TYPE, &type, sizeof(type));
	if (rv)
		goto bail;

	/* Default boolean properties the client template can override */
	rv = import_object_boolprop(&obj, ref, CKA_TOKEN);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_PRIVATE);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_MODIFIABLE);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_COPYABLE);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_DESTROYABLE);
	if (rv)
		goto bail;

	MSG("import boolprop attribute Derive. Looks ok.");
	rv = import_object_boolprop(&obj, ref, CKA_DERIVE);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_LOCAL);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_SENSITIVE);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_ENCRYPT);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_DECRYPT);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_SIGN);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_VERIFY);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_WRAP);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_UNWRAP);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_EXTRACTABLE);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_ALWAYS_SENSITIVE);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_NEVER_EXTRACTABLE);
	if (rv)
		goto bail;
	rv = import_object_boolprop(&obj, ref, CKA_WRAP_WITH_TRUSTED);
	if (rv)
		goto bail;

	/* Imported clearkey cannot be trusted */
	rv = set_object_boolprop(&obj, CKA_TRUSTED, CK_FALSE);
	if (rv)
		goto bail;

	/* Do not forget the mandated key data */
	rv = serial_get_attribute_ptr(ref, CKA_VALUE, &attr, &size);
	if (rv == CKR_OK)
		rv = serialize_sks_ref(&obj, CKA_VALUE, attr, size);

bail:
	if (rv)
		release_serial_object(&obj);

	return rv ? NULL : obj.buffer;
}

/*
 * Create an raw DATA object
 *
 * @session - session onwing the object creation
 * @head - pointer to serialized attributes
 * @hld - object handle returned to hte client
 */
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
 * The serialized attribute is expected to contain at least well formated
 * and consistent class and type attributes. All other attributes are check
 * here.
 */
static void *set_pkcs11_data_object_attributes(void *ref)
{
	CK_RV rv;
	struct serializer obj;
	void *attr;
	size_t size;
	uint32_t class =serial_get_class(ref);

	/* TODO: move to keyhead serial object: easier boolprop handling */
	reset_serial_object_rawhead(&obj);

	/* Class and type are mandatory */
	rv = serialize_sks_ref(&obj, CKA_CLASS, &class, sizeof(class));
	if (rv)
		goto bail;

	/* Default boolean properties the client template can override */
	rv = import_object_boolprop(&obj, ref, CKA_TOKEN);
	if (rv)
		goto bail;

	// TODO: check the expect default value
	rv = import_object_boolprop(&obj, ref, CKA_PRIVATE);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_MODIFIABLE);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_COPYABLE);
	if (rv)
		goto bail;

	rv = import_object_boolprop(&obj, ref, CKA_DESTROYABLE);
	if (rv)
		goto bail;

	/* Optional attributes */
	rv = serial_get_attribute_ptr(ref, CKA_APPLICATION, &attr, &size);
	if (rv == CKR_OK) {
		rv = serialize_sks_ref(&obj, CKA_APPLICATION, attr, size);
		if (rv)
			goto bail;
	}

	rv = serial_get_attribute_ptr(ref, CKA_OBJECT_ID, &attr, &size);
	if (rv == CKR_OK) {
		rv = serialize_sks_ref(&obj, CKA_OBJECT_ID, attr, size);
		if (rv)
			goto bail;
	}

bail:
	if (rv) {
		release_serial_object(&obj);
		return NULL;
	}

	return obj.buffer;
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
	void *obj_head = NULL;

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

	// TODO; change to TEE_Free(); Needs serializer to use TEE_Realloc
	free(head);

	if (res) {
		free(obj_head);
		return res;
	}

	memcpy(out->memref.buffer, &obj_handle, sizeof(uint32_t));
	out->memref.size = sizeof(uint32_t);

	return res;
}

TEE_Result entry_destroy_object(TEE_Param __unused *ctrl,
				TEE_Param __unused *in,
				TEE_Param __unused *out)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

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
#include "ck_helpers.h"
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

struct sks_object *object_get_tee_handle(uint32_t ck_handle)
{
	int handle = (int)ck_handle;
	struct sks_object *obj = handle_lookup(&object_handle_db, handle);

	return obj;
}

/*
 * Destroy an object
 *
 * @session - session requesting object destruction
 * @hld - object handle returned to hte client
 */
CK_RV destroy_object(struct pkcs11_session *session,
			  struct sks_object *object,
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

static void cleanup_object(struct sks_object *obj)
{
	CK_BBOOL persistent;

	if (!obj)
		return;

	if (obj->key_handle != TEE_HANDLE_NULL) {
		if (!obj->attributes ||
		    serial_get_attribute(obj->attributes, CKA_TOKEN,
					 &persistent, NULL))
			TEE_Panic(0);

		if (persistent)
			TEE_CloseAndDeletePersistentObject1(obj->key_handle);
		else
			TEE_FreeTransientObject(obj->key_handle);
	}

	handle_put(&object_handle_db, obj->ck_handle);
	TEE_Free(obj->id);
	TEE_Free(obj);
}

static bool session_allows_persistent_object(void *session)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = session;

	return pkcs11_session_is_read_write(ck_session);
}

static struct object_list *get_session_objects(void *session)
{
	/* Currently supporting only pkcs11 session */
	struct pkcs11_session *ck_session = session;

	return pkcs11_get_session_objects(ck_session);
}

static CK_RV get_tee_object_info(uint32_t *type, uint32_t *attr, void *head)
{
	switch (serial_get_type(head)) {
	case CKK_AES:
		*type = TEE_TYPE_AES;
		goto secret;
	case CKK_MD5_HMAC:
		*type = TEE_TYPE_HMAC_MD5;
		goto secret;
	case CKK_SHA_1_HMAC:
		*type = TEE_TYPE_HMAC_SHA1;
		goto secret;
	case CKK_SHA256_HMAC:
		*type = TEE_TYPE_HMAC_SHA256;
		goto secret;
	case CKK_SHA384_HMAC:
		*type = TEE_TYPE_HMAC_SHA384;
		goto secret;
	case CKK_SHA224_HMAC:
		*type = TEE_TYPE_HMAC_SHA224;
		goto secret;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

secret:
	*attr = TEE_ATTR_SECRET_VALUE;
	return CKR_OK;
}

CK_RV create_object(void *session, void *head, void *data, size_t data_size,
		    uint32_t *out_handle)
{
	CK_RV rv = CKR_OK;
	TEE_Result res = TEE_SUCCESS;
	struct sks_object *obj;
	uint8_t is_persistent;
	TEE_Attribute tee_key_attr;
	int obj_handle;
	uint32_t tee_obj_type;
	uint32_t tee_obj_attr;

	/*
	 * We do not check the key attributes. At this point, key attributes
	 * are expected consistent and reliable.
	 */

	obj = TEE_Malloc(sizeof(*obj), TEE_MALLOC_FILL_ZERO);
	if (!obj)
		return CKR_DEVICE_MEMORY;

	obj_handle = handle_get(&object_handle_db, obj);
	if (obj_handle < 0 || obj_handle > 0x7FFFFFFF) {
		TEE_Free(obj);
		return CKR_FUNCTION_FAILED;
	}

	obj->key_handle = TEE_HANDLE_NULL;
	obj->id = NULL;
	obj->attributes = head;
	obj->ck_handle = (uint32_t)obj_handle;

	/* Session bound or persistent object? */
	rv = serial_get_attribute(head, CKA_TOKEN, &is_persistent, NULL);
	if (rv) {
		DMSG("No token attribute found");
		TEE_Panic(0);
	}

	if (is_persistent && !session_allows_persistent_object(session)) {
		rv = CKR_SESSION_READ_ONLY;
		goto bail;
	}

	/* Non raw data object get their data content store aside attrbiutes */
	switch (serial_get_class(head)) {
	case CKO_DATA:
		if (!is_persistent) {
			/* Volatile object now owns the data buffer */
			obj->data = data;
			obj->data_size = data_size;
		}
		break;

	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
		rv = get_tee_object_info(&tee_obj_type, &tee_obj_attr, head);
		if (rv) {
			DMSG("get_tee_object_info failed, %s", ckr2str(rv));
			goto bail;
		}

		res = TEE_AllocateTransientObject(tee_obj_type, data_size * 8,
						  &obj->key_handle);
		if (res) {
			DMSG("TEE_AllocateTransientObject failed, %" PRIx32,
				res);
			goto bail;
		}

		TEE_InitRefAttribute(&tee_key_attr, tee_obj_attr,
				     data, data_size);

		res = TEE_PopulateTransientObject(obj->key_handle,
						  &tee_key_attr, 1);
		if (res) {
			DMSG("TEE_PopulateTransientObject failed, %" PRIx32,
				res);
			goto bail;
		}
		break;

	default:
		TEE_Panic(0);
	}

	if (is_persistent) {
		TEE_ObjectHandle handle = obj->key_handle;

		/*
		 * Create a unique ID
		 * FIXME; find a better ID scheme than a random number
		 * TODO; store the TEE ID in the object attribute list
		 */
		obj->id_size = 32;
		obj->id = TEE_Malloc(obj->id_size,
				     TEE_USER_MEM_HINT_NO_FILL_ZERO);
		if (!obj->id) {
			rv = CKR_DEVICE_MEMORY;
			goto bail;
		}

		TEE_GenerateRandom(obj->id, obj->id_size);

		// TODO: add field 'id' to the attribute list of the object.

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						 obj->id, obj->id_size,
						 TEE_DATA_FLAG_ACCESS_READ |
						 TEE_DATA_FLAG_ACCESS_WRITE |
						 TEE_DATA_FLAG_ACCESS_WRITE_META |
						 TEE_DATA_FLAG_OVERWRITE, /* TODO: don't overwrite! */
						 handle,
						 data, data_size,
						 &obj->key_handle);

		if (handle != TEE_HANDLE_NULL)
			TEE_FreeTransientObject(handle);

		if (res) {
			obj->key_handle = TEE_HANDLE_NULL;
			goto bail;
		}
	}

	if (is_persistent && session_allows_persistent_object(session)) {

		//TODO: add object to the SKS persistent database

	}

	LIST_INSERT_HEAD(get_session_objects(session), obj, link);
	obj->session_owner = session;

	// TODO: debug trace
	//serial_trace_attributes_from_head("[create]", object->attributes);

bail:
	/* Free data buffer if its content has been moved to a TEE object */
	if (!obj->data) {
		MSG("free");
		TEE_Free(data);
		MSG("freed");
	}

	if (res)
		rv = tee2ckr_error(res);

	if (rv)
		cleanup_object(obj);
	else
		*out_handle = obj->ck_handle;

	return rv;
}

/*
 * Find a 'value' attribute in serializer object.
 * Remove the attribute reference from the serialized object and return
 * it in output data arguments.
 *
 * Return CKR_ATTRIBUTE_VALUE_INVALID if the attribute is not found.
 * Return CKR_OK on success and error ck code on failure.
 */
static CK_RV extract_object_data(struct serializer *attributes,
				 void **data, size_t *data_size)
{
	CK_RV rv;
	void *value;
	size_t size = 0;

	rv = serial_get_attribute(attributes->buffer, CKA_VALUE, NULL, &size);
	if (rv != CKR_BUFFER_TOO_SMALL)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	value = TEE_Malloc(size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!value)
		return CKR_DEVICE_MEMORY;

	rv = serial_get_attribute(attributes->buffer, CKA_VALUE, value, &size);
	if (rv)
		TEE_Panic(0);		// FIXME: use assert

	*data_size = size;
	data = value;

	rv = serializer_remove_attribute(attributes, CKA_VALUE);
	if (rv)
		TEE_Panic(0);		// FIXME: use assert

	*data_size = size;
	*data = value;

	return rv;
}

/*
 * Create an object from a clear content provided by client
 */
CK_RV entry_create_object(int teesess,
			  TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	CK_RV rv;
	char *ctrl_ptr;
	uint32_t ck_session;
	struct pkcs11_session *session;
	struct serializer template;
	struct serializer *attrs = NULL;
	uint32_t obj_handle;
	void *temp = NULL;
	size_t temp_size;
	void *data;
	size_t data_size;

	/* Arguments */
	if (!ctrl || in || !out || out->memref.size < sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	ctrl_ptr = ctrl->memref.buffer;
	ck_session = *(uint32_t *)(void *)ctrl_ptr;

	session = get_pkcs_session(ck_session);
	if (!session || session->tee_session != teesess)
		return CKR_SESSION_HANDLE_INVALID;

	/* Safely copy attributes and sanitize the content */
	temp_size = ctrl->memref.size - sizeof(uint32_t);
	temp = TEE_Malloc(temp_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!temp)
		return CKR_DEVICE_MEMORY;

	TEE_MemMove(temp, ctrl_ptr + sizeof(uint32_t), temp_size);

#ifdef DEBUG
	serial_trace_attributes_from_head("client-template", temp);
#endif

	rv = sanitize_attributes_from_head(&template, temp, temp_size);
	TEE_Free(temp);

	if (rv)
		goto bail;

	/* Set the attributes from pkcs11 directives and requested template */
	switch (template.class) {
	case CKO_DATA:
		rv = create_pkcs11_data_attributes(&attrs, template.buffer);
		break;
	case CKO_SECRET_KEY:
		rv = create_pkcs11_symkey_attributes(&attrs, template.buffer);
		break;
	default:
		rv = CKR_OBJECT_HANDLE_INVALID;
		break;
	}

	serializer_release_buffer(&template);
	if (rv)
		goto bail;

	/* Seperate object data from object attribute and create the object */
	rv = extract_object_data(attrs, &data, &data_size);
	if (rv)
		goto bail;

	rv = create_object(session, attrs->buffer, data, data_size, &obj_handle);
	if (rv)
		goto bail;

#ifdef DEBUG
	serial_trace_attributes_from_head("attributes", attrs->buffer);
#endif

	TEE_MemMove(out->memref.buffer, &obj_handle, sizeof(uint32_t));
	out->memref.size = sizeof(uint32_t);

	/*
	 * Memory for 'data' was allocated in extract_object_data.
	 * Now to was either freed or get owned by the generated sks object.
	 */

	/*
	 * Now obj_handle and relate struct sks_object own the attribute
	 * serialised buffer. Hence we must not free attrs->buffer but
	 * serializer resources can be freed from serializer_release().
	 */
	attrs->buffer = NULL;
bail:
	serializer_release(attrs);
	return rv;
}

CK_RV  entry_destroy_object(int teesess, TEE_Param *ctrl,
			    TEE_Param *in, TEE_Param *out)
{
	size_t ctrl_size;
	char *ctrl_ptr;
	uint32_t session_handle;
	uint32_t object_handle;
	struct pkcs11_session *session;
	struct sks_object *object;

	if (!ctrl || in || out)
		return CKR_ARGUMENTS_BAD;

	ctrl_size = ctrl->memref.size;
	ctrl_ptr = ctrl->memref.buffer;

	/* First serial arg: [32b-session-handle] */
	if (ctrl_size < sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	TEE_MemMove(&session_handle, ctrl_ptr, sizeof(uint32_t));
	ctrl_ptr += sizeof(uint32_t);
	ctrl_size -= sizeof(uint32_t);

	session = get_pkcs_session(session_handle);
	if (!session || session->tee_session != teesess)
		return CKR_SESSION_HANDLE_INVALID;

	/* Next serial arg: [32b-object-handle] */
	if (ctrl_size < sizeof(uint32_t))
		return CKR_ARGUMENTS_BAD;

	TEE_MemMove(&object_handle, ctrl_ptr, sizeof(uint32_t));
	ctrl_ptr += sizeof(uint32_t);
	ctrl_size -= sizeof(uint32_t);

	object = object_get_tee_handle(object_handle);
	if (!object || object->session_owner != session)
		return CKR_KEY_HANDLE_INVALID;

	return destroy_object(session, object, false);
}

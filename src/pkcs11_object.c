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

/*
 * Object expects several boolean attributes to be set to a default value
 * or to a validate client configuration value. This function append the input
 * attrubute (id/size/value) in the serailzed object.
 */
static CK_RV pkcs11_import_object_boolprop(struct serializer *obj, void *head,
					   CK_ATTRIBUTE_TYPE attribute)
{
	CK_RV rv;
	CK_BBOOL *attr;
	size_t attr_size;

	/* Expect boolprop not defined in head: it is added outside the head */
	if (!serial_is_rawhead(head) && !serial_is_genhead(head)) {
		EMSG("Expect boolprop not in head");
		return CKR_FUNCTION_FAILED;
	}

	rv = serial_get_attribute_ptr(head, attribute,
				      (void **)&attr, &attr_size);

	/* default value if not found or malformed */
	if (rv || attr_size != sizeof(CK_BBOOL))
		attr = pkcs11_object_default_boolprop(attribute);

	/* CK_BBOOL is 1byte, no alignment issue */
	return serialize_sks_ref(obj, attribute, attr, sizeof(CK_BBOOL));
}

CK_RV create_pkcs11_symkey_attributes(struct serializer **out, void *head)
{
	CK_RV rv;
	struct serializer *obj;
	void *attr;
	size_t size;
	CK_ULONG class = serial_get_class(head);
	CK_ULONG type = serial_get_type(head);

	obj = TEE_Malloc(sizeof(*obj), TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!obj)
		return CKR_DEVICE_MEMORY;

	/* TODO: move to keyhead serial object: easier boolprop handling */
	serializer_reset_to_rawhead(obj);

	/* Class and type are mandatory */
	rv = serialize_sks_ref(obj, CKA_CLASS, &class, sizeof(CK_ULONG));
	if (rv)
		goto bail;

	rv = serialize_sks_ref(obj, CKA_KEY_TYPE, &type, sizeof(CK_ULONG));
	if (rv)
		goto bail;

	/* Default boolean properties the client template can override */
	rv = pkcs11_import_object_boolprop(obj, head, CKA_TOKEN);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_PRIVATE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_MODIFIABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_COPYABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_DESTROYABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_DERIVE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_LOCAL);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_SENSITIVE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_ENCRYPT);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_DECRYPT);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_SIGN);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_VERIFY);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_WRAP);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_UNWRAP);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_EXTRACTABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_ALWAYS_SENSITIVE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_NEVER_EXTRACTABLE);
	if (rv)
		goto bail;
	rv = pkcs11_import_object_boolprop(obj, head, CKA_WRAP_WITH_TRUSTED);
	if (rv)
		goto bail;

	/* Imported clearkey cannot be trusted */
	rv = set_object_boolprop(obj, CKA_TRUSTED, CK_FALSE);
	if (rv)
		goto bail;

	/* Do not forget the key data if any (may be outside the attributes) */
	rv = serial_get_attribute_ptr(head, CKA_VALUE, &attr, &size);
	if (rv == CKR_OK)
		rv = serialize_sks_ref(obj, CKA_VALUE, attr, size);

	rv = serializer_finalize(obj);
	if (rv)
		goto bail;

	*out = obj;

bail:
	if (rv) {
		serializer_release_buffer(obj);
		TEE_Free(obj);
	}

	return rv;
}

CK_RV create_pkcs11_data_attributes(struct serializer **out, void *head)
{
	CK_RV rv;
	struct serializer *obj;
	void *attr;
	size_t size;
	uint32_t class = CKO_DATA;

	if (serial_get_class(head) != CKO_DATA) {
		EMSG("Expect CKO_DATA");
		return CKR_FUNCTION_FAILED;
	}

	obj = TEE_Malloc(sizeof(*obj), TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!obj)
		return CKR_DEVICE_MEMORY;

	/* TODO: move to keyhead serial object: easier boolprop handling */
	serializer_reset_to_rawhead(obj);

	/* Class and type are mandatory */
	rv = serialize_sks_ref(obj, CKA_CLASS, &class, sizeof(CK_ULONG));
	if (rv)
		goto bail;

	/* Default boolean properties the client template can override */
	rv = pkcs11_import_object_boolprop(obj, head, CKA_TOKEN);
	if (rv)
		goto bail;

	// TODO: check the expect default value
	rv = pkcs11_import_object_boolprop(obj, head, CKA_PRIVATE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_MODIFIABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_COPYABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(obj, head, CKA_DESTROYABLE);
	if (rv)
		goto bail;

	/* Optional attributes */
	rv = serial_get_attribute_ptr(head, CKA_APPLICATION, &attr, &size);
	if (rv == CKR_OK) {
		rv = serialize_sks_ref(obj, CKA_APPLICATION, attr, size);
		if (rv)
			goto bail;
	}

	rv = serial_get_attribute_ptr(head, CKA_OBJECT_ID, &attr, &size);
	if (rv == CKR_OK) {
		rv = serialize_sks_ref(obj, CKA_OBJECT_ID, attr, size);
		if (rv)
			goto bail;
	}

	rv = serializer_finalize(obj);
	if (rv)
		goto bail;

	*out = obj;

bail:
	if (rv) {
		serializer_release_buffer(obj);
		TEE_Free(obj);
	}

	return rv;
}

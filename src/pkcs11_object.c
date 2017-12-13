/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <inttypes.h>
#include <pkcs11.h>
#include <string.h>	// FIXME: use TEE_MemCopy(), not memcpy()
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

static CK_RV pkcs11_import_object_boolprop(struct serializer *obj, void *head,
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

void *set_pkcs11_imported_symkey_attributes(void *ref)
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
	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_TOKEN);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_PRIVATE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_MODIFIABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_COPYABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_DESTROYABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_DERIVE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_LOCAL);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_SENSITIVE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_ENCRYPT);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_DECRYPT);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_SIGN);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_VERIFY);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_WRAP);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_UNWRAP);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_EXTRACTABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_ALWAYS_SENSITIVE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_NEVER_EXTRACTABLE);
	if (rv)
		goto bail;
	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_WRAP_WITH_TRUSTED);
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

	rv = serial_finalize_object(&obj);
bail:
	if (rv)
		release_serial_object(&obj);

	return rv ? NULL : obj.buffer;
}

/*
 * The serialized attribute is expected to contain at least well formated
 * and consistent class and type attributes. All other attributes are check
 * here.
 */
void *set_pkcs11_data_object_attributes(void *ref)
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
	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_TOKEN);
	if (rv)
		goto bail;

	// TODO: check the expect default value
	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_PRIVATE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_MODIFIABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_COPYABLE);
	if (rv)
		goto bail;

	rv = pkcs11_import_object_boolprop(&obj, ref, CKA_DESTROYABLE);
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

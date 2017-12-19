/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_abi.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>

#include "ck_helpers.h"
#include "serializer.h"

static size_t __sizeof_serial_head(uint32_t version, uint32_t config)
{
	if (version != SKS_ABI_VERSION_CK_2_40)
		return 0;

	switch (SKS_ABI_HEAD(config)) {
	case SKS_ABI_CONFIG_RAWHEAD:
		return sizeof(struct sks_obj_rawhead);
	case SKS_ABI_CONFIG_GENHEAD:
		return sizeof(struct sks_obj_genhead);
	case SKS_ABI_CONFIG_KEYHEAD:
		return sizeof(struct sks_obj_keyhead);
	default:
		return 0;
	}
}

size_t sizeof_serial_head(void *ref)
{
	struct sks_obj_rawhead raw;

	TEE_MemMove(&raw, ref, sizeof(raw));

	return __sizeof_serial_head(raw.version, raw.configuration);
}

size_t serial_get_size(void *ref)
{
	struct sks_obj_rawhead raw;

	TEE_MemMove(&raw, ref, sizeof(raw));

	return raw.blobs_size +
		__sizeof_serial_head(raw.version, raw.configuration);
}

size_t serial_get_count(void *ref)
{
	struct sks_obj_rawhead raw;

	TEE_MemMove(&raw, ref, sizeof(raw));

	return raw.blobs_count;
}

/*
 * Utilitaries on already serialized object.
 * Serialized object reference is the start address of object head.
 */


uint32_t serial_get_class(void *ref)
{
	uint32_t class;
	uint32_t class_size = sizeof(uint32_t);
	CK_RV rv;

	rv = serial_get_attribute(ref, CKA_CLASS, &class, &class_size);
	if (rv)
		return SKS_UNDEFINED_ID;

	return class;
}

uint32_t serial_get_type(void *ref)
{
	struct sks_obj_rawhead *raw = ref;
	char *cur = (char *)ref + sizeof_serial_head(raw);
	char *end = cur + raw->blobs_size;
	size_t next;
	uint32_t type;

	for (; cur < end; cur += next) {
		/* Structure aligned copy of the sks_ref in the object */
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		if (!sks_attr_is_type(sks_ref.id))
			continue;

		if (sks_ref.size != sizeof(uint32_t))
			TEE_Panic(0);

		TEE_MemMove(&type, cur + sizeof(sks_ref), sks_ref.size);
		return type;
	}

	/* Sanity */
	if (cur != end) {
		EMSG("unexpected unalignment\n");
		TEE_Panic(0);
	}

	return SKS_UNDEFINED_ID;
}

void serial_get_attributes_ptr(void *ref, uint32_t attribute,
				void **attr, size_t *attr_size, size_t *count)
{
	struct sks_obj_rawhead *raw = ref;
	char *cur = (char *)ref + sizeof_serial_head(raw);
	char *end = cur + raw->blobs_size;
	size_t next;
	size_t max_found = *count;
	size_t found = 0;
	void **attr_ptr = attr;
	size_t *attr_size_ptr = attr_size;

	for (; cur < end; cur += next) {
		/* Structure aligned copy of the sks_ref in the object */
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		if (sks_ref.id != attribute)
			continue;

		found++;

		if (!max_found)
			continue;	/* only count matching attributes */

		if (attr)
			*attr_ptr++ = cur + sizeof(sks_ref);

		if (attr_size)
			*attr_size_ptr++ = sks_ref.size;

		if (found == max_found)
			break;
	}

	/* Sanity */
	if (cur > end) {
		DMSG("Exceeding serial object length");
		TEE_Panic(0);
	}
	if (*count)
		*count = found;
}

CK_RV serial_get_attribute_ptr(void *ref, uint32_t attribute,
				void **attr_ptr, size_t *attr_size)
{
	size_t count = 1;

	serial_get_attributes_ptr(ref, attribute, attr_ptr, attr_size, &count);

	if (count != 1)
		return CKR_GENERAL_ERROR;

	return CKR_OK;
}

CK_RV serial_get_attribute(void *ref, uint32_t attribute,
			   void *attr, size_t *attr_size)
{
	CK_RV rv;
	void *attr_ptr;
	size_t size;

	rv = serial_get_attribute_ptr(ref, attribute, &attr_ptr, &size);
	if (rv)
		return rv;

	if (attr_size && *attr_size != size) {
		*attr_size = size;
		/* This reuses buffer-to-small for any bad size matching */
		return CKR_BUFFER_TOO_SMALL;
	}

	if (attr)
		TEE_MemMove(attr, attr_ptr, size);

	if (attr_size)
		*attr_size = size;

	return CKR_OK;
}

/*
 * Removing an attribute from a serialized object
 */

static bool attribute_is_in_head(struct serializer *ref, uint32_t attribute)
{
	if (ref->version != SKS_ABI_VERSION_CK_2_40)
		TEE_Panic(0);

	switch (SKS_ABI_HEAD(ref->config)) {
	case SKS_ABI_CONFIG_RAWHEAD:
		return false;
	case SKS_ABI_CONFIG_GENHEAD:
		return (attribute == CKA_CLASS || sks_attr_is_type(attribute));
	case SKS_ABI_CONFIG_KEYHEAD:
		return (attribute == CKA_CLASS || sks_attr_is_type(attribute) ||
			sks_attr2boolprop_shift(attribute) >= 0);
	default:
		TEE_Panic(0);
	}

	return false;
}

CK_RV serial_remove_attribute(void *ref, uint32_t attribute)
{
	CK_RV rv;
	struct serializer *obj;
	char *cur = ref;
	char *end;
	size_t next;
	int found = 0;

	rv = serializer_init_from_head(&obj, ref);
	if (rv)
		return rv;

	/* Can't remove an attribute that is defined in the head */
	if (attribute_is_in_head(obj, attribute)) {
		rv = CKR_FUNCTION_FAILED;
		goto bail;
	}

	/* Let's find the target attribute */
	cur = obj->buffer + sizeof_serial_object_head(obj);
	end = obj->buffer + obj->size;
	for (; cur < end; cur += next) {
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		if (sks_ref.id != attribute)
			continue;

		if (found) {
			EMSG("Attribute found twice");
			TEE_Panic(0);
		}
		found = 1;

		TEE_MemMove(cur, cur + next, end - (cur + next));

		obj->item_count--;
		obj->size -= sks_ref.size;
		end -= next;
		next = 0;
	}

	/* sanity */
	if (cur != end) {
		EMSG("unexpected none alignement\n");
		TEE_Panic(0);
	}

	if (!found)
		rv = CKR_FUNCTION_FAILED;
	else
		rv = serializer_finalize(obj);

bail:
	TEE_Free(obj);

	return rv;
}

/* Check attribute value matches provided blob */
bool serial_attribute_value_matches(char *head, uint32_t attr,
				    void *value, size_t size)
{
	size_t count = 1;
	size_t attr_size;
	void *attr_value = TEE_Malloc(size, 0);
	void **attr_array = &attr_value;

	if (!attr_value)
		TEE_Panic(0);		/* FIXME: really panic? */

	serial_get_attributes_ptr(head, attr, attr_array, &attr_size, &count);

	return (count == 1 && attr_size == size &&
		!buf_compare_ct(value, attr_value, size));
}

/* Check attribute value matches provided blob */
bool serial_boolean_attribute_matches(char *head, uint32_t attr, bool value)
{
	CK_BBOOL *ptr;

	/*
	 * Ref is sanitized, each boolean attribute set if consistent (unique).
	 * CK_BBOOL type is a byte, hence no alignement issue.
	 */
	serial_get_attribute_ptr(head, attr, (void **)&ptr, NULL);

	return !!*ptr == value;
}

/* Check at least the attribute is defined in the serial object */
bool serial_boolean_attribute_is_set(char *head, uint32_t attr)
{
	return serial_get_attribute(head, attr, NULL, NULL) == CKR_OK;
}

/*
 * Tools based on serializer structure: used when serializing data
 */

size_t sizeof_serial_object_head(struct serializer *obj)
{
	return __sizeof_serial_head(obj->version, obj->config);
}

size_t get_serial_object_size(struct serializer *obj)
{
	return sizeof_serial_object_head(obj) + obj->size;
}

char *get_serial_object_buffer(struct serializer *obj)
{
	return obj->buffer;
}

/*
 * TODO: rename the family into
 *	serial_object_init()
 *	serial_(raw|...)head_init()
 */
void serializer_reset(struct serializer *obj)
{
	TEE_MemFill(obj, 0, sizeof(*obj));
	obj->class = SKS_UNDEFINED_ID;
	obj->type = SKS_UNDEFINED_ID;
}

CK_RV serializer_reset_to_rawhead(struct serializer *obj)
{
	struct sks_obj_rawhead head;

	serializer_reset(obj);

	obj->version = SKS_ABI_VERSION_CK_2_40;
	obj->config = SKS_ABI_CONFIG_RAWHEAD;

	head.version = obj->version;
	head.configuration = obj->config;

	/* Object starts with a head, followed by the blob, store the head now */
	return serialize_buffer(obj, &head, sizeof(head));
}

CK_RV serializer_reset_to_genhead(struct serializer *obj)
{
	struct sks_obj_genhead head;

	serializer_reset(obj);

	obj->version = SKS_ABI_VERSION_CK_2_40;
	obj->config = SKS_ABI_CONFIG_GENHEAD;

	head.version = obj->version;
	head.configuration = obj->config;
	head.class = obj->class;
	head.type = obj->type;

	/* Object starts with a head, followed by the blob, store the head now */
	return serialize_buffer(obj, &head, sizeof(head));
}

CK_RV serializer_reset_to_keyhead(struct serializer *obj)
{
	struct sks_obj_keyhead head;

	serializer_reset(obj);

	obj->version = SKS_ABI_VERSION_CK_2_40;
	obj->config = SKS_ABI_CONFIG_KEYHEAD;

	head.version = obj->version;
	head.configuration = obj->config;
	head.class = obj->class;
	head.type = obj->type;
	head.boolpropl = *((uint32_t *)obj->boolprop);
	head.boolproph = *((uint32_t *)obj->boolprop + 1);

	/* Object starts with a head, followed by the blob, store the head now */
	return serialize_buffer(obj, &head, sizeof(head));
}

CK_RV serializer_init_from_head(struct serializer **out, void *ref)
{
	struct serializer *obj;
	union {
		struct sks_obj_rawhead raw;
		struct sks_obj_genhead gen;
		struct sks_obj_keyhead key;
	} head;


	obj = TEE_Malloc(sizeof(*obj), 0);
	if (!obj)
		return CKR_DEVICE_MEMORY;

	serializer_reset(obj);

	TEE_MemMove(&head.raw, ref, sizeof(head.raw));

	obj->version = head.raw.version;
	obj->config = head.raw.configuration;
	obj->buffer = ref;

	if (obj->version != SKS_ABI_VERSION_CK_2_40)
		goto error;

	switch (SKS_ABI_HEAD(obj->config)) {
	case SKS_ABI_CONFIG_RAWHEAD:
		obj->size = sizeof(head.raw) + head.raw.blobs_size;
		obj->item_count = head.raw.blobs_count;
		break;
	case SKS_ABI_CONFIG_GENHEAD:
		TEE_MemMove(&head.gen, ref, sizeof(head.gen));
		obj->size = sizeof(head.gen) + head.gen.blobs_size;
		obj->item_count = head.gen.blobs_count;
		break;
	case SKS_ABI_CONFIG_KEYHEAD:
		TEE_MemMove(&head.key, ref, sizeof(head.key));
		obj->size = sizeof(head.key) + head.key.blobs_size;
		obj->item_count = head.key.blobs_count;
		break;
	default:
		goto error;
	}

	*out = obj;
	return CKR_OK;

error:
	TEE_Free(obj);
	return CKR_FUNCTION_FAILED;
}

CK_RV serializer_finalize(struct serializer *obj)
{
	union {
		struct sks_obj_rawhead raw;
		struct sks_obj_genhead gen;
		struct sks_obj_keyhead key;
	} head;

	switch (obj->version) {
	case SKS_ABI_VERSION_CK_2_40:
		switch (SKS_ABI_HEAD(obj->config)) {
		case SKS_ABI_CONFIG_RAWHEAD:
			head.raw.version = obj->version;
			head.raw.configuration = obj->config;
			head.raw.blobs_size = obj->size - sizeof(head.raw);
			head.raw.blobs_count = obj->item_count;
			TEE_MemMove(obj->buffer, &head.raw, sizeof(head.raw));
			break;
		case SKS_ABI_CONFIG_GENHEAD:
			head.gen.version = obj->version;
			head.gen.configuration = obj->config;
			head.gen.blobs_size = obj->size - sizeof(head.gen);
			head.gen.blobs_count = obj->item_count;
			head.gen.class = obj->class;
			head.gen.type = obj->type;
			TEE_MemMove(obj->buffer, &head.gen, sizeof(head.gen));
			break;
		case SKS_ABI_CONFIG_KEYHEAD:
			head.key.version = obj->version;
			head.key.configuration = obj->config;
			head.key.blobs_size = obj->size - sizeof(head.key);
			head.key.blobs_count = obj->item_count;
			head.key.class = obj->class;
			head.key.type = obj->type;
			head.key.boolpropl = obj->boolprop[0];
			head.key.boolproph = obj->boolprop[1];
			TEE_MemMove(obj->buffer, &head.key, sizeof(head.key));
			break;
		default:
			return CKR_FUNCTION_FAILED;
		}
		break;
	default:
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

void serializer_release(struct serializer *obj)
{
	TEE_Free(obj->buffer);
	obj->buffer = NULL;
}

/**
 * serialize - serialize input data in buffer
 *
 * Serialize data in provided buffer.
 * Insure 64byte alignement of appended data in the buffer.
 */
CK_RV serialize(char **bstart, size_t *blen, void *data, size_t len)
{
	char *buf;
	size_t nlen = *blen + len;

	buf = TEE_Realloc(*bstart, nlen);
	if (!buf)
		return CKR_DEVICE_MEMORY;

	TEE_MemMove(buf + *blen, data, len);

	*blen = nlen;
	*bstart = buf;

	return CKR_OK;
}

CK_RV serialize_32b(struct serializer *obj, uint32_t data)
{
	return serialize(&obj->buffer, &obj->size, &data, sizeof(uint32_t));
}

CK_RV serialize_buffer(struct serializer *obj, void *data, size_t size)
{
	return serialize(&obj->buffer, &obj->size, data, size);
}

CK_RV serialize_ck_ulong(struct serializer *obj, CK_ULONG data)
{
	uint32_t data32 = data;

	return serialize_buffer(obj, &data32, sizeof(data32));
}

CK_RV serialize_sks_ref(struct serializer *obj,
			CK_ATTRIBUTE_TYPE id, void *data, size_t size)
{
	CK_RV rv;
	CK_ULONG ck_size = size;

	rv = serialize_ck_ulong(obj, id);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, ck_size);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, data, size);
	if (rv)
		return rv;

	obj->item_count++;

	return rv;
}

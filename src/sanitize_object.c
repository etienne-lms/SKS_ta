/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_abi.h>
#include <stdlib.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>

#include "ck_debug.h"
#include "ck_helpers.h"
#include "sanitize_object.h"
#include "serializer.h"

/*
 * Functions to generate a serialized object.
 * References are pointers to struct serializer.
 */

static CK_RV sanitize_class_and_type(struct serializer *dst,
				     struct serializer *src)
{
	char *cur = src->buffer + sizeof_serial_object_head(src);
	char *end = src->buffer + src->size;
	struct sks_ref sks_ref;
	uint32_t class;
	uint32_t type;
	size_t next;

	dst->class = src->class;
	dst->type = src->type;

	for (; cur < end; cur += next) {
		/* Structure aligned copy of the sks_ref in the object */
		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		if (sks_attr_is_class(sks_ref.id)) {

			if (sks_ref.size != sks_attr_is_class(sks_ref.id))
				return CKR_TEMPLATE_INCONSISTENT;

			TEE_MemMove(&class, cur + sizeof(sks_ref), sks_ref.size);

			if (dst->class != SKS_UNDEFINED_ID &&
			    dst->class != class)
				return CKR_TEMPLATE_INCONSISTENT;

			/* If class not in destination head, serialize it */
			if (SKS_ABI_HEAD(dst->config) ==
			    SKS_ABI_CONFIG_RAWHEAD) {
				CK_RV rv;

				rv = serialize_buffer(dst, cur, next);
				if (rv)
					return rv;

				dst->item_count++;
			}

			dst->class = class;
		}

		/* The attribute is a type-in-class */
		if (sks_attr_is_type(sks_ref.id)) {
			if (sks_ref.size != sks_attr_is_type(sks_ref.id))
				return CKR_TEMPLATE_INCONSISTENT;

			TEE_MemMove(&type, sks_ref.data, sks_ref.size);

			if (dst->type != SKS_UNDEFINED_ID &&
			    dst->type != type)
				return CKR_TEMPLATE_INCONSISTENT;

			/* If type not in destination head, serialize it */
			if (SKS_ABI_HEAD(dst->config) ==
			    SKS_ABI_CONFIG_RAWHEAD) {
				CK_RV rv;

				rv = serialize_buffer(dst, cur, next);
				if (rv)
					return rv;

				dst->item_count++;
			}

			dst->type = type;
		}
	}

	/* Sanity */
	if (cur != end) {
		EMSG("unexpected unalignment\n");
		return CKR_FUNCTION_FAILED;
	}

	/* TODO: verify type against the class */

	return CKR_OK;
}

static CK_RV sanitize_boolprop(struct serializer *dst,
				struct sks_ref *sks_ref,
				char *cur,
				uint32_t *sanity)
{
	int shift;
	uint32_t mask;
	uint32_t value;
	uint32_t *boolprop_ptr;
	uint32_t *sanity_ptr;

	/* Get the booloean property shift position and value */
	shift = sks_attr2boolprop_shift(sks_ref->id);
	if (shift < 0)
		return CKR_NO_EVENT;

	if (shift >= SKS_MAX_BOOLPROP_SHIFT)
		return CKR_FUNCTION_FAILED;

	mask = 1 << (shift % 32);
	if ((*(CK_BBOOL *)(cur + sizeof(*sks_ref))) == CK_TRUE)
		value = mask;
	else
		value = 0;

	/* Locate the current config value for the boolean property */
	boolprop_ptr = dst->boolprop + (shift / 32);
	sanity_ptr = sanity + (shift / 32);

	/* Error if already set to a different boolean value */
	if (*sanity_ptr & mask && value != (*boolprop_ptr & mask))
		return CKR_TEMPLATE_INCONSISTENT;

	*sanity_ptr |= mask;
	if (value)
		*boolprop_ptr |= mask;
	else
		*boolprop_ptr &= ~mask;

	/* If no boolprop in destination head, serliase the attribute */
	if (dst->config != SKS_ABI_CONFIG_KEYHEAD) {
		CK_RV rv;

		rv = serialize_buffer(dst, cur,
				      sizeof(*sks_ref) + sks_ref->size);
		if (rv)
			return rv;

		dst->item_count++;
	}

	return CKR_OK;
}

static CK_RV sanitize_boolprops(struct serializer *dst,
				struct serializer *src)
{
	char *end= src->buffer + src->size;
	char *cur = src->buffer + sizeof_serial_object_head(src);
	size_t next;
	struct sks_ref sks_ref;
	uint32_t sanity[SKS_MAX_BOOLPROP_ARRAY] = { 0 };
	CK_RV rv;

	for (; cur < end; cur += next) {
		/* Structure aligned copy of the sks_ref in the object */
		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		rv = sanitize_boolprop(dst, &sks_ref, cur, sanity);
		if (rv != CKR_OK && rv != CKR_NO_EVENT)
			return rv;
	}

	return CKR_OK;
}

/* Forward ref since an attribute refernece can contain a list of attribute */
static CK_RV sanitize_attributes_from_head(struct serializer *dst, void *src);

/* Counterpart of serialize_indirect_attribute() */
static CK_RV sanitize_indirect_attr(struct serializer *dst,
				    struct serializer *src,
				    struct sks_ref *sks_ref,
				    char *cur)
{
	struct serializer obj2;
	CK_RV rv;

	/*
	 * Serialized subblobs: current applicable only the key templates which
	 * are tables of attributes.
	 */
	switch (sks_ref->id) {
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
	case CKA_DERIVE_TEMPLATE:
		break;
	default:
		return CKR_NO_EVENT;
	}
	/* Such attributes are expected only for keys (and vendor defined) */
	if (sks_attr_class_is_key(src->class))
		return CKR_TEMPLATE_INCONSISTENT;

	/* Build a new serial object while sanitizing the attributes list */
	rv = sanitize_attributes_from_head(&obj2, cur + sizeof(*sks_ref));
	if (rv)
		return rv;

	rv = serialize_32b(dst, sks_ref->id);
	if (rv)
		return rv;

	rv = serialize_32b(dst, sks_ref->size);
	if (rv)
		return rv;

	rv = serialize_buffer(dst, obj2.buffer, obj2.size);
	if (rv)
		return rv;

	dst->item_count++;

	return rv;
}

/**
 * serial_raw2gen_attributes - create a genhead serial object from a sks blob.
 *
 * @out_object - output structure tracking the generated serial object
 * @ref - pointer to the rawhead formated serialized object
 *
 * ref points to a blob starting with a sks head.
 * ref may pointer to an unaligned address.
 * This function generates another serial blob starting with a genhead
 * (class and type extracted).
 */
static CK_RV sanitize_attributes_from_head(struct serializer *dst, void *src)
{
	struct serializer *obj;
	CK_RV rv;
	char *cur;
	char *end;
	size_t next;

	rv = serializer_init_from_head(&obj, src);
	if (rv)
		return rv;

	rv = sanitize_class_and_type(dst, obj);
	if (rv)
		goto bail;

	rv = sanitize_boolprops(dst, obj);
	if (rv)
		goto bail;

	cur = obj->buffer + sizeof_serial_object_head(obj);
	end = obj->buffer + obj->size;
	for (; cur < end; cur += next) {
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		if (sks_attr_is_class(sks_ref.id) ||
		    sks_attr_is_type(sks_ref.id) ||
		    sks_attr2boolprop_shift(sks_ref.id) >= 0)
			continue;

		rv = sanitize_indirect_attr(dst, obj, &sks_ref, cur);
		if (rv == CKR_OK)
			continue;
		if (rv != CKR_NO_EVENT)
			goto bail;

		/* It is a standard attribute reference, serializa it */
		rv = serialize_buffer(dst, cur, next);
		if (rv)
			goto bail;

		dst->item_count++;
	}

	/* sanity */
	if (cur != end) {
		EMSG("unexpected none alignement\n");
		rv = CKR_FUNCTION_FAILED;
		goto bail;
	}

	rv = serializer_finalize(dst);

bail:
	TEE_Free(obj);

	return rv;
}

/* Sanitize ref into head (this duplicates the serial object in memory) */
CK_RV serial_sanitize_attributes(void **head, void *ref, size_t ref_size)
{
	struct serializer dst_obj;
	CK_RV rv;

	if (ref_size < serial_get_size(ref))
		return CKR_FUNCTION_FAILED; // FIXME: invalid arguments

	rv = serializer_reset_to_rawhead(&dst_obj);
	if (rv)
		return rv;

	rv = sanitize_attributes_from_head(&dst_obj, ref);
	if (rv)
		serializer_release(&dst_obj);
	else
		*head = dst_obj.buffer;

	return rv;
}

/*
 * Debug: dump CK attribute array to output trace
 */

static CK_RV trace_attributes(char *prefix, void *src, void *end)
{
	size_t next = 0;
	char *prefix2;
	size_t prefix_len = strlen(prefix);
	char *cur = src;

	/* append 4 spaces to the prefix plus terminal '\0' */
	prefix2 = TEE_Malloc(prefix_len + 1 + 4, TEE_MALLOC_FILL_ZERO);
	if (!prefix2)
		return CKR_DEVICE_MEMORY;

	TEE_MemMove(prefix2, prefix, prefix_len + 1);
	TEE_MemFill(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 4) = '\0';

	for (; cur < (char *)end; cur += next) {
		struct sks_ref sks_ref;

		TEE_MemMove(&sks_ref, cur, sizeof(sks_ref));
		next = sizeof(sks_ref) + sks_ref.size;

		// TODO: nice ui to trace the attribute info
		IMSG("%s attr %s (%" PRIx32 " %" PRIx32 " byte) : %02x %02x %02x %02x ...\n",
			prefix, cka2str(sks_ref.id), sks_ref.id, sks_ref.size,
			*((char *)cur + sizeof(sks_ref) + 0),
			*((char *)cur + sizeof(sks_ref) + 1),
			*((char *)cur + sizeof(sks_ref) + 2),
			*((char *)cur + sizeof(sks_ref) + 3));

		switch (sks_ref.id) {
		case CKA_WRAP_TEMPLATE:
		case CKA_UNWRAP_TEMPLATE:
		case CKA_DERIVE_TEMPLATE:
			serial_trace_attributes_from_head(prefix2,
							  cur + sizeof(sks_ref));
			break;
		default:
			break;
		}
	}

	/* sanity */
	if (cur != (char *)end) {
		EMSG("unexpected none alignement\n");
	}

	TEE_Free(prefix2);
	return CKR_OK;
}

CK_RV serial_trace_attributes_from_head(const char *prefix, void *ref)
{
	struct sks_obj_rawhead raw;
	char *pre;
	size_t offset;
	CK_RV rv;

	TEE_MemMove(&raw, ref, sizeof(raw));
	if (raw.version != SKS_ABI_VERSION_CK_2_40)
		return CKR_TEMPLATE_INCONSISTENT;

	pre = TEE_Malloc(prefix ? strlen(prefix) + 2 : 2, TEE_MALLOC_FILL_ZERO);
	if (!pre)
		return CKR_HOST_MEMORY;
	if (prefix)
		TEE_MemMove(pre, prefix, strlen(prefix));

	// TODO: nice ui to trace the attribute info
	IMSG_RAW("%s,--- (serial object) Attributes list --------\n", pre);
	IMSG_RAW("%s| version 0x%" PRIx32 "  config 0x%" PRIx32 " - %" PRIx32 " item(s) - %" PRIu32 " bytes\n",
		pre, raw.version, raw.configuration,
		raw.blobs_count, raw.blobs_size);

	if (raw.version != SKS_ABI_VERSION_CK_2_40) {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto bail;
	}

	if (SKS_ABI_HEAD(raw.configuration) == SKS_ABI_CONFIG_RAWHEAD) {
		offset = sizeof(raw);
	} else if (SKS_ABI_HEAD(raw.configuration) == SKS_ABI_CONFIG_GENHEAD) {
		struct sks_obj_genhead head;

		offset = sizeof(head);
		TEE_MemMove(&head, ref, sizeof(head));
		IMSG_RAW("%s| class (%" PRIx32 ") %s type (%" PRIx32 ") %s\n",
			 pre, head.class, ckclass2str(head.class),
			 head.type, cktype2str(head.type, head.class));
	} else if (SKS_ABI_HEAD(raw.configuration) == SKS_ABI_CONFIG_KEYHEAD) {
		struct sks_obj_keyhead head;

		offset = sizeof(head);
		TEE_MemMove(&head, ref, sizeof(head));
		IMSG_RAW("%s| class (%" PRIx32 ") %s type (%" PRIx32 ") %s"
			 " - boolpropl/h 0x%" PRIx32 "/0x%" PRIx32 "\n",
			 pre, head.class, ckclass2str(head.class),
			 head.type, cktype2str(head.type, head.class),
			 head.boolpropl, head.boolproph);
	} else {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto bail;
	}

	pre[prefix ? strlen(prefix) : 0] = '|';
	rv = trace_attributes(pre, (char *)ref + offset, (char *)ref + offset + raw.blobs_size);
	if (rv)
		goto bail;

	IMSG_RAW("%s`-----------------------\n", prefix ? prefix : "");

bail:
	TEE_Free(pre);
	return rv;
}

CK_RV serial_trace_attributes(char *prefix, struct serializer *obj)
{
	return serial_trace_attributes_from_head(prefix, obj->buffer);
}


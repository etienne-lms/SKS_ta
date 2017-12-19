/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SERIALIZER_H
#define __SERIALIZER_H

#include <pkcs11.h>
#include <stdint.h>
#include <stddef.h>
#include <sks_abi.h>
#include <tee_internal_api.h>

#define SKS_MAX_BOOLPROP_SHIFT	64
#define SKS_MAX_BOOLPROP_ARRAY	(SKS_MAX_BOOLPROP_SHIFT / sizeof(uint32_t))

/*
 * Struct used to manage the memory buffer storing the serial object.
 * The structure also contains some fields to help parsing content.
 */
struct serializer {
	char *buffer;		/* serial buffer base address */
	size_t size;		/* serial buffer current byte size */
	size_t item_count;	/* number of items in entry table */
	uint32_t version;
	uint32_t config;
	uint32_t class;
	uint32_t type;
	uint32_t boolprop[SKS_MAX_BOOLPROP_ARRAY];
};

/* Return the byte size of the sks header */
size_t sizeof_serial_object_head(struct serializer *obj);
/* Return the byte size of the sks header */
size_t get_serial_object_size(struct serializer *obj);
/* Return the location of the serial object */
char *get_serial_object_buffer(struct serializer *obj);

/* Init/finalize/release a serial object */
void reset_serial_object(struct serializer *obj);
CK_RV reset_serial_object_rawhead(struct serializer *obj);
CK_RV reset_serial_object_genhead(struct serializer *obj);
CK_RV reset_serial_object_keyhead(struct serializer *obj);
CK_RV serial_init_object(struct serializer **out, void *ref);
CK_RV serial_finalize_object(struct serializer *obj);
void release_serial_object(struct serializer *obj);

/**
 * serialize - serialize input data in buffer
 *
 * Serialize data in provided buffer.
 * Insure 64byte alignement of appended data in the buffer.
 */
CK_RV serialize(char **bstart, size_t *blen, void *data, size_t len);
/* Append data to a serial object */
CK_RV serialize_32b(struct serializer *obj, uint32_t data);
CK_RV serialize_buffer(struct serializer *obj, void *data, size_t size);
CK_RV serialize_ck_ulong(struct serializer *obj, CK_ULONG data);
CK_RV serialize_sks_ref(struct serializer *obj,
			CK_ATTRIBUTE_TYPE id, void *data, size_t size);

/* Check attribute value matches provided blob */
bool serial_attribute_value_matches(char *head, uint32_t attr,
				    void *value, size_t size);

/* Check attribute value matches provided blob */
bool serial_boolean_attribute_matches(char *head, uint32_t attr, bool value);

/* Check at least the attribute is defined in the serail object */
bool serial_boolean_attribute_is_set(char *head, uint32_t attr);

/*
 * Tools on already serialized object: input referenc is the serial object
 * head address.
 */

/* Return the size of the serial blob head or 0 on error */
size_t sizeof_serial_head(void *ref);

/* Return the number of items of the serial object (nb blobs after the head) */
size_t serial_get_count(void *ref);

/* Return the size of a serial object (head + blobs size) */
size_t serial_get_size(void *ref);

/* Return the class of the object or the invalid ID if not found */
uint32_t serial_get_class(void *ref);

/* Return the type of the object or the invalid ID if not found */
uint32_t serial_get_type(void *ref);

/*
 * serial_get_attribute_ptr - Get location of the target attribute
 *
 * @ref - object attribute reference where the attribute is searched in
 * @attribute - ID of the attribute to seach
 * @attr_ptr - output pointer to attribute data when found.
 * @attr_size - output byte size of the attribute data when found.
 *
 * Return CKR_OK if attribute is found, else return non CKR_OK.
 *
 * If attr_ptr is not null and attribute is found, attr_ptr will store the
 * attribute data location in memory.
 *
 * If attr_size is not null and attribute is found, attr_size will store the
 * byte size of the attribute data in memory.
 */
CK_RV serial_get_attribute_ptr(void *ref, uint32_t attribute,
				void **attr_ptr, size_t *attr_size);

/*
 * serial_get_attributes_ptr - Get count locations of target attribute
 *
 * @ref - object attribute reference where the attribute is searched in
 * @attribute - ID of the attribute to seach
 * @attr_ptr - output pointer to attribute data when found.
 * @attr_size - output byte size of the attribute data when found.
 * @count - input/ouptut count of attribute occurences.
 *
 * Count must be a valid pointer/reference. When *count is zero, the function
 * only counts the number of occurences of the attribute in the serial object.
 * When *count is not zero, it value defines how many occurrences we expect to
 * find.
 *
 * If attr_ptr is not null and attributes are found, each cell of attr_ptr
 * array will store the location (address) in memory of an occurence of the
 * target attribute.
 *
 * If attr_size is not null and attributes are found, each cell of attr_size
 * array will store the byte size in memory of an occurence of the target
 * attribute.
 *
 * Obviously the n'th cell referred by attr_ptr is related to the n'th cell
 * referred by attr_size.
 */
void serial_get_attributes_ptr(void *ref, uint32_t attribute,
				void **attr_ptr, size_t *attr_size, size_t *count);

/*
 * serial_get_attribute - Get target attribute data content
 *
 * @ref - object attribute reference where the attribute is searched in
 * @attribute - ID of the attribute to seach
 * @attr - NULL or output buffer where attribute data get copied to
 * @attr_size - NULL or pointer to the byte size of the attribute data
 *
 * Return a value different from CKR_OK if attribute is not found and cannot
 * be loaded in to attr and attr_size references.
 *
 * If attr is not null and attribute is found, attribute data get copied into
 * attr reference.
 *
 * If attr_size is not null and attribute is found, attr_size stores the byte
 * size in memory of the attribute data. Size must exacltly matches unless a
 *
 * FIXME: Unclear how to use this to check occurence (attr=attr_size=NULL) or
 * check occurrence and get attribute info (data and/or byte size).
 */
CK_RV serial_get_attribute(void *ref, uint32_t attribute,
			   void *attr, size_t *attr_size);

/*
 * serial_remove_attribute - Remove an attribute from a serialized object
 *
 * @ref - object attribute reference where the attribute shall be removed
 * @attribute - ID of the attribute to remove
 *
 * Return CKR_OK on success, CKR_FUNCTION_FAILED on error.
 */
CK_RV serial_remove_attribute(void *ref, uint32_t attribute);


#endif /*__SERIALIZER_H*/


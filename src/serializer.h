/*
 * Copyright (c) 2014-2017, Linaro Limited
 * All rights reserved.
 *
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
CK_RV init_serial_object_from_head(struct serializer *obj, void *ref);
CK_RV finalize_serial_object_to_head(struct serializer *obj);
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
CK_RV serialize_size_and_buffer(struct serializer *obj, void *data,
				size_t size);

/*
 * Tools on already serialized object: input referenc is the serial object
 * head address.
 */

/* Return the size of the serial blob head or 0 on error */
size_t sizeof_serial_head(void *ref);

/* Return the size of a serial object (head + blobs size) */
size_t serial_get_size(void *ref);

/* Return the class of the object or the invalid ID if not found */
uint32_t serial_get_class(void *ref);

/* Return the type of the object or the invalid ID if not found */
uint32_t serial_get_type(void *ref);

/* Get the location of target the attribute data and size */
CK_RV serial_get_attribute_ptr(void *ref, uint32_t attribute,
				void **attr, size_t *attr_size);

/* Get target the attribute data content */
CK_RV serial_get_attribute(void *ref, uint32_t attribute,
				 void *attr, size_t *attr_size);

#endif /*__SERIALIZER_H*/


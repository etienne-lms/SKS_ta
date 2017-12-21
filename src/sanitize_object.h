/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SERIAL_SANITIZE_H
#define __SERIAL_SANITIZE_H

#include <pkcs11.h>
#include "serializer.h"

/**
 * sanitize_attributes_from_head - Setup a serializer from a serialized object
 *
 * @out - output structure tracking the generated serial object
 * @ref - pointer to the formated serialized object (its head)
 * @size - byte size of the serialized binary blob
 *
 * ref points to a blob starting with a sks head.
 * ref may pointer to an unaligned address.
 * This function allocates, fill and returns a serialized attribute list
 * into a serializer container.
 */
CK_RV sanitize_attributes_from_head(struct serializer *dst,
				    void *head, size_t size);

/* TODO */
CK_RV serial_sanitize_mechanism(struct serializer *obj);

/* Debug: dump attribute content as debug traces */
CK_RV serial_trace_attributes(char *prefix, struct serializer *obj);
CK_RV serial_trace_attributes_from_head(const char *prefix, void *ref);

#endif /*__SERIAL_SANITIZE_H*/


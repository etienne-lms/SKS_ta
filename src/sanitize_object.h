/*
 * Copyright (c) 2014-2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SERIAL_SANITIZE_H
#define __SERIAL_SANITIZE_H

#include <pkcs11.h>
#include "serializer.h"

/* Generate a sanitzed vopy of a serialized CK attribute object */
CK_RV serial_sanitize_attributes(void **head, void *ref, size_t ref_size);

/* TODO */
CK_RV serial_sanitize_mechanism(struct serializer *obj);

/* Debug: dump attribute content as debug traces */
CK_RV serial_trace_attributes(char *prefix, struct serializer *obj);
CK_RV serial_trace_attributes_from_head(char *prefix, void *ref);

#endif /*__SERIAL_SANITIZE_H*/


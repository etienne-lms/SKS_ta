/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_TA_PKCS11_OBJECT_H
#define __SKS_TA_PKCS11_OBJECT_H

#include "serializer.h"

/*
 * create_pkcs11_data_attributes - setup the attribute list of a symkey object
 *
 * @out - output allocated/loaded serializer contained attribute list
 * @head - head of template provided by client
 *
 * Create a serialized object defining the attributes of the symmetric key
 * object. The object is returned contained in a struct serializer.
 *
 * Attributes list and their respective value are defined in this function
 * from pkcs11 specifications and/or client requested template.
 */
CK_RV create_pkcs11_symkey_attributes(struct serializer **out, void *head);

/*
 * create_pkcs11_data_attributes - setup the attribute list of a data object
 *
 * @out - output allocated/loaded serializer contained attribute list
 * @head - head of template provided by client
 *
 * Create a serialized object defining the attributes of a CKO_DATA object.
 * The object is returned contained in a struct serializer.
 *
 * Attributes list and their respective value are defined in this function
 * from pkcs11 specifications and/or client requested template.
 */
CK_RV create_pkcs11_data_attributes(struct serializer **out, void *head);

#endif /*__SKS_TA_PKCS11_OBJECT_H*/

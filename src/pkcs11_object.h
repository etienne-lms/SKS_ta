/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_TA_PKCS11_OBJECT_H
#define __SKS_TA_PKCS11_OBJECT_H

/*
 * Allocate a serial attribute object and fill its attributes
 * from PKCS#11 specification and provided input attribute template.
 */
CK_RV set_pkcs11_imported_symkey_attributes(void **out, void *in);
CK_RV set_pkcs11_data_object_attributes(void **out, void *in);

#endif /*__SKS_TA_PKCS11_OBJECT_H*/

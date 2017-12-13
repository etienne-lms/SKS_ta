/*
 * Copyright (c) 2017, Linaro Limited
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_TA_PROCESSING_H
#define __SKS_TA_PROCESSING_H

#include <tee_internal_api.h>

TEE_Result entry_cipher_init(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out, int enc);
TEE_Result entry_cipher_update(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out, int enc);
TEE_Result entry_cipher_final(int teesess, TEE_Param *ctrl,
				TEE_Param *in, TEE_Param *out, int enc);

#endif /*__SKS_TA_PROCESSING_H*/

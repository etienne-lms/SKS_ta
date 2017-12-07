/*
 * ck2tee_id.c
 *
 * Copyright (C) STMicroelectronics SA 2017
 * Author: etienne carriere <etienne.carriere@st.com> for STMicroelectronics.
 */

#include <pkcs11.h>
#include <sks_abi.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ck2tee_id.h"

TEE_Result ckr2tee(CK_RV rv)
{
	switch (rv) {
	case CKR_OK:
		return TEE_SUCCESS;
	case CKR_DEVICE_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;
	case CKR_BUFFER_TOO_SMALL:
		return TEE_ERROR_SHORT_BUFFER;
	default:
		return TEE_ERROR_GENERIC;
	}
}

const char *cka2str(CK_ATTRIBUTE_TYPE id)
{
	static char ckastr_undefined[] = "<vendor-reserved-undef>";
	static char ckastr_invalid[] = "<unknown-id>";
	static char ckastr_class[] = "CKA_CLASS";
	static char ckastr_token[] = "CKA_TOKEN";
	static char ckastr_private[] = "CKA_PRIVATE";
	static char ckastr_label[] = "CKA_LABEL";
	static char ckastr_application[] = "CKA_APPLICATION";
	static char ckastr_value[] = "CKA_VALUE";
	static char ckastr_object_id[] = "CKA_OBJECT_ID";
	static char ckastr_certif_type[] = "CKA_CERTIFICATE_TYPE";
	static char ckastr_issuer[] = "CKA_ISSUER";
	static char ckastr_serial_num[] = "CKA_SERIAL_NUMBER";
	static char ckastr_ac_issuer[] = "CKA_AC_ISSUER";
	static char ckastr_owner[] = "CKA_OWNER";
	static char ckastr_attr_types[] = "CKA_ATTR_TYPES";
	static char ckastr_trusted[] = "CKA_TRUSTED";
	static char ckastr_certif_category[] = "CKA_CERTIFICATE_CATEGORY";
	static char ckastr_java_midp_secu_dom[] = "CKA_JAVA_MIDP_SECURITY_DOMAIN";
	static char ckastr_url[] = "CKA_URL";
	static char ckastr_hash_pubkey_subject[] = "CKA_HASH_OF_SUBJECT_PUBLIC_KEY";
	static char ckastr_hash_pubkey_issuer[] = "CKA_HASH_OF_ISSUER_PUBLIC_KEY";
	static char ckastr_hash_algo[] = "CKA_NAME_HASH_ALGORITHM";
	static char ckastr_check_value[] = "CKA_CHECK_VALUE";
	static char ckastr_key_type[] = "CKA_KEY_TYPE";
	static char ckastr_subject[] = "CKA_SUBJECT";
	static char ckastr_identifier[] = "CKA_ID";
	static char ckastr_sensitive[] = "CKA_SENSITIVE";
	static char ckastr_encrypt[] = "CKA_ENCRYPT";
	static char ckastr_decrypt[] = "CKA_DECRYPT";
	static char ckastr_wrap[] = "CKA_WRAP";
	static char ckastr_unwrap[] = "CKA_UNWRAP";
	static char ckastr_sign[] = "CKA_SIGN";
	static char ckastr_sign_recover[] = "CKA_SIGN_RECOVER";
	static char ckastr_verify[] = "CKA_VERIFY";
	static char ckastr_verify_recover[] = "CKA_VERIFY_RECOVER";
	static char ckastr_derive[] = "CKA_DERIVE";
	static char ckastr_start_date[] = "CKA_START_DATE";
	static char ckastr_end_date[] = "CKA_END_DATE";
	static char ckastr_modulus[] = "CKA_MODULUS";
	static char ckastr_modulus_bits[] = "CKA_MODULUS_BITS";
	static char ckastr_pub_exponent[] = "CKA_PUBLIC_EXPONENT";
	static char ckastr_priv_exponent[] = "CKA_PRIVATE_EXPONENT";
	static char ckastr_prime_one[] = "CKA_PRIME_1";
	static char ckastr_prime_two[] = "CKA_PRIME_2";
	static char ckastr_exponent_one[] = "CKA_EXPONENT_1";
	static char ckastr_exponent_two[] = "CKA_EXPONENT_2";
	static char ckastr_coefficient[] = "CKA_COEFFICIENT";
	static char ckastr_pubkey_info[] = "CKA_PUBLIC_KEY_INFO";
	static char ckastr_prime[] = "CKA_PRIME";
	static char ckastr_subprime[] = "CKA_SUBPRIME";
	static char ckastr_base[] = "CKA_BASE";
	static char ckastr_prime_bits[] = "CKA_PRIME_BITS";
	static char ckastr_subprime_bits[] = "CKA_SUBPRIME_BITS";
	static char ckastr_value_bits[] = "CKA_VALUE_BITS";
	static char ckastr_value_length[] = "CKA_VALUE_LEN";
	static char ckastr_extractable[] = "CKA_EXTRACTABLE";
	static char ckastr_local[] = "CKA_LOCAL";
	static char ckastr_never_extractable[] = "CKA_NEVER_EXTRACTABLE";
	static char ckastr_always_sensitive[] = "CKA_ALWAYS_SENSITIVE";
	static char ckastr_key_gen_mecha[] = "CKA_KEY_GEN_MECHANISM";
	static char ckastr_modifiable[] = "CKA_MODIFIABLE";
	static char ckastr_copyable[] = "CKA_COPYABLE";
	static char ckastr_destroyable[] = "CKA_DESTROYABLE";
	static char ckastr_ec_params[] = "CKA_EC_PARAMS";
	static char ckastr_ec_point[] = "CKA_EC_POINT";
	static char ckastr_secondary_auth[] = "deprecated-CKA_SECONDARY_AUTH";
	static char ckastr_auth_pin_flags[] = "deprecated-CKA_AUTH_PIN_FLAGS";
	static char ckastr_always_auth[] = "CKA_ALWAYS_AUTHENTICATE";
	static char ckastr_wrap_with_trusted[] = "CKA_WRAP_WITH_TRUSTED";
	static char ckastr_wrap_templ[] = "CKA_WRAP_TEMPLATE";
	static char ckastr_unwrap_templ[] = "CKA_UNWRAP_TEMPLATE";
	static char ckastr_derive_templ[] = "CKA_DERIVE_TEMPLATE";
	static char ckastr_otp_format[] = "CKA_OTP_FORMAT";
	static char ckastr_otp_length[] = "CKA_OTP_LENGTH";
	static char ckastr_otp_time_int[] = "CKA_OTP_TIME_INTERVAL";
	static char ckastr_otp_user_friend_mode[] = "CKA_OTP_USER_FRIENDLY_MODE";
	static char ckastr_otp_challenge_req[] = "CKA_OTP_CHALLENGE_REQUIREMENT";
	static char ckastr_otp_time_req[] = "CKA_OTP_TIME_REQUIREMENT";
	static char ckastr_otp_count_req[] = "CKA_OTP_COUNTER_REQUIREMENT";
	static char ckastr_otp_pin_req[] = "CKA_OTP_PIN_REQUIREMENT";
	static char ckastr_otp_counter[] = "CKA_OTP_COUNTER";
	static char ckastr_otp_time[] = "CKA_OTP_TIME";
	static char ckastr_otp_user_id[] = "CKA_OTP_USER_IDENTIFIER";
	static char ckastr_otp_service_id[] = "CKA_OTP_SERVICE_IDENTIFIER";
	static char ckastr_otp_service_logo[] = "CKA_OTP_SERVICE_LOGO";
	static char ckastr_otp_service_logo_type[] = "CKA_OTP_SERVICE_LOGO_TYPE";
	static char ckastr_gostr3410_params[] = "CKA_GOSTR3410_PARAMS";
	static char ckastr_gostr3411_params[] = "CKA_GOSTR3411_PARAMS";
	static char ckastr_gost28147_params[] = "CKA_GOST28147_PARAMS";
	static char ckastr_hw_feature_type[] = "CKA_HW_FEATURE_TYPE";
	static char ckastr_reset_on_init[] = "CKA_RESET_ON_INIT";
	static char ckastr_has_reset[] = "CKA_HAS_RESET";
	static char ckastr_pixel_x[] = "CKA_PIXEL_X";
	static char ckastr_pixel_y[] = "CKA_PIXEL_Y";
	static char ckastr_resolution[] = "CKA_RESOLUTION";
	static char ckastr_char_rows[] = "CKA_CHAR_ROWS";
	static char ckastr_char_columns[] = "CKA_CHAR_COLUMNS";
	static char ckastr_color[] = "CKA_COLOR";
	static char ckastr_bits_per_pixel[] = "CKA_BITS_PER_PIXEL";
	static char ckastr_char_sets[] = "CKA_CHAR_SETS";
	static char ckastr_encoding_methods[] = "CKA_ENCODING_METHODS";
	static char ckastr_mime_types[] = "CKA_MIME_TYPES";
	static char ckastr_mecha_type[] = "CKA_MECHANISM_TYPE";
	static char ckastr_required_cms_attrs[] = "CKA_REQUIRED_CMS_ATTRIBUTES";
	static char ckastr_default_cms_attrs[] = "CKA_DEFAULT_CMS_ATTRIBUTES";
	static char ckastr_supported_cms_attrs[] = "CKA_SUPPORTED_CMS_ATTRIBUTES";
	static char ckastr_allowed_mecha[] = "KA_ALLOWED_MECHANISMS";
	static char ckastr_vendor_base[] = "CKA_VENDOR_DEFINED";
	static char ckastr_vendor_range[] = "<unknown-vendor-specific>";

	switch (id) {
	case CKA_CLASS:
		return ckastr_class;
	case CKA_TOKEN:
		return ckastr_token;
	case CKA_PRIVATE:
		return ckastr_private;
	case CKA_LABEL:
		return ckastr_label;
	case CKA_APPLICATION:
		return ckastr_application;
	case CKA_VALUE:
		return ckastr_value;
	case CKA_OBJECT_ID:
		return ckastr_object_id;
	case CKA_CERTIFICATE_TYPE:
		return ckastr_certif_type;
	case CKA_ISSUER:
		return ckastr_issuer;
	case CKA_SERIAL_NUMBER:
		return ckastr_serial_num;
	case CKA_AC_ISSUER:
		return ckastr_ac_issuer;
	case CKA_OWNER:
		return ckastr_owner;
	case CKA_ATTR_TYPES:
		return ckastr_attr_types;
	case CKA_TRUSTED:
		return ckastr_trusted;
	case CKA_CERTIFICATE_CATEGORY:
		return ckastr_certif_category;
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
		return ckastr_java_midp_secu_dom;
	case CKA_URL:
		return ckastr_url;
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		return ckastr_hash_pubkey_subject;
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		return ckastr_hash_pubkey_issuer;
	case CKA_NAME_HASH_ALGORITHM:
		return ckastr_hash_algo;
	case CKA_CHECK_VALUE:
		return ckastr_check_value;
	case CKA_KEY_TYPE:
		return ckastr_key_type;
	case CKA_SUBJECT:
		return ckastr_subject;
	case CKA_ID:
		return ckastr_identifier;
	case CKA_SENSITIVE:
		return ckastr_sensitive;
	case CKA_ENCRYPT:
		return ckastr_encrypt;
	case CKA_DECRYPT:
		return ckastr_decrypt;
	case CKA_WRAP:
		return ckastr_wrap;
	case CKA_UNWRAP:
		return ckastr_unwrap;
	case CKA_SIGN:
		return ckastr_sign;
	case CKA_SIGN_RECOVER:
		return ckastr_sign_recover;
	case CKA_VERIFY:
		return ckastr_verify;
	case CKA_VERIFY_RECOVER:
		return ckastr_verify_recover;
	case CKA_DERIVE:
		return ckastr_derive;
	case CKA_START_DATE:
		return ckastr_start_date;
	case CKA_END_DATE:
		return ckastr_end_date;
	case CKA_MODULUS:
		return ckastr_modulus;
	case CKA_MODULUS_BITS:
		return ckastr_modulus_bits;
	case CKA_PUBLIC_EXPONENT:
		return ckastr_pub_exponent;
	case CKA_PRIVATE_EXPONENT:
		return ckastr_priv_exponent;
	case CKA_PRIME_1:
		return ckastr_prime_one;
	case CKA_PRIME_2:
		return ckastr_prime_two;
	case CKA_EXPONENT_1:
		return ckastr_exponent_one;
	case CKA_EXPONENT_2:
		return ckastr_exponent_two;
	case CKA_COEFFICIENT:
		return ckastr_coefficient;
	case CKA_PUBLIC_KEY_INFO:
		return ckastr_pubkey_info;
	case CKA_PRIME:
		return ckastr_prime;
	case CKA_SUBPRIME:
		return ckastr_subprime;
	case CKA_BASE:
		return ckastr_base;
	case CKA_PRIME_BITS:
		return ckastr_prime_bits;
	case CKA_SUBPRIME_BITS:
		return ckastr_subprime_bits;
	case CKA_VALUE_BITS:
		return ckastr_value_bits;
	case CKA_VALUE_LEN:
		return ckastr_value_length;
	case CKA_EXTRACTABLE:
		return ckastr_extractable;
	case CKA_LOCAL:
		return ckastr_local;
	case CKA_NEVER_EXTRACTABLE:
		return ckastr_never_extractable;
	case CKA_ALWAYS_SENSITIVE:
		return ckastr_always_sensitive;
	case CKA_KEY_GEN_MECHANISM:
		return ckastr_key_gen_mecha;
	case CKA_MODIFIABLE:
		return ckastr_modifiable;
	case CKA_COPYABLE:
		return ckastr_copyable;
	case CKA_DESTROYABLE:
		return ckastr_destroyable;
	case CKA_EC_PARAMS:
		return ckastr_ec_params;
	case CKA_EC_POINT:
		return ckastr_ec_point;
	case CKA_SECONDARY_AUTH:
		return ckastr_secondary_auth;
	case CKA_AUTH_PIN_FLAGS:
		return ckastr_auth_pin_flags;
	case CKA_ALWAYS_AUTHENTICATE:
		return ckastr_always_auth;
	case CKA_WRAP_WITH_TRUSTED:
		return ckastr_wrap_with_trusted;
	case CKA_WRAP_TEMPLATE:
		return ckastr_wrap_templ;
	case CKA_UNWRAP_TEMPLATE:
		return ckastr_unwrap_templ;
	case CKA_DERIVE_TEMPLATE:
		return ckastr_derive_templ;
	case CKA_OTP_FORMAT:
		return ckastr_otp_format;
	case CKA_OTP_LENGTH:
		return ckastr_otp_length;
	case CKA_OTP_TIME_INTERVAL:
		return ckastr_otp_time_int;
	case CKA_OTP_USER_FRIENDLY_MODE:
		return ckastr_otp_user_friend_mode;
	case CKA_OTP_CHALLENGE_REQUIREMENT:
		return ckastr_otp_challenge_req;
	case CKA_OTP_TIME_REQUIREMENT:
		return ckastr_otp_time_req;
	case CKA_OTP_COUNTER_REQUIREMENT:
		return ckastr_otp_count_req;
	case CKA_OTP_PIN_REQUIREMENT:
		return ckastr_otp_pin_req;
	case CKA_OTP_COUNTER:
		return ckastr_otp_counter;
	case CKA_OTP_TIME:
		return ckastr_otp_time;
	case CKA_OTP_USER_IDENTIFIER:
		return ckastr_otp_user_id;
	case CKA_OTP_SERVICE_IDENTIFIER:
		return ckastr_otp_service_id;
	case CKA_OTP_SERVICE_LOGO:
		return ckastr_otp_service_logo;
	case CKA_OTP_SERVICE_LOGO_TYPE:
		return ckastr_otp_service_logo_type;
	case CKA_GOSTR3410_PARAMS:
		return ckastr_gostr3410_params;
	case CKA_GOSTR3411_PARAMS:
		return ckastr_gostr3411_params;
	case CKA_GOST28147_PARAMS:
		return ckastr_gost28147_params;
	case CKA_HW_FEATURE_TYPE:
		return ckastr_hw_feature_type;
	case CKA_RESET_ON_INIT:
		return ckastr_reset_on_init;
	case CKA_HAS_RESET:
		return ckastr_has_reset;
	case CKA_PIXEL_X:
		return ckastr_pixel_x;
	case CKA_PIXEL_Y:
		return ckastr_pixel_y;
	case CKA_RESOLUTION:
		return ckastr_resolution;
	case CKA_CHAR_ROWS:
		return ckastr_char_rows;
	case CKA_CHAR_COLUMNS:
		return ckastr_char_columns;
	case CKA_COLOR:
		return ckastr_color;
	case CKA_BITS_PER_PIXEL:
		return ckastr_bits_per_pixel;
	case CKA_CHAR_SETS:
		return ckastr_char_sets;
	case CKA_ENCODING_METHODS:
		return ckastr_encoding_methods;
	case CKA_MIME_TYPES:
		return ckastr_mime_types;
	case CKA_MECHANISM_TYPE:
		return ckastr_mecha_type;
	case CKA_REQUIRED_CMS_ATTRIBUTES:
		return ckastr_required_cms_attrs;
	case CKA_DEFAULT_CMS_ATTRIBUTES:
		return ckastr_default_cms_attrs;
	case CKA_SUPPORTED_CMS_ATTRIBUTES:
		return ckastr_supported_cms_attrs;
	case CKA_ALLOWED_MECHANISMS:
		return ckastr_allowed_mecha;
	case CKA_VENDOR_DEFINED:
		return ckastr_vendor_base;
	/* OP-TEE SKS ID representing a not-yet defined value */
	case CK_VENDOR_UNDEFINED_ID:
		return ckastr_undefined;

	default:
		break;
	}

	if (id > CKA_VENDOR_DEFINED)
		return ckastr_vendor_range;

	return ckastr_invalid;
}


#ifndef _GSC_CRYPTOPP_HPP_
#define _GSC_CRYPTOPP_HPP_

#ifdef __cplusplus
extern "C" {
#endif

/* default stuff */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* gsc functions */
#include "gsc.hpp"

/* link unlink */
#include <unistd.h>

void gsc_cryptopp_base64_encode();
void gsc_cryptopp_base64_decode();
void gsc_cryptopp_md5();
void gsc_cryptopp_sha1();
void gsc_cryptopp_sha224();
void gsc_cryptopp_sha256();
void gsc_cryptopp_sha384();
void gsc_cryptopp_sha512();
void gsc_cryptopp_ripemd128();
void gsc_cryptopp_ripemd160();
void gsc_cryptopp_ripemd256();
void gsc_cryptopp_ripemd320();
void gsc_cryptopp_whirlpool();

#ifdef __cplusplus
}
#endif

#endif

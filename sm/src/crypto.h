//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <sbi/sbi_types.h>
#include "sha3/sha3.h"
#include "hkdf_sha3_512/hkdf_sha3_512.h"
#include "falcon512_sm/falcon.h"

typedef sha3_ctx_t hash_ctx;
#define MDSIZE  64

#define SIGNATURE_SIZE  64
#define PRIVATE_KEY_SIZE  64 // includes public key
#define PUBLIC_KEY_SIZE 32

/******************************/
/* 
_FALCON 512_
PUBLIC KEY SIZE: 897 
PRIVATE KEY SIZE: 1281 
TMP BUFFER SIZE: 15879
SIG_CT SIZE: 809
*/
#define FALCON_512_PK_SIZE 897
#define FALCON_512_SK_SIZE 1281
#define FALCON_512_SIG_SIZE 809

/*
_FALCON 1024_
PUBLIC KEY SIZE: 1793 
PRIVATE KEY SIZE: 2305 
TMP BUFFER SIZE: 31751
SIG_CT SIZE: 1577
*/

#define FALCON_1024_PK_SIZE 1793
#define FALCON_1024_SK_SIZE 2305
#define FALCON_1024_SIG_SIZE 1577

#if LOGN_PARAM == 9

#define FALCON_PK_SIZE FALCON_512_PK_SIZE
#define FALCON_SK_SIZE FALCON_512_SK_SIZE
#define FALCON_SIG_SIZE FALCON_512_SIG_SIZE

#else

#define FALCON_PK_SIZE FALCON_1024_PK_SIZE
#define FALCON_SK_SIZE FALCON_1024_SK_SIZE
#define FALCON_SIG_SIZE FALCON_1024_SIG_SIZE

#endif
/********************************/

typedef unsigned char byte;

extern byte sm_hash[MDSIZE];
extern byte sm_signature[FALCON_512_SIG_SIZE];
extern byte sm_public_key[FALCON_512_PK_SIZE];
extern byte sm_private_key[FALCON_512_SK_SIZE];

void hash_init(hash_ctx* hash_ctx);
void hash_extend(hash_ctx* hash_ctx, const void* ptr, size_t len);
void hash_extend_page(hash_ctx* hash_ctx, const void* ptr);
void hash_finalize(void* md, hash_ctx* hash_ctx);

void sign(void* sign, const void* data, size_t len, const byte* private_key, unsigned char* tmp, shake256_context *rng); //const byte* public_key,
int kdf(const unsigned char* salt, size_t salt_len,
        const unsigned char* ikm, size_t ikm_len,
        const unsigned char* info, size_t info_len,
        unsigned char* okm, size_t okm_len);
#endif /* crypto.h */

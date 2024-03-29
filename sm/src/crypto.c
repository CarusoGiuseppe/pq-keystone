//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "crypto.h"
#include "page.h"

void hash_init(hash_ctx* hash_ctx)
{
  sha3_init(hash_ctx, MDSIZE);
}

void hash_extend(hash_ctx* hash_ctx, const void* ptr, size_t len)
{
  sha3_update(hash_ctx, ptr, len);
}

void hash_extend_page(hash_ctx* hash_ctx, const void* ptr)
{
  sha3_update(hash_ctx, ptr, RISCV_PGSIZE);
}

void hash_finalize(void* md, hash_ctx* hash_ctx)
{
  sha3_final(md, hash_ctx);
}

void sign(void* sign, const void* data, size_t len,const unsigned char* private_key, unsigned char* tmp, shake256_context *rng)
{ 
  size_t sig_len;
  falcon_sign_dyn(rng, sign, &sig_len, FALCON_SIG_CT, private_key, FALCON_PRIVKEY_SIZE(LOGN_PARAM), data, len, tmp, FALCON_TMPSIZE_SIGNDYN(LOGN_PARAM));
}

int kdf(const unsigned char* salt, size_t salt_len,
        const unsigned char* ikm, size_t ikm_len,
        const unsigned char* info, size_t info_len,
        unsigned char* okm, size_t okm_len)
{
  return hkdf_sha3_512(salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len);
}

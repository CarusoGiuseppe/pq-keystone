#ifndef AES256CTR_H
#define AES256CTR_H

#include <stddef.h>
#include <stdint.h>

#define AES256CTR_BLOCKBYTES 64

#define AES256CTR_NAMESPACE(s) pqcrystals_dilithium_aes256ctr_ref_##s

typedef struct {
  uint64_t *sk_exp;
  uint32_t *ivw;
} aes256ctr_ctx;

#define aes256ctr_prf AES256CTR_NAMESPACE(prf)
void aes256ctr_prf(uint8_t *out,
                   size_t outlen,
                   const uint8_t *key,
                   const uint8_t *nonce);

#define aes256ctr_init AES256CTR_NAMESPACE(init)
void aes256ctr_init(aes256ctr_ctx *state,
                    const uint8_t *key,
                    const uint8_t *nonce);

#define aes256ctr_squeezeblocks AES256CTR_NAMESPACE(squeezeblocks)
void aes256ctr_squeezeblocks(uint8_t *out,
                             size_t nblocks,
                             aes256ctr_ctx *state);

#endif

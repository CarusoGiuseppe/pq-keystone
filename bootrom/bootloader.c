#include <stddef.h>

#define ED25519_NO_SEED 1
#include "sha3/sha3.h"
/* adopted from
  provides:
  - int sha3_init(sha3_context * md);
  - int sha3_update(sha3_context * md, const unsigned char *in, size_t inlen);
  - int sha3_final(sha3_context * md, unsigned char *out);
  types: sha3_context
*/

#include "ed25519/ed25519.h"
/* Adopted from https://github.com/orlp/ed25519
  provides:
  - void ed25519_create_keypair(t_pubkey *public_key, t_privkey *private_key, t_seed *seed);
  - void ed25519_sign(t_signature *signature,
                      const unsigned uint8_t *message,
                      size_t message_len,
                      t_pubkey *public_key,
                      t_privkey *private_key);
*/

#include "x509custom/x509custom.h"

#include "falcon512/falcon.h"

#ifndef __STRING_H__
#include "string.h"
#endif

static const unsigned char sanctum_uds[] = {
  0x40, 0xa0, 0x99, 0x47, 0x8c, 0xce, 0xfa, 0x3a, 0x06, 0x63, 0xab, 0xc9,
  0x5e, 0x7a, 0x1e, 0xc9, 0x54, 0xb4, 0xf5, 0xf6, 0x45, 0xba, 0xd8, 0x04,
  0xdb, 0x13, 0xe7, 0xd7, 0x82, 0x6c, 0x70, 0x73};

typedef unsigned char byte;

extern byte sanctum_sm_hash[64];
extern byte sanctum_sm_public_key[897];
extern byte sanctum_sm_secret_key[1281];
extern byte sanctum_sm_signature[809];
extern byte sanctum_ECASM_priv[1281];

/**
 * DEVICE IDENTIFIER COMPOSITION ENGINE PARAMETERS TO SM
*/
extern byte sanctum_CDI[64];
extern byte sanctum_cert_sm[2065];
extern byte sanctum_cert_root[1883];
extern byte sanctum_cert_man[1903];
extern int sanctum_length_cert;
extern int sanctum_length_cert_root;
extern int sanctum_length_cert_man;

#define DRAM_BASE 0x80000000


//2^logn is the degree of the falcon algorithm (e.g. 10 is falcon1024)
static int logn_test = 9;
unsigned int sanctum_sm_size = 0x1fd000;
/* 
_FALCON 512_
PUBLIC KEY SIZE: 897 
PRIVATE KEY SIZE: 1281 
TMP BUFFER SIZE: 15879
SIG_CT SIZE: 809
_FALCON 1024_
PUBLIC KEY SIZE: 1793 
PRIVATE KEY SIZE: 2305 
TMP BUFFER SIZE: 31751
SIG_CT SIZE: 1577
*/

/* Update this to generate valid entropy for target platform*/
inline byte random_byte(unsigned int i) {
#warning Bootloader does not have entropy source, keys are for TESTING ONLY
  return 0xac + (0xdd ^ i);
}

int bootloader() {
  // Reserve stack space for secrets
  int logn_test = 9, ret;
  
  byte scratchpad[128];
  
  sha3_ctx_t hash_ctx;
  
  shake256_context rng;
  byte sanctum_dev_secret_key[1281];
  
    /* Gathering high quality entropy during boot on embedded devices is
   * a hard problem. Platforms taking security seriously must provide
   * a high quality entropy source available in hardware. Platforms
   * that do not provide such a source must gather their own
   * entropy. See the Keystone documentation for further
   * discussion. For testing purposes, we have no entropy generation.
  */

  for (unsigned int i=0; i < 32; i++) {
    scratchpad[i] = random_byte(i);
  }

  shake256_init_prng_from_seed(&rng, scratchpad, 32);
  
  byte sanctum_device_root_key_priv[1281];
  byte sanctum_device_root_key_pub[897];

  byte sanctum_sm_signature_test[809];

  byte sanctum_sm_sign[809];          

  byte buf[324];    
  
  // keypair of the eca in sm
  byte ECASM_pk[FALCON_PUBKEY_SIZE(logn_test)];
  byte ECASM_priv[FALCON_PRIVKEY_SIZE(logn_test)];
  
  
  //buffer to accomodate signature  
  size_t sig_len = FALCON_SIG_CT_SIZE(logn_test);
  byte sig[sig_len];

  //tmp buffer to store intermediate values in the key generation process
  unsigned int falcon_tmpkeygen_size_test = FALCON_TMPSIZE_KEYGEN(logn_test);
  byte tmp[falcon_tmpkeygen_size_test];

  //tmp buffer to store intermediate values in the signature process
  unsigned int falcon_tmpsign_size_test = FALCON_TMPSIZE_SIGNDYN(logn_test);
  byte tmp_sig[falcon_tmpsign_size_test];

  //tmp buffer to store values in the verification process
  unsigned int falcon_tmpvrfy_size_test = FALCON_TMPSIZE_VERIFY(logn_test);
  byte tmp_vrfy[falcon_tmpvrfy_size_test];

  // TODO: on real device, copy boot image from memory. In simulator, HTIF writes boot image
  
  /* On a real device, the platform must provide a secure root device
     keystore. For testing purposes we hardcode a known private/public
     keypair */
  // TEST Device key
  #include "use_test_keys.h"
  
  //#include "sm_sign_and_pk_man.h"
  
  // Derive {SK_D, PK_D} (device keys) from a 32 B random seed
  
  // Measure for the first time the SM to simulate that the signature is provided by the manufacturer
  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, (void*)DRAM_BASE, sanctum_sm_size);
  sha3_final(sanctum_sm_hash, &hash_ctx);
  falcon_sign_dyn(&rng, sanctum_sm_signature_test, &sig_len, FALCON_SIG_CT, _sanctum_dev_secret_key, FALCON_PRIVKEY_SIZE(logn_test), sanctum_sm_hash, 64, tmp_sig, falcon_tmpsign_size_test);

  // Measure SM to verify the signature
  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, (void *)DRAM_BASE, sanctum_sm_size);
  sha3_final(sanctum_sm_hash, &hash_ctx);
  if((falcon_verify(sanctum_sm_signature_test, sig_len, FALCON_SIG_CT, _sanctum_dev_public_key, FALCON_PUBKEY_SIZE(logn_test), sanctum_sm_hash, 64, tmp_vrfy, falcon_tmpvrfy_size_test)) != 0)
  {
    // The return value of the bootloader function is used to check if the secure boot is gone well or not
    return 0;
  }

  // Combine hash of the security monitor and the device root key to obtain the CDI
  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, sanctum_uds, sizeof(*sanctum_uds));
  sha3_update(&hash_ctx, sanctum_sm_hash, sizeof(*sanctum_sm_hash));
  sha3_final(sanctum_CDI, &hash_ctx);

  // The device root keys are created from the CDI
  // This keys are certified by the manufacuter and the cert is stored in memory, like the cert of the manufacturer
  shake256_init_prng_from_seed(&rng, sanctum_CDI, sizeof(*sanctum_CDI));
  
  //generate device root key from CDI
  falcon_keygen_make(&rng, logn_test, sanctum_device_root_key_priv, FALCON_PRIVKEY_SIZE(logn_test), sanctum_device_root_key_pub, FALCON_PUBKEY_SIZE(logn_test),tmp,falcon_tmpkeygen_size_test);
  
  // The ECA keys are obtained starting from a seed generated hashing the CDI and the measure of the SM
  unsigned char seed_for_ECA_keys[64];

  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, sanctum_CDI, 64);
  sha3_update(&hash_ctx, sanctum_sm_hash, 64);
  sha3_final(seed_for_ECA_keys, &hash_ctx);

  //rng for the ECA keys
  shake256_init_prng_from_seed(&rng, seed_for_ECA_keys, 64);
  falcon_keygen_make(&rng, logn_test, ECASM_priv, FALCON_PRIVKEY_SIZE(logn_test), ECASM_pk, FALCON_PUBKEY_SIZE(logn_test), tmp, falcon_tmpkeygen_size_test);

  memcpy(sanctum_ECASM_priv, ECASM_priv, FALCON_PRIVKEY_SIZE(logn_test));

/**********************************SM CERT GEN*****************************/
  // Create the certificate structure mbedtls_x509write_cert to release the cert of the security monitor
  mbedtls_x509write_cert cert;
  mbedtls_x509write_crt_init(&cert);

  ret = mbedtls_x509write_crt_set_issuer_name_mod(&cert, "CN=Root of Trust");
  if (ret != 0)
  {
    return 0;
  }
  
  ret = mbedtls_x509write_crt_set_subject_name_mod(&cert, "CN=Security Monitor");
  if (ret != 0)
  {
    return 0; 
  }

  mbedtls_pk_context subj_key;
  mbedtls_pk_init(&subj_key);

  mbedtls_pk_context issu_key;
  mbedtls_pk_init(&issu_key);
  
  ret = mbedtls_pk_parse_public_key(&issu_key, sanctum_device_root_key_priv, FALCON_PRIVKEY_SIZE(logn_test), 1);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&issu_key, sanctum_device_root_key_pub, FALCON_PUBKEY_SIZE(logn_test), 0);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&subj_key, ECASM_pk, FALCON_PUBKEY_SIZE(logn_test), 0);
  if (ret != 0)
  {
    return 0;
  }

  
  unsigned char serial[] = {0x01, 0x01, 0x01};
  mbedtls_x509write_crt_set_subject_key(&cert, &subj_key);

  mbedtls_x509write_crt_set_issuer_key(&cert, &issu_key);
  
  mbedtls_x509write_crt_set_serial_raw(&cert, serial, 3);
  
  mbedtls_x509write_crt_set_md_alg(&cert, KEYSTONE_SHA3);
  
  ret = mbedtls_x509write_crt_set_validity(&cert, "20230101000000", "20250101000000");
  if (ret != 0)
  {
    return 0; 
  }
  
  unsigned char cert_der[4096];
  int effe_len_cert_der;

  unsigned char oid_ext[] = {0xff, 0x20, 0xff};

  mbedtls_x509write_crt_set_basic_constraints(&cert, 1, 10);
  
  dice_tcbInfo tcbInfo;
  init_dice_tcbInfo(&tcbInfo);

  measure m;
  const unsigned char OID_algo[] = {0x02,0x10,0x03,0x48,0x01,0x65,0x03,0x04,0x02,0x0A};


  memcpy(m.digest, sanctum_sm_hash, 64);
  memcpy(m.OID_algho, OID_algo, 10);
  m.oid_len = 10;

  set_dice_tcbInfo_measure(&tcbInfo, m);

  int dim= 324;

  if(mbedtls_x509write_crt_set_dice_tcbInfo(&cert, tcbInfo, dim, buf, sizeof(buf))!=0)
    return 0;


  ret = mbedtls_x509write_crt_der(&cert, cert_der, 4096, NULL, NULL);//, test, &len);
  if (ret != 0)
  {
    effe_len_cert_der = ret;
  }
  else
  {
    return 0;
  }
  
  unsigned char *cert_real = cert_der;
  int dif  = 4096-effe_len_cert_der;
  cert_real += dif;
  
  sanctum_length_cert = effe_len_cert_der;
  memcpy(sanctum_cert_sm, cert_real, effe_len_cert_der);

  mbedtls_x509_crt uff_cert;
  mbedtls_x509_crt_init(&uff_cert);

  if ((mbedtls_x509_crt_parse_der(&uff_cert, cert_real, effe_len_cert_der)) != 0){
     return 0;
  }
  if(memcmp( uff_cert.dice_tcb_info.fwids[0].digest, sanctum_sm_hash, 64) != 0){
  return 0;
  }
/**************************************************************************/
/*********************************MAN CERT GEN*****************************/
  //MAN CERT GENERATION
  /*
  mbedtls_x509write_cert cert_man;
  mbedtls_x509write_crt_init(&cert_man);
  
  ret = mbedtls_x509write_crt_set_issuer_name_mod(&cert_man, "O=Manufacturer");
  if (ret != 0)
  {
 return 0;
  }

  ret = mbedtls_x509write_crt_set_subject_name_mod(&cert_man, "O=Manufacturer");
  if (ret != 0)
  {
    return 0;
  }

  mbedtls_pk_context subj_key_man;
  mbedtls_pk_init(&subj_key_man);

  mbedtls_pk_context issu_key_man;
  mbedtls_pk_init(&issu_key_man);
  
  ret = mbedtls_pk_parse_public_key(&issu_key_man, _sanctum_dev_secret_key, FALCON_PRIVKEY_SIZE(logn_test), 1);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&issu_key_man, _sanctum_dev_public_key, FALCON_PUBKEY_SIZE(logn_test), 0);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&subj_key_man, _sanctum_dev_public_key, FALCON_PUBKEY_SIZE(logn_test), 0);
  if (ret != 0)
  {
    return 0;
  }

  
  unsigned char serial_man[] = {0xFF, 0xFF, 0xFF};
  
  mbedtls_x509write_crt_set_subject_key(&cert_man, &subj_key_man);

  mbedtls_x509write_crt_set_issuer_key(&cert_man, &issu_key_man);
  
  mbedtls_x509write_crt_set_serial_raw(&cert_man, serial_man, 3);
  
  mbedtls_x509write_crt_set_md_alg(&cert_man, KEYSTONE_SHA3);
  
  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert_man, "20230101000000", "20250101000000");
  if (ret != 0)
  {
    return 0;
  }
  mbedtls_x509write_crt_set_basic_constraints(&cert_man, 1, 10);
  */
  /*AT THIS POINT THE MANUFACTURER CERTIFICATE IS CORRECTLY CREATED*/
  /*
  unsigned char cert_der_man[4096];
  int effe_len_cert_der_man;

  ret = mbedtls_x509write_crt_der(&cert_man, cert_der_man, 4096, NULL, NULL);//, test, &len);
  if (ret != 0)
  {
    effe_len_cert_der_man = ret;
  }
  else
  {
    return 0;
  }

  unsigned char *cert_real_man = cert_der_man;
  int dif_man = 4096-effe_len_cert_der_man;
  cert_real_man += dif_man;
  */
  sanctum_length_cert_man = _sanctum_length_cert_man;
  memcpy(sanctum_cert_man, _sanctum_cert_man, sanctum_length_cert_man);
  
  /*AT THIS POINT THE MANUFACTURER DER CERTIFICATE IS CORRECTLY CREATED*/
  
  /*********************************ROOT CERT GEN*****************************/
  
  mbedtls_x509write_cert cert_root;
  mbedtls_x509write_crt_init(&cert_root);
  
  ret = mbedtls_x509write_crt_set_issuer_name_mod(&cert_root, "O=Manufacturer");
  if (ret != 0)
  {
    return 0;
  }
    
  ret = mbedtls_x509write_crt_set_subject_name_mod(&cert_root, "O=Root of Trust");
  if (ret != 0)
  {
    return 0;
  }

  mbedtls_pk_context subj_key_test;
  mbedtls_pk_init(&subj_key_test);

  mbedtls_pk_context issu_key_test;
  mbedtls_pk_init(&issu_key_test);
  
  ret = mbedtls_pk_parse_public_key(&issu_key_test, _sanctum_dev_secret_key, FALCON_PRIVKEY_SIZE(logn_test), 1);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&issu_key_test, _sanctum_dev_public_key, FALCON_PUBKEY_SIZE(logn_test), 0);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&subj_key_test, sanctum_device_root_key_pub, FALCON_PUBKEY_SIZE(logn_test), 0);
  if (ret != 0)
  {
    return 0;
  }

  
  unsigned char serial_root[] = {0x00, 0x00, 0x00};
  
  mbedtls_x509write_crt_set_subject_key(&cert_root, &subj_key_test);

  mbedtls_x509write_crt_set_issuer_key(&cert_root, &issu_key_test);
  
  mbedtls_x509write_crt_set_serial_raw(&cert_root, serial_root, 3);
  
  mbedtls_x509write_crt_set_md_alg(&cert_root, KEYSTONE_SHA3);
  
  ret = mbedtls_x509write_crt_set_validity(&cert_root, "20230101000000", "20240101000000");
  if (ret != 0)
  {
    return 0;
  }
  //mbedtls_x509write_crt_set_basic_constraints(&cert_root, 1, 10);
  
  unsigned char cert_der_root[4096];
  int effe_len_cert_der_root;

  ret = mbedtls_x509write_crt_der(&cert_root, cert_der_root, 4096, NULL, NULL);//, test, &len);
  if (ret != 0)
  {
    effe_len_cert_der_root = ret;
  }
  else
  {
    return 0;
  }

  unsigned char *cert_real_root = cert_der_root;
  int dif_root = 4096-effe_len_cert_der_root;
  cert_real_root += dif_root;

  sanctum_length_cert_root = effe_len_cert_der_root;
  memcpy(sanctum_cert_root, cert_real_root, effe_len_cert_der_root);
/***************************************************************************/
 
  //In the real case the cert associated to the device root key is provided by the manufacturer
  //in this scenario it is not possible due to the fact the SM can change, so also its measure can change
  //and if the sm measure change also the CDI and consequently the device root keys will change.
  //So until the sm can change, the cert associated to the device root keys are generated here
  //In this way there will be no problem to check the cert, that otherwise will be associated to a device root key pub wrong
  /***********************************************************************************************************/
  /***********************************************************************************************************/

/*------------------------------------------------------*/
  // Combine SK_D and H_SM via a hash
  // sm_key_seed <-- H(SK_D, H_SM), truncate to 32B
  byte scratch[64 + FALCON_PUBKEY_SIZE(logn_test)];
  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, sanctum_dev_secret_key, FALCON_PUBKEY_SIZE(logn_test));
  sha3_update(&hash_ctx, sanctum_sm_hash, sizeof(*sanctum_sm_hash));
  sha3_final(scratchpad, &hash_ctx);
  // Derive {SK_D, PK_D} (device keys) from the first 32 B of the hash (NIST endorses SHA512 truncation as safe)
  shake256_init_prng_from_seed(&rng, scratchpad, 32);
  falcon_keygen_make(&rng, logn_test, sanctum_sm_secret_key, FALCON_PRIVKEY_SIZE(logn_test), sanctum_sm_public_key, FALCON_PUBKEY_SIZE(logn_test), tmp, falcon_tmpkeygen_size_test);

  // Endorse the SM
  memcpy(scratch, sanctum_sm_hash, 64);
  memcpy(scratch + 64, sanctum_sm_public_key, FALCON_PUBKEY_SIZE(logn_test));

  // Sign (H_SM, PK_SM) with SK_D
  falcon_sign_dyn(&rng, sanctum_sm_signature, &sig_len, FALCON_SIG_CT, _sanctum_dev_secret_key, FALCON_PRIVKEY_SIZE(logn_test), scratch, 64 + FALCON_PUBKEY_SIZE(logn_test), tmp_sig, falcon_tmpsign_size_test);

  // Clean up
  //memcpy(sanctum_sm_signature, sanctum_sm_signature_test, sizeof(*sanctum_sm_signature_test));
  memset((void*)sanctum_dev_secret_key, 0, sizeof(*sanctum_dev_secret_key));
  memset((void *)sanctum_device_root_key_priv, 0, sizeof(*sanctum_device_root_key_priv));
  
  // caller will clean core state and memory (including the stack), and boot.
  return 1;
}

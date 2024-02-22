//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "ipi.h"
#include "sm.h"
#include "pmp.h"
#include "crypto.h"
#include "enclave.h"
#include "platform-hook.h"
#include "sm-sbi-opensbi.h"
#include "falcon512_sm/my_string.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_timer.h>

#include "x509custom_sm/x509custom.h"

/* from Sanctum BootROM */
extern byte sanctum_sm_hash[MDSIZE];
extern byte sanctum_sm_signature[809];
extern byte sanctum_sm_secret_key[1281];
extern byte sanctum_sm_public_key[897];
extern byte sanctum_ECASM_priv[1281];

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

// Variable used to pass the all that is needed to the SM to properly work
extern byte sanctum_CDI[64];
extern byte sanctum_cert_sm[2065]; //2065
extern byte sanctum_cert_root[1883];//1883
extern byte sanctum_cert_man[1903];//1903
extern int sanctum_length_cert;
extern int sanctum_length_cert_root;
extern int sanctum_length_cert_man;

byte CDI[64] = { 0, };
byte cert_sm[2065] = { 0, };
byte cert_root[1883] = { 0, };
byte cert_man[1903] = { 0, };
byte ECASM_priv[FALCON_512_SK_SIZE]= { 0, };
byte ECASM_pk[FALCON_512_PK_SIZE] = { 0, };
byte sm_hash[MDSIZE] = { 0, };
byte sm_signature[FALCON_512_SIG_SIZE] = { 0, };
byte sm_public_key[FALCON_512_PK_SIZE] = { 0, };
byte sm_private_key[FALCON_512_SK_SIZE] = { 0, };
byte dev_public_key[FALCON_512_PK_SIZE] = { 0, };
byte tmp[FALCON_TMPSIZE_SIGNDYN(9)];
byte hash_for_verification[64];

mbedtls_x509_crt uff_cert_sm;
mbedtls_x509_crt uff_cert_root;
mbedtls_x509_crt uff_cert_man;

sha3_ctx_t ctx_hash;
shake256_context rng;

unsigned int sanctum_sm_size = 0x1fd000;

u64 init_value;
u64 final_value;
static int sm_init_done = 0;
static int sm_region_id = 0, os_region_id = 0;
int length_cert_root;
int length_cert_man;
int length_cert;
//falcon security parameter
static int logn_test = 9;


char* validation(mbedtls_x509_crt cert);

void print_hash(byte *hash, size_t size);

void print_hash(byte *hash, size_t size){
  sbi_printf("HASH:\n");
  for (int i = 0; i < size; ++i)
  {
    sbi_printf("%02x", hash[i]);
  }
  sbi_printf("\n");
}

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};


void base64_encode(unsigned char *data,
                    size_t input_length, int flag) {
    size_t output_length;

    if (input_length % 3) {
    output_length = ((input_length / 3) + 1) * 4;
  } else {
    output_length = (input_length / 3) * 4;
  }
    char encoded_data[output_length];

    unsigned char tmpByte = 0;
    tmpByte = data[0] & (0xFF >> 6);
    unsigned char mask = ~(0xFF >> 6);
    unsigned char lookupVal = (data[0] & mask) >> 2;
    encoded_data[0] = encoding_table[lookupVal];
    size_t divider = 4;
    size_t i = 1;
    size_t bufIndex = 1;
  
  while (i < input_length) {
    tmpByte <<= divider;
    unsigned char mask = ~(0xFF >> divider);
    unsigned char mostSigBits = data[i] & mask;
    mostSigBits >>= (8 - divider);
    encoded_data[bufIndex] = encoding_table[tmpByte ^ mostSigBits];
    bufIndex++;
    if (divider == 2) {
      encoded_data[bufIndex] = encoding_table[(data[i] & (0xFF >> divider))];
      bufIndex++;
      tmpByte = 0;
    } else {
      tmpByte = data[i] & (0xFF >> divider);
    }

    divider = (divider - 2) ? divider - 2 : 6;
    i++;
  }
  encoded_data[bufIndex]= encoding_table[tmpByte <<= divider];

  while (bufIndex < output_length) {
    encoded_data[++bufIndex] = '=';
  }
    if (flag == 0)
      sbi_printf("\n-----BEGIN PUBLIC KEY-----\n");
    else
      sbi_printf("\n-----BEGIN CERTIFICATE-----\n");
    for (int i = 0; i < 96; ++i)
    {
      if(i%64 == 0 && i != 0)
        sbi_printf("\n");
      sbi_printf("%c", encoded_data[i]);
    }
    sbi_printf("...");
    if (flag == 0)
    {
      for (int i = output_length - 137; i < output_length; ++i)
      {
        if(i%64 == 0 && i != 0)
          sbi_printf("\n");
        sbi_printf("%c", encoded_data[i]);
      }
    }
    else {
      for (int i = output_length - 121; i < output_length; ++i)
      {
        if(i%64 == 0 && i != 0)
          sbi_printf("\n");
        sbi_printf("%c", encoded_data[i]);
      }
    }
    if (flag == 0)
      sbi_printf("\n-----END PUBLIC KEY-----\n");
    else
      sbi_printf("\n-----END CERTIFICATE-----\n");
}


int osm_pmp_set(uint8_t perm)
{
  /* in case of OSM, PMP cfg is exactly the opposite.*/
  return pmp_set_keystone(os_region_id, perm);
}

int smm_init()
{
  int region = -1;
  int ret = pmp_region_init_atomic(SMM_BASE, SMM_SIZE, PMP_PRI_TOP, &region, 0);
  if(ret)
    return -1;

  return region;
}

int osm_init()
{
  int region = -1;
  int ret = pmp_region_init_atomic(0, -1UL, PMP_PRI_BOTTOM, &region, 1);
  if(ret)
    return -1;

  return region;
}

void sm_sign(void* signature, const void* data, size_t len)
{
  byte seed[]={0x01};
  shake256_init_prng_from_seed(&rng, seed, 1);
  sign(signature, data, len, sm_private_key, tmp, &rng);
}

int sm_derive_sealing_key(unsigned char *key, const unsigned char *key_ident,
                          size_t key_ident_size,
                          const unsigned char *enclave_hash)
{
  unsigned char info[MDSIZE + key_ident_size];

  sbi_memcpy(info, enclave_hash, MDSIZE);
  sbi_memcpy(info + MDSIZE, key_ident, key_ident_size);

  /*
   * The key is derived without a salt because we have no entropy source
   * available to generate the salt.
   */
  return kdf(NULL, 0,
             (const unsigned char *)sm_private_key, FALCON_512_SK_SIZE,
             info, MDSIZE + key_ident_size, key, SEALING_KEY_SIZE); //do we need post quantum solution
}

void sm_copy_key()
{ 
  /********************COPY VARIABLES FROM BOOTROM TO SM**********************/

  sbi_memcpy(sm_hash, sanctum_sm_hash, MDSIZE);
  sbi_memcpy(sm_signature, sanctum_sm_signature, FALCON_512_SIG_SIZE);
  sbi_memcpy(sm_public_key, sanctum_sm_public_key, FALCON_512_PK_SIZE);
  sbi_memcpy(sm_private_key, sanctum_sm_secret_key, FALCON_512_SK_SIZE);
  sbi_memcpy(ECASM_priv, sanctum_ECASM_priv, FALCON_512_SK_SIZE);
  sbi_memcpy(CDI, sanctum_CDI, 64);
  sbi_memcpy(cert_sm, sanctum_cert_sm, sanctum_length_cert);
  sbi_memcpy(cert_root, sanctum_cert_root, sanctum_length_cert_root);
  sbi_memcpy(cert_man, sanctum_cert_man, sanctum_length_cert_man); 
  length_cert = sanctum_length_cert;
  length_cert_root = sanctum_length_cert_root;
  length_cert_man = sanctum_length_cert_man;

  /********************PARSE CERTIFICATES FOR CORRECTNESS**********************/

  if ((mbedtls_x509_crt_parse_der(&uff_cert_sm, cert_sm, length_cert)) != 0){

      // If there are some problems parsing a cert, all the start process is stopped
      sbi_printf("\n\n\n[SM] Error parsing the ECA certificate");
      sbi_hart_hang();
  }
  else{
    sbi_printf("\n[SM] The ECA certificate is correctly parsed\n\n");
    //print_uffcert(&uff_cert_sm);
  }

  if ((mbedtls_x509_crt_parse_der(&uff_cert_root, cert_root, length_cert_root)) != 0){
      sbi_printf("[SM] Error parsing the DRK certificate\n\n");
      sbi_hart_hang();
  }
  else{
    sbi_printf("[SM] The DRK certificate is correctly parsed\n\n");
    //print_uffcert(&uff_cert_root);
  }

  if ((mbedtls_x509_crt_parse_der(&uff_cert_man, cert_man, length_cert_man)) != 0){
      sbi_printf("[SM] Error parsing the manufacturer certificate\n\n");
      sbi_hart_hang();
  }
  else{
    sbi_printf("[SM] The manufacturer certificate is correctly parsed\n\n");
    //print_uffcert(&uff_cert_man);
  }

  char* str_ret = validation(uff_cert_sm);
  if(my_strlen(str_ret) != 0){
    sbi_printf("[SM] Problem with the ECA certificate: %s \n\n", str_ret);
    sbi_hart_hang();

  }
  else 
  {
    str_ret = validation(uff_cert_root);
    if(my_strlen(str_ret) != 0){
      sbi_printf("[SM] Problem with the DRK certificate: %s \n\n", str_ret);
      sbi_hart_hang();

    }
    else {
      str_ret = validation(uff_cert_man);
      if(my_strlen(str_ret) != 0){
        sbi_printf("[SM] Problem with the manufacturer certificate: %s \n\n", str_ret);
        sbi_hart_hang();

      }
      else {
        sbi_printf("[SM] All the certificate chain is formally correct\n\n");
      }
    }
  }

/********************VERIFY CERTIFICATES SIGNATURES**********************/

  int falcon_tmpvrfy_size_test = FALCON_TMPSIZE_SIGNDYN(logn_test);
  sha3_init(&ctx_hash, 64);
  sha3_update(&ctx_hash, uff_cert_sm.tbs.p, uff_cert_sm.tbs.len);
  sha3_final(hash_for_verification, &ctx_hash);
  
  sbi_printf("[SM] Verifying the chain signatures of the certificates until the man cert...\n\n");
  
  if((falcon_verify(uff_cert_sm.sig.p, uff_cert_sm.sig.len, FALCON_SIG_CT, uff_cert_root.pk.pk_ctx.pub_key, FALCON_PUBKEY_SIZE(logn_test), hash_for_verification, 64, tmp, falcon_tmpvrfy_size_test)) != 0){
    sbi_printf("[SM] Error verifying the signature of the ECA certificate\n\n");
    sbi_hart_hang();
  }
  else{
    // The verification process is also repeated to verify the cert associated to the root of trust, certified with the private key of the manufacturer
    sbi_printf("[SM] The signature of the ECA certificate is ok\n\n");
    
    sha3_init(&ctx_hash, 64);
    sha3_update(&ctx_hash, uff_cert_root.tbs.p, uff_cert_root.tbs.len);
    sha3_final(hash_for_verification, &ctx_hash);
    //hash_for_verification[0] = 0x0;
    
    if(falcon_verify(uff_cert_root.sig.p, uff_cert_root.sig.len, FALCON_SIG_CT, uff_cert_man.pk.pk_ctx.pub_key, FALCON_PUBKEY_SIZE(logn_test), hash_for_verification, 64, tmp, falcon_tmpvrfy_size_test) != 0){
      sbi_printf("[SM] Error verifying the signature of the DRK certificate\n\n");
      sbi_hart_hang();
    }
    else{
      sbi_printf("[SM] The signature of the DRK certificate is ok\n\n");
      sbi_printf("[SM] All the chain is verified\n\n");
    }
  }

  if(my_memcmp(uff_cert_sm.dice_tcb_info.fwids[0].digest, sm_hash, 64) != 0){
    sbi_printf("[SM] Problem with the extension of the ECA certificate");
    sbi_hart_hang();
  }
  else
      sbi_printf("[SM] No differeces between ECA cert extension and value provided by original Keystone implementation\n\n");

    /************************EXTRACT PUBLIC KEYS FROM CERTIFICATES*************************/

    sbi_memcpy(dev_public_key, uff_cert_man.pk.pk_ctx.pub_key, FALCON_512_PK_SIZE);
    sbi_memcpy(ECASM_pk, uff_cert_sm.pk.pk_ctx.pub_key, FALCON_512_PK_SIZE);
    
    sbi_printf("[SM] Public Keys extracted from certs generated in the bootrom\n");
    
    sbi_printf("\nMANUFACTURER PUBLIC KEY:\n");
    base64_encode(uff_cert_man.pk.pk_ctx.pub_key, FALCON_512_PK_SIZE, 0);
    sbi_printf("\nECA SM PUBLIC KEY:\n");
    base64_encode(uff_cert_sm.pk.pk_ctx.pub_key, FALCON_512_PK_SIZE, 0);
    sbi_printf("\nDEVICE ROOT PUBLIC KEY:\n");
    base64_encode(uff_cert_root.pk.pk_ctx.pub_key, FALCON_512_PK_SIZE, 0);
    
}

void sm_print_hash()
{
  sbi_printf("[SM] Hash value: ");
  for (int i=0; i<MDSIZE; i++)
  {
    sbi_printf("%02x", (char) sm_hash[i]);
  }
  sbi_printf("\n\n");
}

/*
void sm_print_cert()
{
	int i;

	sbi_printf("Booting from Security Monitor\n");
	sbi_printf("Size: %d\n", sanctum_sm_size);

	sbi_printf("============ PUBKEY =============\n");
	for(i=0; i<8; i+=1)
	{
		sbi_printf("%x",*((int*)sanctum_dev_public_key+i));
		if(i%4==3) sbi_printf("\n");
	}
	sbi_printf("=================================\n");

	sbi_printf("=========== SIGNATURE ===========\n");
	for(i=0; i<16; i+=1)
	{
		sbi_printf("%x",*((int*)sanctum_sm_signature+i));
		if(i%4==3) sbi_printf("\n");
	}
	sbi_printf("=================================\n");
}
*/
void sm_init(bool cold_boot)
{
	// initialize SMM
  if (cold_boot) {
    /* only the cold-booting hart will execute these */
    sbi_printf("[SM] Initializing ... hart [%lx]\n", csr_read(mhartid));

    init_value = sbi_timer_value();
    sbi_printf("Ticks needed to enter the SM starting process: %ld\n", init_value);

    sbi_ecall_register_extension(&ecall_keystone_enclave);

    sm_region_id = smm_init();

    if(sm_region_id < 0) {
      sbi_printf("[SM] intolerable error - failed to initialize SM memory");
      sbi_hart_hang();
    }

    os_region_id = osm_init();
    if(os_region_id < 0) {
      sbi_printf("[SM] intolerable error - failed to initialize OS memory");
      sbi_hart_hang();
    }

    if (platform_init_global_once() != SBI_ERR_SM_ENCLAVE_SUCCESS) {
      sbi_printf("[SM] platform global init fatal error");
      sbi_hart_hang();
    }
    // Copy the keypair from the root of trust
    sm_copy_key();

    // Init the enclave metadata
    enclave_init_metadata();

    sm_init_done = 1;

    mb();
  
  }

  /* wait until cold-boot hart finishes */
  while (!sm_init_done)
  {
    mb();
  }

  /* below are executed by all harts */
  pmp_init();

  pmp_set_keystone(sm_region_id, PMP_NO_PERM);
  pmp_set_keystone(os_region_id, PMP_ALL_PERM);

  /* Fire platform specific global init */
  if (platform_init_global() != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    sbi_printf("[SM] platform global init fatal error");
    sbi_hart_hang();
  }

  sbi_printf("[SM] Keystone SM has been initialized!\n\n");
  final_value = sbi_timer_value();
  sbi_printf("Ticks needed to start the SM: %ld\n", final_value - init_value);

  sm_print_hash();

  return;
  // for debug
  // sm_print_cert();
}

char* validation(mbedtls_x509_crt cert){
  
  if(cert.ne_issue_arr == 0)
    return "Problem with the issuer of the certificate";
  if(cert.ne_subje_arr == 0)
    return "Problem with the subject of the certificate";
  if(((cert.valid_from.day < 1)&& (cert.valid_from.day > 31)) || ((cert.valid_from.mon < 1)&& (cert.valid_from.mon > 12)) || (cert.valid_from.year == 0))
    return "Problem with the valid_from field of the certificate";
  if(((cert.valid_to.day < 1)&& (cert.valid_to.day > 31)) || ((cert.valid_to.mon < 1)&& (cert.valid_to.mon > 12)) || (cert.valid_to.year == 0))
    return "Problem with the valid_to field of the certificate";
  if(cert.pk.pk_ctx.len != 897)
    return "Problem with the pk length of the certificate";
  if(cert.serial.len == 0)
    return "Problem with the serial length of the certificate";
  if(cert.sig.len == 0)
    return "Problem with the signature length of the certificate";
  return "";

}

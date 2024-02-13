//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#ifndef TARGET_PLATFORM_HEADER
#error "SM requires a defined platform to build"
#endif

#include "sm.h"
#include "pmp.h"
#include "thread.h"
#include "crypto.h"
#include "x509custom_sm/x509custom.h"
#include "falcon512_sm/my_string.h"
#include "falcon512_sm/falcon.h"

// Special target platform header, set by configure script
#include TARGET_PLATFORM_HEADER

#define ATTEST_DATA_MAXLEN  20//1024
#define ENCLAVE_REGIONS_MAX 8
/* TODO: does not support multithreaded enclave yet */
#define MAX_ENCL_THREADS 1

typedef enum {
  INVALID = -1,
  DESTROYING = 0,
  ALLOCATED,
  FRESH,
  STOPPED,
  RUNNING,
} enclave_state;

/* Enclave stop reasons requested */
#define STOP_TIMER_INTERRUPT  0
#define STOP_EDGE_CALL_HOST   1
#define STOP_EXIT_ENCLAVE     2

/* For now, eid's are a simple unsigned int */
typedef unsigned int enclave_id;

/* Metadata around memory regions associate with this enclave
 * EPM is the 'home' for the enclave, contains runtime code/etc
 * UTM is the untrusted shared pages
 * OTHER is managed by some other component (e.g. platform_)
 * INVALID is an unused index
 */
enum enclave_region_type{
  REGION_INVALID,
  REGION_EPM,
  REGION_UTM,
  REGION_OTHER,
};

struct enclave_region
{
  region_id pmp_rid;
  enum enclave_region_type type;
};

/* enclave metadata */
struct enclave
{
  //spinlock_t lock; //local enclave lock. we don't need this until we have multithreaded enclave
  enclave_id eid; //enclave id
  unsigned long encl_satp; // enclave's page table base
  enclave_state state; // global state of the enclave

  /* Physical memory regions associate with this enclave */
  struct enclave_region regions[ENCLAVE_REGIONS_MAX];

  /* measurement */
  byte hash[MDSIZE];
  byte sign[FALCON_512_SIG_SIZE]; //SIGNATURE_SIZE

  byte CDI[64]; 
  byte local_att_pub[FALCON_512_PK_SIZE]; //32
  byte local_att_priv[FALCON_512_SK_SIZE]; //64
  /*
  the falcon keygen stalls with the tmp allocated in the stack
  */
  //byte tmp[FALCON_TMPSIZE_KEYGEN(9)];
  unsigned char cert_der[2100];
  mbedtls_x509write_cert crt_local_att;
  unsigned char crt_local_att_der[2037]; //512
  int crt_local_att_der_length;
  mbedtls_pk_context subj_key;
  mbedtls_pk_context issu_key;

 // byte pk_ldev[FALCON_512_PK_SIZE]; //32
 // byte sk_ldev[FALCON_512_SK_SIZE]; //64
/*
  byte sk_array[2][FALCON_512_SK_SIZE]; //32-10
  byte pk_array[2][FALCON_512_PK_SIZE]; //64-10
  int n_keypair;
*/
  /* parameters */
  struct runtime_va_params_t params;
  struct runtime_pa_params pa_params;

  /* enclave execution context */
  unsigned int n_thread;
  struct thread_state threads[MAX_ENCL_THREADS];

  struct platform_enclave_data ped;
};

/* attestation reports */
struct enclave_report
{
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
  byte signature[FALCON_512_SIG_SIZE]; //SIGNATURE_SIZE
};
struct sm_report
{
  byte hash[MDSIZE];
  byte public_key[FALCON_512_PK_SIZE]; //PUBLIC_KEY_SIZE
  byte signature[FALCON_512_SIG_SIZE]; //SIGNATURE_SIZE
};
struct report
{
  struct enclave_report enclave;
  struct sm_report sm;
  //byte dev_public_key[FALCON_512_PK_SIZE]; //PUBLIC_KEY_SIZE
};

/* sealing key structure */
#define SEALING_KEY_SIZE 128
struct sealing_key
{
  uint8_t key[SEALING_KEY_SIZE];
  uint8_t signature[FALCON_512_SIG_SIZE]; //SIGNATURE_SIZE
};

/*** SBI functions & external functions ***/
// callables from the host
unsigned long create_enclave(unsigned long *eid, struct keystone_sbi_create create_args);
unsigned long destroy_enclave(enclave_id eid);
unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid);
unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid);
// callables from the enclave
unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid);
unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid);
unsigned long attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size, enclave_id eid);
/* attestation and virtual mapping validation */
unsigned long validate_and_hash_enclave(struct enclave* enclave);
// TODO: These functions are supposed to be internal functions.
void enclave_init_metadata();
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create* dest);
int get_enclave_region_index(enclave_id eid, enum enclave_region_type type);
uintptr_t get_enclave_region_base(enclave_id eid, int memid);
uintptr_t get_enclave_region_size(enclave_id eid, int memid);
unsigned long get_sealing_key(uintptr_t seal_key, uintptr_t key_ident, size_t key_ident_size, enclave_id eid);
/*
unsigned long create_keypair(enclave_id eid, unsigned char* pk ,int seed_enc); //
unsigned long get_cert_chain(unsigned char** certs, unsigned char* sizes); //
unsigned long do_crypto_op(enclave_id eid, int flag, unsigned char* data, int data_len, unsigned char* out_data, int* len_out_data, unsigned char* pk); //
*/
#endif

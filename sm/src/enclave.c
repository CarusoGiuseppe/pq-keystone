//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "mprv.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include "sha3/sha3.h"
#include "sm.h"
#include "falcon512_sm/falcon.h"
#include "ed25519/ed25519.h"
#include <sbi/sbi_timer.h>
#include <sbi/sbi_string.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sbi/riscv_barrier.h>

#define ENCL_MAX  16

struct enclave enclaves[ENCL_MAX];
#define ENCLAVE_EXISTS(eid) (eid >= 0 && eid < ENCL_MAX && enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;

extern void save_host_regs(void);
extern void restore_host_regs(void);
extern byte dev_public_key[897];//PUBLIC_KEY_SIZE
extern byte tmp[FALCON_TMPSIZE_SIGNDYN(9)];
extern byte CDI[64]; 
extern byte ECASM_pk[897]; //64
extern byte ECASM_priv[1281]; //64
//extern mbedtls_x509_crt uff_cert_sm;
extern byte sm_hash[MDSIZE];
extern byte sm_signature[FALCON_512_SIG_SIZE];
extern byte sm_public_key[FALCON_512_PK_SIZE];
extern byte cert_sm[2065]; //2065
extern byte cert_root[1883]; //1883
extern byte cert_man[1903]; //1903
extern int length_cert_man;
extern int length_cert_root;
extern int length_cert;
extern shake256_context rng;
struct report report;
const unsigned char OID_algo[] = {0x02,0x10,0x03,0x48,0x01,0x65,0x03,0x04,0x02,0x0A};
dice_tcbInfo tcbInfo;
measure m;
byte sign_tmp[FALCON_SIG_CT_SIZE(9)];

/****************************
 *
 * Enclave utility functions
 * Internal use by SBI calls
 *
 ****************************/

/* Internal function containing the core of the context switching
 * code to the enclave.
 *
 * Used by resume_enclave and run_enclave.
 *
 * Expects that eid has already been valided, and it is OK to run this enclave
*/

static inline void context_switch_to_enclave(struct sbi_trap_regs* regs,
                                                enclave_id eid,
                                                int load_parameters){
  /* save host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, 1);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  uintptr_t interrupts = 0;
  csr_write(mideleg, interrupts);

  if(load_parameters) {
    // passing parameters for a first run
    regs->mepc = (uintptr_t) enclaves[eid].pa_params.dram_base - 4; // regs->mepc will be +4 before sbi_ecall_handler return
    regs->mstatus = (1 << MSTATUS_MPP_SHIFT);
    // $a1: (PA) DRAM base,
    regs->a1 = (uintptr_t) enclaves[eid].pa_params.dram_base;
    // $a2: (PA) DRAM size,
    regs->a2 = (uintptr_t) enclaves[eid].pa_params.dram_size;
    // $a3: (PA) kernel location,
    regs->a3 = (uintptr_t) enclaves[eid].pa_params.runtime_base;
    // $a4: (PA) user location,
    regs->a4 = (uintptr_t) enclaves[eid].pa_params.user_base;
    // $a5: (PA) freemem location,
    regs->a5 = (uintptr_t) enclaves[eid].pa_params.free_base;
    // $a6: (PA) utm base,
    regs->a6 = (uintptr_t) enclaves[eid].params.untrusted_ptr;
    // $a7: (size_t) utm size
    regs->a7 = (uintptr_t) enclaves[eid].params.untrusted_size;

    // enclave will only have physical addresses in the first run
    csr_write(satp, 0);
  }

  switch_vector_enclave();

  // set PMP
  osm_pmp_set(PMP_NO_PERM);
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
    }
  }

  // Setup any platform specific defenses
  platform_switch_to_enclave(&(enclaves[eid]));
  cpu_enter_enclave_context(eid);
}

static inline void context_switch_to_host(struct sbi_trap_regs *regs,
    enclave_id eid,
    int return_on_resume){

  // set PMP
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
    }
  }
  osm_pmp_set(PMP_ALL_PERM);

  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
  csr_write(mideleg, interrupts);

  /* restore host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, return_on_resume);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  switch_vector_host();

  uintptr_t pending = csr_read(mip);

  if (pending & MIP_MTIP) {
    csr_clear(mip, MIP_MTIP);
    csr_set(mip, MIP_STIP);
  }
  if (pending & MIP_MSIP) {
    csr_clear(mip, MIP_MSIP);
    csr_set(mip, MIP_SSIP);
  }
  if (pending & MIP_MEIP) {
    csr_clear(mip, MIP_MEIP);
    csr_set(mip, MIP_SEIP);
  }

  // Reconfigure platform specific defenses
  platform_switch_from_enclave(&(enclaves[eid]));

  cpu_exit_enclave_context();

  return;
}


// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
void enclave_init_metadata(){
  enclave_id eid;
  int i=0;

  /* Assumes eids are incrementing values, which they are for now */
  for(eid=0; eid < ENCL_MAX; eid++){
    enclaves[eid].state = INVALID;

    // Clear out regions
    for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
      enclaves[eid].regions[i].type = REGION_INVALID;
    }
    /* Fire all platform specific init for each enclave */
    platform_init_enclave(&(enclaves[eid]));
  }

}

static unsigned long clean_enclave_memory(uintptr_t utbase, uintptr_t utsize)
{

  // This function is quite temporary. See issue #38

  // Zero out the untrusted memory region, since it may be in
  // indeterminate state.
  sbi_memset((void*)utbase, 0, utsize);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long encl_alloc_eid(enclave_id* _eid)
{
  enclave_id eid;

  spin_lock(&encl_lock);

  for(eid=0; eid<ENCL_MAX; eid++)
  {
    if(enclaves[eid].state == INVALID){
      break;
    }
  }
  if(eid != ENCL_MAX)
    enclaves[eid].state = ALLOCATED;

  spin_unlock(&encl_lock);

  if(eid != ENCL_MAX){
    *_eid = eid;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  else{
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }
}

static unsigned long encl_free_eid(enclave_id eid)
{
  spin_lock(&encl_lock);
  enclaves[eid].state = INVALID;
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

int get_enclave_region_index(enclave_id eid, enum enclave_region_type type){
  size_t i;
  for(i = 0;i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == type){
      return i;
    }
  }
  // No such region for this enclave
  return -1;
}

uintptr_t get_enclave_region_size(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

uintptr_t get_enclave_region_base(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create* dest){

  int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_create));

  if (region_overlap)
    return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data from enclave, source must be inside EPM */
static unsigned long copy_enclave_data(struct enclave* enclave,
                                          void* dest, uintptr_t source, size_t size) {

  int illegal = copy_to_sm(dest, source, size);

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data into enclave, destination must be inside EPM */
static unsigned long copy_enclave_report(struct enclave* enclave,
                                            uintptr_t dest, struct report* source) {
  int illegal = copy_from_sm(dest, source, sizeof(struct report));

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct keystone_sbi_create* args)
{
  uintptr_t epm_start, epm_end;

   /*sbi_printf("[create args info]: \r\n\tepm_addr: %lx\r\n\tepmsize: %lx\r\n\tutm_addr: %lx\r\n\tutmsize: %lx\r\n\truntime_addr: %lx\r\n\tuser_addr: %lx\r\n\tfree_addr: %lx\r\n", 
          args->epm_region.paddr, 
          args->epm_region.size, 
          args->utm_region.paddr, 
          args->utm_region.size, 
          args->runtime_paddr, 
          args->user_paddr, 
          args->free_paddr); 
  */
  // check if physical addresses are valid
  if (args->epm_region.size <= 0)
    return 0;

  // check if overflow
  if (args->epm_region.paddr >=
      args->epm_region.paddr + args->epm_region.size)
    return 0;
  if (args->utm_region.paddr >=
      args->utm_region.paddr + args->utm_region.size)
    return 0;

  epm_start = args->epm_region.paddr;
  epm_end = args->epm_region.paddr + args->epm_region.size;

  // check if physical addresses are in the range
  if (args->runtime_paddr < epm_start ||
      args->runtime_paddr >= epm_end)
    return 0;
  if (args->user_paddr < epm_start ||
      args->user_paddr >= epm_end)
    return 0;
  if (args->free_paddr < epm_start ||
      args->free_paddr > epm_end)
      // note: free_paddr == epm_end if there's no free memory
    return 0;

  // check the order of physical addresses
  if (args->runtime_paddr > args->user_paddr)
    return 0;
  if (args->user_paddr > args->free_paddr)
    return 0;

  return 1;
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/


/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
unsigned long create_enclave(unsigned long *eidptr, struct keystone_sbi_create create_args)
{

  /* EPM and UTM parameters */
  unsigned char serial[] = {0x0};
  unsigned long ret;
  int region, shared_region;
  int logn_test = 9;
  enclave_id eid; 
  sha3_ctx_t hash_ctx_to_use;
  

  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;

  u64 init_value;
  u64 final_value;

  struct runtime_pa_params pa_params;
  struct runtime_va_params_t params = create_args.params;

  init_value = sbi_timer_value();
  
  /* Runtime parameters */
  if(!is_create_args_valid(&create_args))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  /* set va params */
  pa_params.dram_base = base;
  pa_params.dram_size = size;
  pa_params.runtime_base = create_args.runtime_paddr;
  pa_params.user_base = create_args.user_paddr;
  pa_params.free_base = create_args.free_paddr;

  // allocate eid
  ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto error;

  // create a PMP region bound to the enclave
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  if(pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
    goto free_encl_idx;

  // create PMP region for shared memory
  if(pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0))
    goto free_region;

  // set pmp registers for private region (not shared)
  if(pmp_set_global(region, PMP_NO_PERM))
    goto free_shared_region;

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);

  // initialize enclave metadata
  enclaves[eid].eid = eid;

  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;
#if __riscv_xlen == 32
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = params;
  enclaves[eid].pa_params = pa_params;

  /* Init enclave state (regs etc) */
  clean_state(&enclaves[eid].threads[0]);

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(&enclaves[eid]);

  if (ret)
    goto unset_region;

  /* Validate memory, prepare hash and signature for attestation */
  spin_lock(&encl_lock); // FIXME This should error for second enter.
 
  ret = validate_and_hash_enclave(&enclaves[eid]);

  if(enclaves[eid].crt_local_att_der_length > 0){
    sbi_printf("\n[SM] Enclave certificate already present...skipping to the run\n");
    } else {
    sha3_init(&hash_ctx_to_use, 64);
    sha3_update(&hash_ctx_to_use, CDI, 64);
    sha3_update(&hash_ctx_to_use, enclaves[eid].hash, 64);
    sha3_final(enclaves[eid].CDI, &hash_ctx_to_use);
   
    shake256_init_prng_from_seed(&rng, enclaves[eid].CDI, 32);

    if(falcon_keygen_make(&rng, logn_test, enclaves[eid].local_att_priv, FALCON_PRIVKEY_SIZE(logn_test), enclaves[eid].local_att_pub, FALCON_PUBKEY_SIZE(logn_test), tmp, FALCON_TMPSIZE_KEYGEN(logn_test)) != 0)
      {
        sbi_printf("\n[SM] Error during PQ keypair generation\n");
        goto unlock;
      }

    // Associated to the local attestation keys of the enclaves, a new 509 cert is created 
    mbedtls_x509write_crt_init(&enclaves[eid].crt_local_att);
    
    if(mbedtls_x509write_crt_set_issuer_name_mod(&enclaves[eid].crt_local_att, "CN=Security Monitor")){
      sbi_printf("\n[SM] Error setting issuer certificate name\n");
      goto unlock;
    }
    
    if(mbedtls_x509write_crt_set_subject_name_mod(&enclaves[eid].crt_local_att, "CN=Enclave" )){
      sbi_printf("\n[SM] Error setting subject certificate name\n");
      goto unlock;
    }

    //mbedtls_pk_context subj_key;
    
    mbedtls_pk_init(&enclaves[eid].subj_key);

    //mbedtls_pk_context issu_key;
    
    mbedtls_pk_init(&enclaves[eid].issu_key);
    
    if(mbedtls_pk_parse_public_key(&enclaves[eid].issu_key, ECASM_priv, FALCON_512_SK_SIZE, 1)){
      sbi_printf("\n[SM] Error parsing issuer private key\n");
      goto unlock;
    }

    if(mbedtls_pk_parse_public_key(&enclaves[eid].issu_key, ECASM_pk, FALCON_512_PK_SIZE, 0)){
      sbi_printf("\n[SM] Error parsing issuer public key\n");
      goto unlock;
    }
    
    if(mbedtls_pk_parse_public_key(&enclaves[eid].subj_key, enclaves[eid].local_att_pub, FALCON_512_PK_SIZE, 0)){
      sbi_printf("\n[SM] Error parsing subject public key\n");
      goto unlock;
    }

    serial[0] = eid;

    mbedtls_x509write_crt_set_subject_key(&enclaves[eid].crt_local_att, &enclaves[eid].subj_key);
    
    mbedtls_x509write_crt_set_issuer_key(&enclaves[eid].crt_local_att, &enclaves[eid].issu_key);

    mbedtls_x509write_crt_set_serial_raw(&enclaves[eid].crt_local_att, serial, 1);

    mbedtls_x509write_crt_set_md_alg(&enclaves[eid].crt_local_att, KEYSTONE_SHA3);

    if(mbedtls_x509write_crt_set_validity(&enclaves[eid].crt_local_att, "20230101000000", "20250101000000"))
      goto unlock;

    init_dice_tcbInfo(&tcbInfo);

    m.oid_len = 10;
    
    my_memcpy(m.OID_algho, OID_algo, m.oid_len);
    my_memcpy(m.digest, enclaves[eid].hash, 64);

    set_dice_tcbInfo_measure(&tcbInfo, m);

    if(mbedtls_x509write_crt_set_dice_tcbInfo(&enclaves[eid].crt_local_att, tcbInfo, 324, tmp, sizeof(tmp))!=0){
      sbi_printf("\n[SM] Error setting DICETCB extension!\n");
      goto unlock;
    }
      
    //sbi_memset(tmp, 0, FALCON_TMPSIZE_SIGNDYN(logn_test));

    //unsigned char cert_der[2700];
    int effe_len_cert_der = 0;

    if((effe_len_cert_der = mbedtls_x509write_crt_der_tmp(&enclaves[eid].crt_local_att, enclaves[eid].cert_der, 2100, NULL, tmp,  &rng, sign_tmp)) <= 0){
      sbi_printf("\n[SM] Error writing certificate in DER format: %d\n", effe_len_cert_der);
        goto unlock;
    }

    //my_memset(tmp, 0, FALCON_TMPSIZE_SIGNDYN(logn_test));
    
    unsigned char *cert_real = enclaves[eid].cert_der;
    int dif  = 0;
    dif= 2100-effe_len_cert_der;
    cert_real += dif;
    
    enclaves[eid].crt_local_att_der_length = effe_len_cert_der;
    my_memcpy(enclaves[eid].crt_local_att_der, cert_real, effe_len_cert_der);
    //enclaves[eid].n_keypair = 0;
      base64_encode(enclaves[eid].local_att_pub, FALCON_512_PK_SIZE, 0);
      base64_encode(enclaves[eid].crt_local_att_der, effe_len_cert_der, 1); 
  }
  /* The enclave is fresh if it has been validated and hashed but not run yet. */
  if (ret)
    goto unlock;

  enclaves[eid].state = FRESH;

  final_value = sbi_timer_value();
  sbi_printf("Ticks needed for the creation of the enclave: %ld\n", final_value - init_value);

  /* EIDs are unsigned int in size, copy via simple copy */
  *eidptr = eid;
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;

unlock:
  spin_unlock(&encl_lock);
// free_platform:
  platform_destroy_enclave(&enclaves[eid]);
unset_region:
  pmp_unset_global(region);
free_shared_region:
  pmp_region_free_atomic(shared_region);
free_region:
  pmp_region_free_atomic(region);
free_encl_idx:
  encl_free_eid(eid);
error:
  return ret;
}

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
unsigned long destroy_enclave(enclave_id eid)
{
  int destroyable;
  spin_lock(&encl_lock);
  destroyable = (ENCLAVE_EXISTS(eid)
                 && enclaves[eid].state <= STOPPED);
  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if(destroyable)
    enclaves[eid].state = DESTROYING;
  spin_unlock(&encl_lock);
  if(!destroyable)
    return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;


  // 0. Let the platform specifics do cleanup/modifications
  platform_destroy_enclave(&enclaves[eid]);


  // 1. clear all the data in the enclave pages
  // requires no lock (single runner)
  int i;
  void* base;
  size_t size;
  region_id rid;
  for(i = 0; i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == REGION_INVALID ||
       enclaves[eid].regions[i].type == REGION_UTM)
      continue;
    //1.a Clear all pages
    rid = enclaves[eid].regions[i].pmp_rid;
    base = (void*) pmp_region_get_addr(rid);
    size = (size_t) pmp_region_get_size(rid);
    sbi_memset((void*) base, 0, size);
    //1.b free pmp region
    pmp_unset_global(rid);
    pmp_region_free_atomic(rid);
  }

  // 2. free pmp region for UTM
  rid = get_enclave_region_index(eid, REGION_UTM);
  if(rid != -1)
    pmp_region_free_atomic(enclaves[eid].regions[rid].pmp_rid);

  enclaves[eid].encl_satp = 0;
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = (struct runtime_va_params_t) {0};
  enclaves[eid].pa_params = (struct runtime_pa_params) {0};
  for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
    enclaves[eid].regions[i].type = REGION_INVALID;
  }
  
  // 3. release eid
  encl_free_eid(eid);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int runable;

  spin_lock(&encl_lock);
  runable = (ENCLAVE_EXISTS(eid)
            && enclaves[eid].state == FRESH);
  if(runable) {
    enclaves[eid].state = RUNNING;
    enclaves[eid].n_thread++;
  }
  spin_unlock(&encl_lock);

  if(!runable) {
    return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
  }

  // Enclave is OK to run, context switch to it
  context_switch_to_enclave(regs, eid, 1);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int exitable;

  spin_lock(&encl_lock);
  exitable = enclaves[eid].state == RUNNING;
  if (exitable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!exitable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid)
{
  int stoppable;

  spin_lock(&encl_lock);
  stoppable = enclaves[eid].state == RUNNING;
  if (stoppable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!stoppable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, request == STOP_EDGE_CALL_HOST);

  switch(request) {
    case(STOP_TIMER_INTERRUPT):
      return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
    case(STOP_EDGE_CALL_HOST):
      return SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
    default:
      return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
  }
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int resumable;

  spin_lock(&encl_lock);
  resumable = (ENCLAVE_EXISTS(eid)
               && (enclaves[eid].state == RUNNING || enclaves[eid].state == STOPPED)
               && enclaves[eid].n_thread < MAX_ENCL_THREADS);

  if(!resumable) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
  } else {
    enclaves[eid].n_thread++;
    enclaves[eid].state = RUNNING;
  }
  spin_unlock(&encl_lock);

  // Enclave is OK to resume, context switch to it
  context_switch_to_enclave(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data, uintptr_t size, enclave_id eid) //buffer, nonce, retdata.size
{
  int attestable;
  int ret;

  if (size > ATTEST_DATA_MAXLEN)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  
  spin_lock(&encl_lock);
  attestable = (ENCLAVE_EXISTS(eid)
                && (enclaves[eid].state >= FRESH));

  if(!attestable) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
    goto err_unlock;
  }

  /* copy data to be signed */
  ret = copy_enclave_data(&enclaves[eid], report.enclave.data,
      data, size);
  report.enclave.data_len = size;

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto err_unlock;
  }

  spin_unlock(&encl_lock); // Don't need to wait while signing, which might take some time
  //if (my_strncmp(report.enclave.hash, enclaves[eid].hash, MDSIZE) == 0)
  //{
    my_memcpy(report.dev_public_key, dev_public_key, FALCON_512_PK_SIZE);
    my_memcpy(report.sm.hash, sm_hash, MDSIZE);
    my_memcpy(report.sm.public_key, sm_public_key, FALCON_512_PK_SIZE);
    my_memcpy(report.sm.signature, sm_signature, FALCON_512_SIG_SIZE);
    my_memcpy(report.enclave.hash, enclaves[eid].hash, MDSIZE);

    sm_sign(report.enclave.signature,
        &report.enclave,
        MDSIZE 
        + sizeof(uint64_t) 
        + report.enclave.data_len);
  /*} else {
    sbi_printf("\n[SM] report for attestation already computed\n");
  }*/

  spin_lock(&encl_lock);

  /* copy report to the enclave */
  ret = copy_enclave_report(&enclaves[eid],
       report_ptr,
      &report);
  
  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto err_unlock;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

err_unlock:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                                 size_t key_ident_size, enclave_id eid)
{
  struct sealing_key *key_struct = (struct sealing_key *)sealing_key;
  int ret;


  /* derive key */
  ret = sm_derive_sealing_key((unsigned char *)key_struct->key,
                              (const unsigned char *)key_ident, key_ident_size,
                              (const unsigned char *)enclaves[eid].hash);
  if (ret)
    return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

  /* sign derived key */
  sm_sign((void *)key_struct->signature, (void *)key_struct->key,
          SEALING_KEY_SIZE);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}
/*
unsigned long create_keypair(enclave_id eid, unsigned char* pk, int seed_enc){

  unsigned char seed[PRIVATE_KEY_SIZE];
  unsigned char pk_app[FALCON_512_PK_SIZE]; //pqc
  unsigned char sk_app[FALCON_512_SK_SIZE]; //pqc
  int logn_test = 9;
  //tmp buffer to store intermediate values in the key generation process
  unsigned int falcon_tmpkeygen_size_test = FALCON_TMPSIZE_KEYGEN(logn_test);
  //byte tmp[falcon_tmpkeygen_size_test];
  unsigned char app[65];

  // The new keypair is obtained adding at the end of the CDI of the enclave an index, provided by the enclave itself
  my_memcpy(app, enclaves[eid].CDI, 64);
  app[64] = seed_enc + '0';
  

  sha3_ctx_t ctx_hash;
  shake256_context rng;
  // The hash function is used to provide the seed for the keys generation
  sha3_init(&ctx_hash, 64);
  sha3_update(&ctx_hash, app, 65);
  sha3_final(seed, &ctx_hash);

  shake256_init_prng_from_seed(&rng, seed, 64);

  falcon_keygen_make(&rng, logn_test, sk_app, FALCON_PRIVKEY_SIZE(logn_test), pk_app, FALCON_PUBKEY_SIZE(logn_test),tmp,falcon_tmpkeygen_size_test);
  
  //ed25519_create_keypair(pk_app, sk_app, seed); //pqc
  if(enclaves[eid].n_keypair == 0){
    my_memcpy(enclaves[eid].sk_ldev, sk_app, FALCON_512_SK_SIZE ); //PRIVATE_KEY_SIZE
    my_memcpy(enclaves[eid].pk_ldev, pk_app, FALCON_512_PK_SIZE); //PUBLIC_KEY_SIZE
  } else{
  // The new keypair is stored in the relatives arrays
  //for(int i = 0; i < FALCON_512_PK_SIZE; i ++) //PUBLIC_KEY_SIZE
    //enclaves[eid].pk_array[enclaves[eid].n_keypair][i] = pk_app[i];
  my_memcpy(enclaves[eid].pk_array[enclaves[eid].n_keypair] + enclaves[eid].n_keypair*FALCON_512_PK_SIZE, pk_app, FALCON_512_PK_SIZE);
  //for(int i = 0; i < FALCON_512_SK_SIZE; i ++) //PRIVATE_KEY_SIZE
    //enclaves[eid].sk_array[enclaves[eid].n_keypair][i] = sk_app[i];
  my_memcpy(enclaves[eid].sk_array[enclaves[eid].n_keypair] + enclaves[eid].n_keypair*FALCON_512_SK_SIZE, sk_app, FALCON_512_SK_SIZE);
  // The first keypair that is asked to be created is the Local Device Keys, that is inserted in the relative variables
  }
  enclaves[eid].n_keypair +=1;
  
  my_memcpy(pk, pk_app, FALCON_512_PK_SIZE); //PUBLIC_KEY_SIZE

  // The location in memoty of the private key of the keypair created is clean
  my_memset(sk_app, 0, FALCON_512_SK_SIZE); //64

  return 0;
}

unsigned long get_cert_chain(unsigned char** certs, unsigned char* sizes){

  // Providing the X509 cert in der format of the ECA and its length
  my_memcpy(certs[0], cert_sm, length_cert);
  sizes[0] = length_cert;

  // Providing the X509 cert in der format of the Device Root Key and its length
  my_memcpy(certs[1], cert_root, length_cert_root);
  sizes[1] = length_cert_root;

  // Providing the X509 cert in der format of the manufacturer key and its length
  my_memcpy(certs[2], cert_man, length_cert_man);
  sizes[2] = length_cert_man;

  return 0;
}

unsigned long do_crypto_op(enclave_id eid, int flag, unsigned char* data, int data_len, unsigned char* out_data, int* len_out_data, unsigned char* pk){

  sha3_ctx_t ctx_hash;
  unsigned char fin_hash[64];
  unsigned char sign[FALCON_512_SIG_SIZE];
  int pos = -1;
  int logn_test = 9;
  //tmp buffer to store intermediate values in the signature process
  unsigned int falcon_tmpsign_size_test = FALCON_TMPSIZE_SIGNDYN(logn_test);
  //byte tmp_sig[falcon_tmpsign_size_test];
  size_t sig_len;

  byte seed[32];
  shake256_context rng;
  for (int i = 0; i < 32; ++i)
  {
    seed[i] = 0xac + (0xdd ^ i);
  }

  shake256_init_prng_from_seed(&rng, seed, 32);

  switch (flag){
    // Sign of TCI|pk_lDev with the private key of the attestation keypair of the enclave.
    // The sign is placed in out_data. The attestation pk can be obtained calling the get_chain_cert method
    case 1:
      sha3_init(&ctx_hash, 64);
      sha3_update(&ctx_hash, enclaves[eid].hash, 64);
      sha3_update(&ctx_hash, enclaves[eid].pk_ldev, FALCON_512_PK_SIZE); //32
      sha3_final(fin_hash, &ctx_hash);

      //ed25519_sign(sign, fin_hash, 64, enclaves[eid].local_att_pub, enclaves[eid].local_att_priv);
      falcon_sign_dyn(&rng, sign, &sig_len, FALCON_SIG_CT, ECASM_priv, FALCON_PRIVKEY_SIZE(logn_test), fin_hash, 64, tmp, falcon_tmpsign_size_test);
      //ed25519_sign(sign, fin_hash, 64, ECASM_pk, ECASM_priv);
      
      my_memcpy(out_data, sign, sig_len);
      *len_out_data = sig_len;
      return 0;
    break;

    case 2:
      // Sign of generic data with a specific private key.
      // In this case the enclave provides directly the hash of the data that have to be signed

      // Finding the private key associated to the public key passed
      for(int i = 0;  i < enclaves[eid].n_keypair; i ++)
        if(my_memcmp(enclaves[eid].pk_array[i], pk, FALCON_512_PK_SIZE) == 0){
          pos = i;
          break;
        }
      if (pos == -1)
        return -1;

      //ed25519_sign(sign, data, data_len, enclaves[eid].pk_array[pos], enclaves[eid].sk_array[pos]);
      falcon_sign_dyn(&rng, sign, &sig_len, FALCON_SIG_CT, enclaves[eid].sk_array[pos], FALCON_PRIVKEY_SIZE(logn_test), data, data_len, sign_tmp, falcon_tmpsign_size_test);

      // Providing the signature
      my_memcpy(out_data, sign, sig_len);
      *len_out_data = sig_len;
      return 0;
    break;
    
    default:
      return -1;
    break;
  }
  return 0;
}
*/
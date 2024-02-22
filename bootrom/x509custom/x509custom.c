#ifdef __STRING_H__
#include "string.h"
#endif
#include "x509custom.h"
#include "falcon512/falcon.h"
#include "sha3/sha3.h"


const x509_attr_descriptor_t *x509_attr_descr_from_name(const char *name, size_t name_len)
{
    const x509_attr_descriptor_t *cur;

    for (cur = x509_attrs; cur->name != NULL; cur++) {
        if (cur->name_len == name_len &&
            strncmp(cur->name, name, name_len) == 0) {
            break;
        }
    }
    if (cur->name == NULL) {
        return NULL;
    }

    return cur;
}

//FALCON
size_t falcon_get_bitlen()
{
    //pub key size returned in bits
    return 8 * FALCON_PUBKEY_SIZE(LOGN_PARAM);
}

//FALCON
int falcon_can_do(mbedtls_pk_type_t type)
{   
    #if LOGN_PARAM == 9
        return type == MBEDTLS_PK_FALCON512;
    #else
        return type = MBEDTLS_PK_FALCON1024;
    #endif
}

//FALCON
void mbedtls_falcon_init(mbedtls_falcon_context *ctx)
{
    /*
    *
    */
}

//FALCON
void falcon_free_wrap(void *ctx)
{
    mbedtls_falcon_free((mbedtls_falcon_context *) ctx);
}

//FALCON512
int falcon_check_pair_wrap(const void *pub, const void *prv,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng)
{ 
  /**
   * TO BE DONE
   * funzione che a partire da pub prende la coppia di chiavi pubblica privata, il seed contenuto in prv e genera
   * nuovamente la pubblica a partire dalla privata, ritornando 0 se matchano le due pubbliche
  */
    (void) f_rng;
    (void) p_rng;
    return mbedtls_falcon_check_pub_priv(((mbedtls_falcon_context *)pub)->priv_key,
                                      ((mbedtls_falcon_context *)pub)->pub_key,
                                      (unsigned char *)prv);
}

//FALCON
int falcon_encrypt_wrap(void *ctx,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
  /**
   * 
   * TO BE DONE
   * 
   * 
  */
    return 0;
}

//FALCON
 int falcon_decrypt_wrap(void *ctx,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
 {

    /**
     * TO BE DONE
     * 
     * 
    */
    return 0;
}

//FALCON
int mbedtls_falcon_write_signature_restartable(mbedtls_falcon_context *ctx,
                                              const unsigned char *hash, size_t hlen,
                                              unsigned char *sig, size_t sig_size, size_t *slen)
{   
  shake256_context rng;  
  byte seed_test[5] = {0x01, 0x01, 0x01, 0x01, 0x01};
  shake256_init_prng_from_seed(&rng, seed_test, 5);
  unsigned int falcon_tmpsign_size_test = FALCON_TMPSIZE_SIGNDYN(LOGN_PARAM);
  byte tmp_sig[falcon_tmpsign_size_test];
    
  falcon_sign_dyn(&rng, sig, &sig_size, FALCON_SIG_CT, ctx->priv_key, FALCON_PRIVKEY_SIZE(LOGN_PARAM), hash, sizeof(hash), tmp_sig, falcon_tmpsign_size_test);
  *slen = sig_size;
  return 0;

}

//FALCON
int mbedtls_falcon_write_signature(mbedtls_falcon_context *ctx,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen)
{
    return mbedtls_falcon_write_signature_restartable(
        ctx, hash, hlen, sig, sig_size, slen);
}

//FALCON
int falcon_sign_wrap(void *ctx, mbedtls_md_type_t md_alg,
                     const unsigned char *hash, size_t hash_len,
                     unsigned char *sig, size_t sig_size, size_t *sig_len,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng)
{   
    return mbedtls_falcon_write_signature((mbedtls_falcon_context *) ctx,
                                         hash, hash_len,
                                         sig, sig_size, sig_len);
}

//FALCON
int falcon_verify_wrap(void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len)
{
    mbedtls_falcon_context *falcon = (mbedtls_falcon_context *) ctx;
    byte tmp[FALCON_TMPSIZE_VERIFY(LOGN_PARAM)];
    return falcon_verify(sig, sig_len, FALCON_SIG_CT, falcon->pub_key, FALCON_PUBKEY_SIZE(LOGN_PARAM), hash, sizeof(hash), tmp, FALCON_TMPSIZE_VERIFY(LOGN_PARAM));
}
    

//FALCON
const mbedtls_pk_info_t mbedtls_falcon_info = {
    #if LOGN_PARAM == 9
        MBEDTLS_PK_FALCON512,
        "FALCON512",
    #else
        MBEDTLS_PK_FALCON1024,
        "FALCON1024",
    #endif
    falcon_get_bitlen,
    falcon_can_do,
    falcon_verify_wrap,
    falcon_sign_wrap,
    falcon_decrypt_wrap,
    falcon_encrypt_wrap,
    falcon_check_pair_wrap,
    falcon_free_wrap,
};

void mbedtls_x509write_crt_init(mbedtls_x509write_cert *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_x509write_cert));
    ctx->version = MBEDTLS_X509_CRT_VERSION_3;
    
}

void mbedtls_asn1_free_named_data_list_mod(int *ne)
{
    *ne = 0;
}

mbedtls_asn1_named_data *asn1_find_named_data(mbedtls_asn1_named_data *list,const char *oid, size_t len)
{
    while (list != NULL) {
        if (list->oid.len == len &&
            memcmp(list->oid.p, oid, len) == 0) {
            break;
        }

        list = list->next;
    }

    return list;
}

void mbedtls_x509write_crt_set_subject_key(mbedtls_x509write_cert *ctx, mbedtls_pk_context *key){
                
    ctx->subject_key = key;
}

void mbedtls_x509write_crt_set_issuer_key(mbedtls_x509write_cert *ctx, mbedtls_pk_context *key)
{
    ctx->issuer_key = key;
}

const mbedtls_pk_info_t *mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type)
{
    switch (pk_type) {
        case MBEDTLS_PK_FALCON512:
            return &mbedtls_falcon_info;
        case MBEDTLS_PK_FALCON1024:
            return &mbedtls_falcon_info;
        default:
            return NULL;
    }
}

int mbedtls_pk_setup(mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info)
{   
    ctx->pk_info = info;
    return 0;
}


mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context *ctx)
{   
    return ctx->pk_info->type;
}

//FALCON
int pk_set_falconpubkey(unsigned char **p, mbedtls_falcon_context *falcon){

    int len = FALCON_PUBKEY_SIZE(LOGN_PARAM);
    /*
    for(int i = 0; i < len; i++){
        falcon->pub_key[i] = (*p)[i];
    } 
    */
    memcpy(falcon->pub_key, *p, len);
    falcon->len = len;
    return 0;

}

//FALCON
int pk_get_falconpubkey(unsigned char **p, mbedtls_falcon_context *falcon){

    int len = FALCON_PUBKEY_SIZE(LOGN_PARAM);
    /*
    for(int i = 0; i < len; i++){
        falcon->pub_key[i] = (*p)[i];
    }
    */
    memcpy(falcon->pub_key, *p, len);
    falcon->len = len;
    return 0;
}

//FALCON
int pk_set_falconprivkey(unsigned char **p, mbedtls_falcon_context *falcon){

   int len = FALCON_PRIVKEY_SIZE(LOGN_PARAM);
    /*for(int i = 0; i < len; i++){
        falcon->priv_key[i] = (*p)[i];
    } */
    memcpy(falcon->priv_key, *p, len);
    falcon->len = len;
    return 0;

}

//falcon
int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx, const unsigned char *key, size_t keylen, int type_k){
    
    unsigned char *p;
    const mbedtls_pk_info_t *pk_info;
    #if LOGN_PARAM == 9
        if ((pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_FALCON512)) == NULL ) {
            return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
        }
    #else
        if ((pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_FALCON1024)) == NULL ) {
            return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
        }
    #endif
    ctx->pk_info = pk_info;

    p = (unsigned char *) key;
    
    if(type_k == 0){
        pk_set_falconpubkey(&p, &ctx->pk_ctx );//mbedtls_pk_falcon(*ctx));
     } else
        pk_set_falconprivkey(&p,&ctx->pk_ctx);//mbedtls_pk_falcon(*ctx);
    return 0;
}

int mbedtls_x509write_crt_set_validity(mbedtls_x509write_cert *ctx, const char *not_before, const char *not_after){
   
    if (strlen(not_before) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 ||
        strlen(not_after)  != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    strncpy(ctx->not_before, not_before, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    strncpy(ctx->not_after, not_after, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    ctx->not_before[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
    ctx->not_after[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

    return 0;
}

void mbedtls_pk_init(mbedtls_pk_context *ctx){
    ctx->pk_info = NULL;
}

//FALCON
void mbedtls_falcon_free(mbedtls_falcon_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
}

//FALCON512
int mbedtls_falcon_check_pub_priv(unsigned char* priv, unsigned char* pub, unsigned char* seed){
  //TODO
  unsigned char result[32]; 
  //create a keypair
  for(int i = 0; i < 32; i++){
    if (result[i] != pub[i])
      return 1;
  }
  return 0;

}

int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng){
    
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const char *sig_oid = NULL;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char sig[FALCON_SIG_CT_SIZE(LOGN_PARAM)];
    unsigned char hash[64];

    size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    mbedtls_pk_type_t pk_alg;

    sha3_ctx_t hash_ctx;

    /*
     * Prepare data to be signed at the end of the target buffer
     */

    //buf punta alla prima locazione di memoria del buffer,
    //se gli aggiungo la sua dimensione, ovvero size
    //il risultato sarà un puntatore alla fine del buffer, ovvero c
    c = buf + size;
    #if LOGN_PARAM == 9
        pk_alg = MBEDTLS_PK_FALCON512;
    #else
        pk_alg = MBEDTLS_PK_FALCON1024;
    #endif
    //    id-Falcon512   OBJECT IDENTIFIER ::= { 1 6 9999 3 6 }
    //    id-Falcon1024   OBJECT IDENTIFIER ::= { 1 6 9999 3 9 }
    mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg, &sig_oid, &sig_oid_len);
    /*
     *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */
    /* Only for v3 */
    
    if (ctx->version == MBEDTLS_X509_CRT_VERSION_3) {
        //MBEDTLS_ASN1_CHK_ADD(len,
          //                   mbedtls_x509_write_extensions(&c,
            //                                               buf, ctx->extensions));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_x509_write_extensions_mod(&c,
                                                           buf, ctx->extens_arr, ctx->ne_ext_arr));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(&c, buf,
                                                    MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(&c, buf,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 3));
    }
    /*
     *  SubjectPublicKeyInfo
     */
    MBEDTLS_ASN1_CHK_ADD(pub_len,
                         mbedtls_pk_write_pubkey_der(ctx->subject_key,
                                                     buf, c - buf));
    //il puntatore a dove si deve scrivere viene spostato della dimensione che occupa
    //la codifica della chiave pubblica in ASN1
    c -= pub_len;
    len += pub_len;
     /*
     *  Subject  ::=  Name
     */
    /*
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_x509_write_names(&c, buf,
                                                  ctx->subject));
                                    */
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_x509_write_names_mod(&c, buf,
                                                  ctx->subject_arr, ctx->ne_subje_arr));
    /*
     *  Validity ::= SEQUENCE {
     *       notBefore      Time,
     *       notAfter       Time }
     */
    sub_len = 0;

    MBEDTLS_ASN1_CHK_ADD(sub_len,
                         x509_write_time(&c, buf, ctx->not_after,
                                         MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

    MBEDTLS_ASN1_CHK_ADD(sub_len,
                         x509_write_time(&c, buf, ctx->not_before,
                                         MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

    len += sub_len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, sub_len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(&c, buf,
                                                MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE));
    /*
     *  Issuer  ::=  Name
     */
    /*
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c, buf,
                                                       ctx->issuer));
                                                       */
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_x509_write_names_mod(&c, buf,
                                                  ctx->issuer_arr, ctx->ne_issue_arr));
    /*
     *  Signature   ::=  AlgorithmIdentifier
     */
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_algorithm_identifier(&c, buf,
                                                                 sig_oid, sig_oid_len, 0));
    /*
     *  Serial   ::=  INTEGER
     *
     * Written data is:
     * - "ctx->serial_len" bytes for the raw serial buffer
     *   - if MSb of "serial" is 1, then prepend an extra 0x00 byte
     * - 1 byte for the length
     * - 1 byte for the TAG
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf,
                                                            ctx->serial, ctx->serial_len));
     if (*c & 0x80) {
        if (c - buf < 1) {
            return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }
        *(--c) = 0x0;
        len++;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf,
                                                         ctx->serial_len + 1));
    } else {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf,
                                                         ctx->serial_len));
    }
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_INTEGER));

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */

    /* Can be omitted for v1 */                                                 
    if (ctx->version != MBEDTLS_X509_CRT_VERSION_1) {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_int(&c, buf, ctx->version));
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_len(&c, buf, sub_len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(&c, buf,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 0));
    }
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE));


    /**
     * 
     * Fase di firma, svolta con le funzioni già presenti in keystone
     * 
     **/

    sha3_init(&hash_ctx, 64);
    sha3_update(&hash_ctx, c, len);
    sha3_final(hash, &hash_ctx);

    shake256_context rng;  
    byte seed_test[5] = {0x01, 0x01, 0x01, 0x01, 0x01};
    shake256_init_prng_from_seed(&rng, seed_test, 5);
    unsigned int falcon_tmpsign_size_test = FALCON_TMPSIZE_SIGNDYN(LOGN_PARAM);
    byte tmp_sig[falcon_tmpsign_size_test];
    //byte sig[FALCON_SIG_CT_SIZE(LOGN_PARAM)];
    size_t sig_len1 = FALCON_SIG_CT_SIZE(LOGN_PARAM);
    
    falcon_sign_dyn(&rng, sig, &sig_len1, FALCON_SIG_CT, ctx->issuer_key->pk_ctx.priv_key, FALCON_PRIVKEY_SIZE(LOGN_PARAM), hash, 64, tmp_sig, falcon_tmpsign_size_test);
    sig_len = sig_len1;
    
    /* Move CRT to the front of the buffer to have space
     * for the signature. */
    memmove(buf, c, len);//in buf there is the pointer to the beginning of the cert
    c = buf + len;

    /* Add signature at the end of the buffer,
     * making sure that it doesn't underflow
     * into the CRT buffer. */
    c2 = buf + size; //size is the static size of the certificate
    if(sig_oid != NULL){
        MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len, mbedtls_x509_write_sig(&c2, c,
                                                                 sig_oid, sig_oid_len, sig,
                                                                 sig_len));                       
    }
    /*
     * Memory layout after this step:
     *
     * buf       c=buf+len                c2            buf+size
     * [CRT0,...,CRTn, UNUSED, ..., UNUSED, SIG0, ..., SIGm]
     */

    /* Move raw CRT to just before the signature. */
    c = c2 - len;
    memmove(c, buf, len); //c points to the beginning of the signature

    len += sig_and_oid_len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    return (int) len;
}



int mbedtls_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (*p < start || (size_t) (*p - start) < size) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    len = size;
    (*p) -= len;
    memcpy(*p, sig, len);

    if (*p - start < 1) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_BIT_STRING));

    // Write OID
    //
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(p, start, oid,
                                                                      oid_len, 0));

    return (int) len;
}

int mbedtls_pk_sign(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char *sig, size_t sig_size, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return mbedtls_pk_sign_restartable(ctx, md_alg, hash, hash_len,
                                       sig, sig_size, sig_len,
                                       f_rng, p_rng);//, NULL);
}

int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx,
                                mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{   
    
    if ((md_alg != MBEDTLS_MD_NONE || hash_len != 0) && hash == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    if (ctx->pk_info->sign_func == NULL) {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    return ctx->pk_info->sign_func(&(ctx->pk_ctx), md_alg,
                                   hash, hash_len,
                                   sig, sig_size, sig_len,
                                   f_rng, p_rng);
}


int mbedtls_pk_write_pubkey_der(const mbedtls_pk_context *key, unsigned char *buf, size_t size)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    if (size == 0) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bitstring(&c, buf, key->pk_ctx.pub_key, falcon_get_bitlen()));

     if (c - buf < 1) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }
    
    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_BIT_STRING));

    #if LOGN_PARAM == 9
        oid_len = sizeof(MBEDTLS_OID_FALCON512_SHAKE256) - 1;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_falcon_identifier(&c, buf, MBEDTLS_OID_FALCON512_SHAKE256, oid_len));
    #else
        oid_len = sizeof(MBEDTLS_OID_FALCON1024_SHAKE256) - 1;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_falcon_identifier(&c, buf, MBEDTLS_OID_FALCON1024_SHAKE256, oid_len));
    #endif
    
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;



}

int mbedtls_pk_write_pubkey(unsigned char **p, unsigned char *start, const mbedtls_pk_context *key){
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    MBEDTLS_ASN1_CHK_ADD(len, pk_write_falcon_pubkey(p, start, key->pk_ctx));
    return (int) len;
}

int pk_write_falcon_pubkey(unsigned char **p, unsigned char *start, mbedtls_falcon_context falcon){

    //int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = FALCON_PUBKEY_SIZE(LOGN_PARAM);
    unsigned char buf[len];

    for(int i = 0; i < len; i ++){
        buf[i] = falcon.pub_key[i];
    }

    if (*p < start || (size_t) (*p - start) < len) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }
    *p -= len;
    
    memcpy(*p, buf, len);
    return (int) len;

}

int mbedtls_asn1_write_len(unsigned char **p, const unsigned char *start, size_t len){
    
    if (len < 0x80) {
        if (*p - start < 1) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = (unsigned char) len;
        return 1;
    }

    if (len <= 0xFF) {
        if (*p - start < 2) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = (unsigned char) len;
        *--(*p) = 0x81;
        return 2;
    }

    if (len <= 0xFFFF) {
        if (*p - start < 3) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = MBEDTLS_BYTE_0(len);
        *--(*p) = MBEDTLS_BYTE_1(len);
        *--(*p) = 0x82;
        return 3;
    }

    if (len <= 0xFFFFFF) {
        if (*p - start < 4) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = MBEDTLS_BYTE_0(len);
        *--(*p) = MBEDTLS_BYTE_1(len);
        *--(*p) = MBEDTLS_BYTE_2(len);
        *--(*p) = 0x83;
        return 4;
    }

    int len_is_valid = 1;

    if (len_is_valid) {
        if (*p - start < 5) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = MBEDTLS_BYTE_0(len);
        *--(*p) = MBEDTLS_BYTE_1(len);
        *--(*p) = MBEDTLS_BYTE_2(len);
        *--(*p) = MBEDTLS_BYTE_3(len);
        *--(*p) = 0x84;
        return 5;
    }

    return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
}

int mbedtls_asn1_write_tag(unsigned char **p, const unsigned char *start, unsigned char tag)
{
    
    if (*p - start < 1) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }    

    *--(*p) = tag;

    return 1;
}

int mbedtls_asn1_write_algorithm_identifier(unsigned char **p, const unsigned char *start,
                                            const char *oid, size_t oid_len,
                                            size_t par_len){
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (par_len == 0) {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_null(p, start));
    } else {
        len += par_len;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, oid, oid_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

int mbedtls_asn1_write_falcon_identifier(unsigned char **p, const unsigned char *start,
                                            const char *oid, size_t oid_len){
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, oid, oid_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

int mbedtls_asn1_write_null(unsigned char **p, const unsigned char *start)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    // Write NULL
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, 0));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_NULL));

    return (int) len;
}

int mbedtls_asn1_write_oid(unsigned char **p, const unsigned char *start,
                           const char *oid, size_t oid_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
  
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                            (const unsigned char *) oid, oid_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OID));
  
    return (int) len;
}

int mbedtls_asn1_write_raw_buffer(unsigned char **p, const unsigned char *start,
                                  const unsigned char *buf, size_t size)
{
    size_t len = 0;

    if (*p < start || (size_t) (*p - start) < size) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    len = size;
    (*p) -= len;
    memcpy(*p, buf, len);

    return (int) len;
}

int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    mbedtls_asn1_named_data *cur = first;

    while (cur != NULL) {
        MBEDTLS_ASN1_CHK_ADD(len, x509_write_name(p, start, cur));
        cur = cur->next;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

int x509_write_name(unsigned char **p,
                           unsigned char *start,
                           mbedtls_asn1_named_data *cur_name)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const char *oid             = (const char *) cur_name->oid.p;
    size_t oid_len              = cur_name->oid.len;
    const unsigned char *name   = cur_name->val.p;
    size_t name_len             = cur_name->val.len;

    // Write correct string tag and value
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tagged_string(p, start,
                                                               cur_name->val.tag,
                                                               (const char *) name,
                                                               name_len));
    // Write OID
    //
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, oid,
                                                     oid_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SET));

    return (int) len;
}

int mbedtls_asn1_write_tagged_string(unsigned char **p, const unsigned char *start, int tag,
                                     const char *text, size_t text_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                            (const unsigned char *) text,
                                                            text_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, tag));

    return (int) len;
}

int x509_write_time(unsigned char **p, unsigned char *start,
                           const char *t, size_t size)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    /*
     * write MBEDTLS_ASN1_UTC_TIME if year < 2050 (2 bytes shorter)
     */
    if (t[0] < '2' || (t[0] == '2' && t[1] == '0' && t[2] < '5')) {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                                (const unsigned char *) t + 2,
                                                                size - 2));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                         MBEDTLS_ASN1_UTC_TIME));
    } else {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                                (const unsigned char *) t,
                                                                size));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                         MBEDTLS_ASN1_GENERALIZED_TIME));
    }

    return (int) len;
}

int mbedtls_asn1_write_int(unsigned char **p, const unsigned char *start, int val)
{
    return asn1_write_tagged_int(p, start, val, MBEDTLS_ASN1_INTEGER);
}

int asn1_write_tagged_int(unsigned char **p, const unsigned char *start, int val, int tag)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    do {
        if (*p - start < 1) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }
        len += 1;
        *--(*p) = val & 0xff;
        val >>= 8;
    } while (val > 0);

    if (**p & 0x80) {
        if (*p - start < 1) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }
        *--(*p) = 0x00;
        len += 1;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, tag));

    return (int) len;
}

int mbedtls_x509write_crt_set_serial_raw(mbedtls_x509write_cert *ctx,
                                         unsigned char *serial, size_t serial_len)
{
    if (serial_len > MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    ctx->serial_len = serial_len;
    memcpy(ctx->serial, serial, serial_len);

    return 0;
}
void mbedtls_x509write_crt_set_md_alg(mbedtls_x509write_cert *ctx,
                                      mbedtls_md_type_t md_alg)
{
    ctx->md_alg = md_alg;
}

int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain, /*const*/ unsigned char *buf,size_t buflen) //uff cert, cert real, effective cert length der
{
    return mbedtls_x509_crt_parse_der_internal(chain, buf, buflen, 1, NULL, NULL);
}

/*
 * Parse one X.509 certificate in DER format from a buffer and add them to a
 * chained list
 */
int mbedtls_x509_crt_parse_der_internal(mbedtls_x509_crt *chain, /*const*/ unsigned char *buf, size_t buflen, int make_copy,
                                               mbedtls_x509_crt_ext_cb_t cb, void *p_ctx) //uff cert, cert real, effective cert length der
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_x509_crt *crt = chain, *prev = NULL;

    /*
     * Check for valid input
     */
    if (crt == NULL || buf == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    while (crt->version != 0 && crt->next != NULL) {
        prev = crt;
        crt = crt->next;
    }

    /*
     * Add new certificate on the end of the chain if needed.
     */
    ret = x509_crt_parse_der_core(crt, buf, buflen, make_copy, cb, p_ctx); //uff cert, cert real, effective cert length der
    if (ret != 0) {
        if (prev) {
            prev->next = NULL;
        }
        /*
        if (crt != chain) {
            mbedtls_free(crt);
        }
        */
        return ret;
    }
    return 0;
}

void mbedtls_x509_crt_init(mbedtls_x509_crt *crt)
{
    memset(crt, 0, sizeof(mbedtls_x509_crt));
}

/*
 * Parse and fill a single X.509 certificate in DER format
 */
int x509_crt_parse_der_core(mbedtls_x509_crt *crt,
                                   /*const*/ unsigned char *buf,
                                   size_t buflen,
                                   int make_copy,
                                   mbedtls_x509_crt_ext_cb_t cb,
                                   void *p_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *p, *end, *crt_end;
    mbedtls_x509_buf sig_params1, sig_params2, sig_oid2;

    memset(&sig_params1, 0, sizeof(mbedtls_x509_buf));
    memset(&sig_params2, 0, sizeof(mbedtls_x509_buf));
    memset(&sig_oid2, 0, sizeof(mbedtls_x509_buf));

    /*
     * Check for valid input
     */
    if (crt == NULL || buf == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    /* Use the original buffer until we figure out actual length. */
    p = (unsigned char *) buf;
    len = buflen;
    end = p + len;

    /*
     * Certificate  ::=  SEQUENCE  {
     *      tbsCertificate       TBSCertificate,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     */

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        //mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    end = crt_end = p + len;
    crt->raw.len = crt_end - buf;
    if (make_copy != 0) {
        /* Create and populate a new buffer for the raw field. */
        crt->raw.p = buf;
        p = crt->raw.p;
        crt->own_buffer = 1;

        p += crt->raw.len - len;
        end = crt_end = p + len;
    } else {
        crt->raw.p = (unsigned char *) buf;
        crt->own_buffer = 0;
    }
    
    /*
     * TBSCertificate  ::=  SEQUENCE  {
     */
    
    crt->tbs.p = p;
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        //mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }
    end = p + len;
    crt->tbs.len = end - crt->tbs.p;
    
    /*
     * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     *
     * CertificateSerialNumber  ::=  INTEGER
     *
     * signature            AlgorithmIdentifier
     */

    if ((ret = x509_get_version(&p, end, &crt->version)) != 0 ||
        (ret = mbedtls_x509_get_serial(&p, end, &crt->serial)) != 0 ||
        (ret = mbedtls_x509_get_alg(&p, end, &crt->sig_oid,
                                    &sig_params1)) != 0) {
        return ret;
    }

    if (crt->version < 0 || crt->version > 2) {
        return MBEDTLS_ERR_X509_UNKNOWN_VERSION;
    }

    crt->version++;

    if ((ret = mbedtls_x509_get_sig_alg_mod(&crt->sig_oid, &sig_params1,
                                        &crt->sig_md, &crt->sig_pk,
                                        &crt->sig_opts)) != 0) {
        return ret;
    }

    /*
     * issuer               Name
     */
    crt->issuer_raw.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }
    
    if ((ret = mbedtls_x509_get_name_mod(&p, p + len, crt->issuer_arr, &crt->ne_issue_arr)) != 0) {
        return ret;
    }

    crt->issuer_raw.len = p - crt->issuer_raw.p;

    /*
     * Validity ::= SEQUENCE {
     *      notBefore      Time,
     *      notAfter       Time }
     *
     */
    if ((ret = x509_get_dates(&p, end, &crt->valid_from,
                              &crt->valid_to)) != 0) {
        return ret;
    }

    /*
     * subject              Name
     */
    crt->subject_raw.p = p;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    if (len && (ret = mbedtls_x509_get_name_mod(&p, p + len, crt->subject_arr, &crt->ne_subje_arr)) != 0) {
        return ret;
    }

    crt->subject_raw.len = p - crt->subject_raw.p;

    /*
     * SubjectPublicKeyInfo
     */
    crt->pk_raw.p = p;
    if ((ret = mbedtls_pk_parse_subpubkey(&p, end, &crt->pk)) != 0) {
        return ret;
    }
    crt->pk_raw.len = p - crt->pk_raw.p;

    /*
     *  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                       -- If present, version shall be v3
     */
    
    if (crt->version == 2 || crt->version == 3) {
        ret = x509_get_uid(&p, end, &crt->issuer_id,  1);
        if (ret != 0) {
            return ret;
        }
    }

    if (crt->version == 2 || crt->version == 3) {
        ret = x509_get_uid(&p, end, &crt->subject_id,  2);
        if (ret != 0) {
            return ret;
        }
    }
    
    if (crt->version == 3) {
        ret = x509_get_crt_ext(&p, end, crt, cb, p_ctx);
        if (ret != 0) {
            return ret;
        }
    }
    
    if (p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    
    /*
     *  }
     *  -- end of TBSCertificate
     *
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signatureValue       BIT STRING
     */
     end = crt_end;
    
    if ((ret = mbedtls_x509_get_alg_mod(&p, end, &sig_oid2, &sig_params2)) != 0) {
        return ret;
    }

    if (crt->sig_oid.len != sig_oid2.len ||
        memcmp(crt->sig_oid.p, sig_oid2.p, crt->sig_oid.len) != 0 ||
        sig_params1.tag != sig_params2.tag ||
        sig_params1.len != sig_params2.len ||
        (sig_params1.len != 0 &&
        memcmp(sig_params1.p, sig_params2.p, sig_params1.len) != 0)) {
        return MBEDTLS_ERR_X509_SIG_MISMATCH;
    }

    if ((ret = mbedtls_x509_get_sig(&p, end, &crt->sig)) != 0) {
        return ret;
    }

    if (p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

int mbedtls_asn1_get_tag(unsigned char **p,
                         const unsigned char *end,
                         size_t *len, int tag)
{

    if ((end - *p) < 1) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    if (**p != tag) {
        return MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
    }

    (*p)++;

    return mbedtls_asn1_get_len(p, end, len);
}

/*
 * ASN.1 DER decoding routines
 */
int mbedtls_asn1_get_len(unsigned char **p,
                         const unsigned char *end,
                         size_t *len)
{
    if ((end - *p) < 1) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    if ((**p & 0x80) == 0) {
        *len = *(*p)++;
    } else {
        switch (**p & 0x7F) {
            case 1:
                if ((end - *p) < 2) {
                    return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
                }

                *len = (*p)[1];
                (*p) += 2;
                break;

            case 2:
                if ((end - *p) < 3) {
                    return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
                }

                *len = ((size_t) (*p)[1] << 8) | (*p)[2];
                (*p) += 3;
                break;

            case 3:
                if ((end - *p) < 4) {
                    return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
                }

                *len = ((size_t) (*p)[1] << 16) |
                       ((size_t) (*p)[2] << 8) | (*p)[3];
                (*p) += 4;
                break;

            case 4:
                if ((end - *p) < 5) {
                    return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
                }

                *len = ((size_t) (*p)[1] << 24) | ((size_t) (*p)[2] << 16) |
                       ((size_t) (*p)[3] << 8) |           (*p)[4];
                (*p) += 5;
                break;

            default:
                return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
        }
    }

    if (*len > (size_t) (end - *p)) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    return 0;
}

void mbedtls_pk_free(mbedtls_pk_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->pk_info != NULL) {
        return;
        //ctx->pk_info->ctx_free_func(&(ctx->pk_ctx));
    }
}

int x509_get_version(unsigned char **p,
                            const unsigned char *end,
                            int *ver)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED |
                                    0)) != 0) {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            *ver = 0;
            return 0;
        }

        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    end = *p + len;

    if ((ret = mbedtls_asn1_get_int(p, end, ver)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_VERSION, ret);
    }

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_VERSION,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

int mbedtls_x509_get_serial(unsigned char **p, const unsigned char *end,
                            mbedtls_x509_buf_crt *serial)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((end - *p) < 1) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SERIAL,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    if (**p != (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_PRIMITIVE | 2) &&
        **p !=   MBEDTLS_ASN1_INTEGER) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SERIAL,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }

    serial->tag = *(*p)++;

    if ((ret = mbedtls_asn1_get_len(p, end, &serial->len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SERIAL, ret);
    }

    serial->p = *p;
    *p += serial->len;

    return 0;
}

int mbedtls_x509_get_alg(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf_crt *alg, mbedtls_x509_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_asn1_get_alg_mod(p, end, alg, params)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_ALG, ret);
    }

    return 0;
}

int mbedtls_x509_get_alg_mod(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *alg, mbedtls_x509_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_asn1_get_alg(p, end, alg, params)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_ALG, ret);
    }

    return 0;
}


int mbedtls_asn1_get_alg_mod(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_asn1_buf_no_arr *alg, mbedtls_asn1_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    if ((end - *p) < 1) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    alg->tag = **p;
    end = *p + len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &alg->len, MBEDTLS_ASN1_OID)) != 0) {
        return ret;
    }

    alg->p = *p;
    *p += alg->len;

    if (*p == end) {
        //mbedtls_platform_zeroize(params, sizeof(mbedtls_asn1_buf));
        return 0;
    }

    params->tag = **p;
    (*p)++;

    if ((ret = mbedtls_asn1_get_len(p, end, &params->len)) != 0) {
        return ret;
    }

    params->p = *p;
    *p += params->len;

    if (*p != end) {
        return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    return 0;
}


//FALCON
int mbedtls_asn1_get_alg_falcon(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_asn1_buf *alg)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    if ((end - *p) < 1) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    alg->tag = **p;
    end = *p + len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &alg->len, MBEDTLS_ASN1_OID)) != 0) {
        return ret;
    }

    alg->p = *p;
    *p += alg->len;

    if (*p != end) {
        return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    return 0;
}


int mbedtls_asn1_get_alg(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_asn1_buf *alg, mbedtls_asn1_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    if ((end - *p) < 1) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    alg->tag = **p;
    end = *p + len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &alg->len, MBEDTLS_ASN1_OID)) != 0) {
        return ret;
    }

    alg->p = *p;
    *p += alg->len;

    if (*p == end) {
        //mbedtls_platform_zeroize(params, sizeof(mbedtls_asn1_buf));
        return 0;
    }

    params->tag = **p;
    (*p)++;

    if ((ret = mbedtls_asn1_get_len(p, end, &params->len)) != 0) {
        return ret;
    }

    params->p = *p;
    *p += params->len;

    if (*p != end) {
        return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    return 0;
}


int mbedtls_x509_get_sig_alg_mod(const mbedtls_x509_buf_crt *sig_oid, const mbedtls_x509_buf *sig_params,
                             mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg,
                             void **sig_opts)
{
    //int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (*sig_opts != NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    #if LOGN_PARAM == 9
        *pk_alg = MBEDTLS_PK_FALCON512;
    #else
        *pk_alg = MBEDTLS_PK_FALCON1024;
    #endif
    *md_alg = KEYSTONE_SHA3;

    return 0;
}


int x509_get_attr_type_value(unsigned char **p,
                                    const unsigned char *end,
                                    mbedtls_x509_name *cur)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    mbedtls_x509_buf *oid;
    mbedtls_x509_buf *val;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
    }

    end = *p + len;

    if ((end - *p) < 1) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    oid = &cur->oid;
    oid->tag = **p;

    if ((ret = mbedtls_asn1_get_tag(p, end, &oid->len, MBEDTLS_ASN1_OID)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
    }

    oid->p = *p;
    *p += oid->len;

    if ((end - *p) < 1) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    if (**p != MBEDTLS_ASN1_BMP_STRING && **p != MBEDTLS_ASN1_UTF8_STRING      &&
        **p != MBEDTLS_ASN1_T61_STRING && **p != MBEDTLS_ASN1_PRINTABLE_STRING &&
        **p != MBEDTLS_ASN1_IA5_STRING && **p != MBEDTLS_ASN1_UNIVERSAL_STRING &&
        **p != MBEDTLS_ASN1_BIT_STRING) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }

    val = &cur->val;
    val->tag = *(*p)++;

    if ((ret = mbedtls_asn1_get_len(p, end, &val->len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
    }

    val->p = *p;
    *p += val->len;

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    cur->next = NULL;

    return 0;
}

int x509_get_dates(unsigned char **p,
                          const unsigned char *end,
                          mbedtls_x509_time *from,
                          mbedtls_x509_time *to)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE, ret);
    }

    end = *p + len;

    if ((ret = mbedtls_x509_get_time(p, end, from)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_x509_get_time(p, end, to)) != 0) {
        return ret;
    }

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

int mbedtls_x509_get_time(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_time *tm)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len, year_len;
    unsigned char tag;

    if ((end - *p) < 1) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    tag = **p;

    if (tag == MBEDTLS_ASN1_UTC_TIME) {
        year_len = 2;
    } else if (tag == MBEDTLS_ASN1_GENERALIZED_TIME) {
        year_len = 4;
    } else {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }

    (*p)++;
    ret = mbedtls_asn1_get_len(p, end, &len);

    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE, ret);
    }

    return x509_parse_time(p, len, year_len, tm);
}

int x509_parse_time(unsigned char **p, size_t len, size_t yearlen,
                           mbedtls_x509_time *tm)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /*
     * Minimum length is 10 or 12 depending on yearlen
     */
    if (len < yearlen + 8) {
        return MBEDTLS_ERR_X509_INVALID_DATE;
    }
    len -= yearlen + 8;

    /*
     * Parse year, month, day, hour, minute
     */
    CHECK(x509_parse_int(p, yearlen, &tm->year));
    if (2 == yearlen) {
        if (tm->year < 50) {
            tm->year += 100;
        }

        tm->year += 1900;
    }

    CHECK(x509_parse_int(p, 2, &tm->mon));
    CHECK(x509_parse_int(p, 2, &tm->day));
    CHECK(x509_parse_int(p, 2, &tm->hour));
    CHECK(x509_parse_int(p, 2, &tm->min));

    /*
     * Parse seconds if present
     */
    if (len >= 2) {
        CHECK(x509_parse_int(p, 2, &tm->sec));
        len -= 2;
    } else {
        return MBEDTLS_ERR_X509_INVALID_DATE;
    }

    /*
     * Parse trailing 'Z' if present
     */
    if (1 == len && 'Z' == **p) {
        (*p)++;
        len--;
    }

    /*
     * We should have parsed all characters at this point
     */
    if (0 != len) {
        return MBEDTLS_ERR_X509_INVALID_DATE;
    }

    CHECK(x509_date_is_valid(tm));

    return 0;
}

int x509_parse_int(unsigned char **p, size_t n, int *res)
{
    *res = 0;

    for (; n > 0; --n) {
        if ((**p < '0') || (**p > '9')) {
            return MBEDTLS_ERR_X509_INVALID_DATE;
        }

        *res *= 10;
        *res += (*(*p)++ - '0');
    }

    return 0;
}

int x509_date_is_valid(const mbedtls_x509_time *t)
{
    int ret = MBEDTLS_ERR_X509_INVALID_DATE;
    int month_len;

    CHECK_RANGE(0, 9999, t->year);
    CHECK_RANGE(0, 23,   t->hour);
    CHECK_RANGE(0, 59,   t->min);
    CHECK_RANGE(0, 59,   t->sec);

    switch (t->mon) {
        case 1: case 3: case 5: case 7: case 8: case 10: case 12:
            month_len = 31;
            break;
        case 4: case 6: case 9: case 11:
            month_len = 30;
            break;
        case 2:
            if ((!(t->year % 4) && t->year % 100) ||
                !(t->year % 400)) {
                month_len = 29;
            } else {
                month_len = 28;
            }
            break;
        default:
            return ret;
    }
    CHECK_RANGE(1, month_len, t->day);

    return 0;
}

int mbedtls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end, mbedtls_pk_context *pk){
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    mbedtls_asn1_buf alg_params;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    const mbedtls_pk_info_t *pk_info;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    end = *p + len;
    
    if ((ret = pk_get_pk_alg(p, end, &pk_alg, &alg_params)) != 0) {
        return ret;
    }
   
   mbedtls_x509_bitstring bs = { 0, 0, NULL };

    if ((ret = mbedtls_asn1_get_bitstring(p, end, &bs)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }
   
    if ((pk_info = mbedtls_pk_info_from_type(pk_alg)) == NULL) {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }

    if ((ret = mbedtls_pk_setup(pk, pk_info)) != 0) {
        return ret;
    }

    ret = pk_get_falconpubkey(&bs.p, &pk->pk_ctx);

    if (ret == 0 && *p != end) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY,
                                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    if (ret != 0) {
        mbedtls_pk_free(pk);
    }

    return ret;
}

int mbedtls_x509_get_sig(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *sig)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    int tag_type;

    if ((end - *p) < 1) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SIGNATURE,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    tag_type = **p;

    if ((ret = mbedtls_asn1_get_bitstring_null(p, end, &len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SIGNATURE, ret);
    }

    sig->tag = tag_type;
    sig->len = len;
    sig->p = *p;

   *p += len;
    
    return 0;
}
int mbedtls_asn1_get_bitstring_null(unsigned char **p, const unsigned char *end,
                                    size_t *len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_asn1_get_tag(p, end, len, MBEDTLS_ASN1_BIT_STRING)) != 0) {
        return ret;
    }

    if (*len == 0) {
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    --(*len);

    if (**p != 0) {
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    ++(*p);

    return 0;
}

int mbedtls_asn1_get_int(unsigned char **p,
                         const unsigned char *end,
                         int *val)
{
    return asn1_get_tagged_int(p, end, MBEDTLS_ASN1_INTEGER, val);
}

int asn1_get_tagged_int(unsigned char **p,
                               const unsigned char *end,
                               int tag, int *val)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len, tag)) != 0) {
        return ret;
    }

    /*
     * len==0 is malformed (0 must be represented as 020100 for INTEGER,
     * or 0A0100 for ENUMERATED tags
     */
    if (len == 0) {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }
    /* This is a cryptography library. Reject negative integers. */
    if ((**p & 0x80) != 0) {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }

    /* Skip leading zeros. */
    while (len > 0 && **p == 0) {
        ++(*p);
        --len;
    }

    /* Reject integers that don't fit in an int. This code assumes that
     * the int type has no padding bit. */
    if (len > sizeof(int)) {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }
    if (len == sizeof(int) && (**p & 0x80) != 0) {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }

    *val = 0;
    while (len-- > 0) {
        *val = (*val << 8) | **p;
        (*p)++;
    }

    return 0;
}

static const oid_sig_alg_t oid_sig_alg[] =
{ 
  {
    OID_DESCRIPTOR(MBEDTLS_OID_PKCS1_MD5,        "md5WithRSAEncryption",     "RSA with MD5"), MBEDTLS_MD_MD5,      MBEDTLS_PK_RSA,
  },
  {
        OID_DESCRIPTOR(MBEDTLS_OID_PKCS1_SHA224,     "sha224WithRSAEncryption",   "RSA with SHA-224"),
        MBEDTLS_MD_SHA224,   MBEDTLS_PK_RSA,
    },
    {
        OID_DESCRIPTOR(MBEDTLS_OID_ECDSA_SHA1,       "ecdsa-with-SHA1",      "ECDSA with SHA1"),
        MBEDTLS_MD_SHA1,     MBEDTLS_PK_ECDSA,
    },
    {
        OID_DESCRIPTOR("\x2B" "\x65" "\x70",    "id-Ed25519",   "id-Ed25519"),
        KEYSTONE_SHA3,   MBEDTLS_PK_ED25519,
    },
    //FALCON512
    //from pqc certificate https://github.com/IETF-Hackathon/pqc-certificates/blob/b5b1cdd95ce805e08756d7ba2539f9cca3816519/docs/oid_mapping.md
    { OID_DESCRIPTOR(
        "\x2B" "\x06" "\x01"
         "\x04" "\x01" "\x81"
          "\x8E" "\x33" "\x87"
           "\x67" "\x02" "\x03"
            "\x08" "\x01", "Falcon512WithShake256", "Falcon512WithShake256"),
            KEYSTONE_SHA3, MBEDTLS_PK_FALCON512,
    
    },
    //FALCON1024
    // from pqc certificate https://github.com/IETF-Hackathon/pqc-certificates/blob/b5b1cdd95ce805e08756d7ba2539f9cca3816519/docs/oid_mapping.md
    { OID_DESCRIPTOR(
        "\x2B" "\x06" "\x01"
         "\x04" "\x01" "\x81"
          "\x8E" "\x33" "\x87"
           "\x67" "\x02" "\x02"
            "\x08" "\x01", "Falcon1024WithShake256", "Falcon1024WithShake256"),
            KEYSTONE_SHA3, MBEDTLS_PK_FALCON1024,
    
    }
};

FN_OID_GET_OID_BY_ATTR2(mbedtls_oid_get_oid_by_sig_alg,
                        oid_sig_alg_t,
                        oid_sig_alg,
                        mbedtls_pk_type_t,
                        pk_alg,
                        mbedtls_md_type_t,
                        md_alg)
int mbedtls_x509_write_extensions(unsigned char **p, unsigned char *start,
                                  mbedtls_asn1_named_data *first)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    mbedtls_asn1_named_data *cur_ext = first;

    while (cur_ext != NULL) {
        MBEDTLS_ASN1_CHK_ADD(len, x509_write_extension(p, start, cur_ext));
        cur_ext = cur_ext->next;
    }

    return (int) len;
}

int mbedtls_x509_write_extensions_mod(unsigned char **p, unsigned char *start,
                                  mbedtls_asn1_named_data *arr_exte, int ne)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    int i = 0;
    //mbedtls_asn1_named_data *cur_ext = first;
    
    while (i != ne) {
        MBEDTLS_ASN1_CHK_ADD(len, x509_write_extension_mod(p, start, arr_exte[i]));
        i = i +1;
    }

    return (int) len;
}

int x509_write_extension_mod(unsigned char **p, unsigned char *start,
                                mbedtls_asn1_named_data ext)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, &ext.val.p_arr[1],
                                                            ext.val.len - 1)); 
    
    
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, ext.val.len - 1));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));
    
    if (ext.val.p_arr[0] != 0) {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bool(p, start, 1));
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, ext.oid.p_arr,
                                                            ext.oid.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, ext.oid.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OID));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

int x509_write_extension(unsigned char **p, unsigned char *start,
                                mbedtls_asn1_named_data *ext)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,  ext->val.p + 1,
                                                           ext->val.len - 1));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, ext->val.len - 1));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));

    if (ext->val.p[0] != 0) {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bool(p, start, 1));
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, ext->oid.p,
                                                            ext->oid.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, ext->oid.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OID));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

int mbedtls_asn1_write_bool(unsigned char **p, const unsigned char *start, int boolean)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (*p - start < 1) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = (boolean) ? 255 : 0;
    len++;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_BOOLEAN));

    return (int) len;
}

int mbedtls_x509write_crt_set_extension(mbedtls_x509write_cert *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        unsigned char *val, size_t val_len)
{
    return mbedtls_x509_set_extension(ctx->extens_arr, oid, oid_len,
                                      critical, val, val_len, &ctx->ne_ext_arr);
}

int mbedtls_x509_set_extension(mbedtls_asn1_named_data *head, const char *oid, size_t oid_len,
                               int critical, /*const*/ unsigned char *val, size_t val_len, int *ne)
{
 
    head[*ne].oid.len = oid_len;
    memcpy(head[*ne].oid.p_arr, oid, oid_len);
    head[*ne].val.p_arr[0] = critical;
    head[*ne].val.len = val_len +1;
    for(int i = 0; i < val_len; i ++)
        head[*ne].val.p_arr[i + 1] = val[i];

    *ne = *ne +1;

    return 0;
}

/*
 * X.509 v2/v3 unique identifier (not parsed)
 */
int x509_get_uid(unsigned char **p,
                        const unsigned char *end,
                        mbedtls_x509_buf_crt *uid, int n)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (*p == end) {
        return 0;
    }

    uid->tag = **p;

    if ((ret = mbedtls_asn1_get_tag(p, end, &uid->len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED |
                                    n)) != 0) {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            return 0;
        }

        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }

    uid->p = *p;
    *p += uid->len;

    return 0;
}

int pk_get_pk_alg(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_pk_type_t *pk_alg, mbedtls_asn1_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_asn1_buf alg_oid;

    memset(params, 0, sizeof(mbedtls_asn1_buf));
    
    if ((ret = mbedtls_asn1_get_alg_falcon(p, end, &alg_oid)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_ALG, ret);
    }

    #if LOGN_PARAM == 9
        *pk_alg = MBEDTLS_PK_FALCON512;
    #else 
        *pk_alg = MBEDTLS_PK_FALCON1024;
    #endif
    
    if (*pk_alg == MBEDTLS_PK_RSA &&
        ((params->tag != MBEDTLS_ASN1_NULL && params->tag != 0) ||
         params->len != 0)) {
        return MBEDTLS_ERR_PK_INVALID_ALG;
    }

    return 0;
}

int mbedtls_x509write_crt_set_subject_name_mod(mbedtls_x509write_cert *ctx, const char *subject_name){
    ctx->ne_subje_arr = 0;
    return mbedtls_x509_string_to_names_mod(ctx->subject_arr, subject_name, &ctx->ne_subje_arr);
}

int mbedtls_x509write_crt_set_issuer_name_mod(mbedtls_x509write_cert *ctx, const char *issuer_name){
    ctx->ne_issue_arr = 0;
    return mbedtls_x509_string_to_names_mod(ctx->issuer_arr, issuer_name, &ctx->ne_issue_arr);
}

int mbedtls_x509_string_to_names_mod(mbedtls_asn1_named_data *head, const char *name, int *ne)
{
    int ret = 0;
    const char *s = name, *c = s;
    const char *end = s + strlen(s);
    const char *oid = NULL;
    const x509_attr_descriptor_t *attr_descr = NULL;
    int in_tag = 1;
    char data[MBEDTLS_X509_MAX_DN_NAME_SIZE];
    char *d = data;

    /* Clear existing chain if present */
    mbedtls_asn1_free_named_data_list_mod(ne);

    while (c <= end) {
        if (in_tag && *c == '=') {
            if ((attr_descr = x509_attr_descr_from_name(s, c - s)) == NULL) {
                ret = MBEDTLS_ERR_X509_UNKNOWN_OID;
                goto exit;
            }

            oid = attr_descr->oid;
            s = c + 1;
            in_tag = 0;
            d = data;
        }

        if (!in_tag && *c == '\\' && c != end) {
            c++;

            /* Check for valid escaped characters */
            if (c == end || *c != ',') {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                goto exit;
            }
        } else if (!in_tag && (*c == ',' || c == end)) {
            int pos=
                mbedtls_asn1_store_named_data_mod(head, oid, strlen(oid),
                                              (unsigned char *) data,
                                              d - data, ne);
            // set tagType
            head[pos].val.tag = attr_descr->default_tag;

            while (c < end && *(c + 1) == ' ') {
                c++;
            }

            s = c + 1;
            in_tag = 1;
        }

        if (!in_tag && s != c + 1) {
            *(d++) = *c;

            if (d - data == MBEDTLS_X509_MAX_DN_NAME_SIZE) {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                goto exit;
            }
        }

        c++;
    }

exit:

    return ret;
}

int mbedtls_asn1_store_named_data_mod( mbedtls_asn1_named_data *head,const char *oid, size_t oid_len,const unsigned char *val,size_t val_len, int *ne)
{
    int pos;
    if (asn1_find_named_data_mod(head, oid, oid_len, *ne) == 0) {
        head[*ne].oid.len = oid_len;
        memcpy(head[*ne].oid.p_arr, oid, oid_len);
        head[*ne].val.len = val_len;
        memcpy(head[*ne].val.p_arr, val, val_len);
        *ne = *ne +1;
        pos = *ne -1;  
    }
    return pos;
}

int asn1_find_named_data_mod(mbedtls_asn1_named_data *list,const char *oid, size_t len, size_t ne)
{
    int i =0;
    while (i != ne) {
        if (list[i].oid.len == len &&
            memcmp(list[i].oid.p_arr, oid, len) == 0) {
            break;
        }
        i+=1;
    }
    if(i == ne)
        return 0;
    return 0;
}

int mbedtls_x509_write_names_mod(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *arr, int ne)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    for(int i = 0; i < ne ; i ++)
    {
        MBEDTLS_ASN1_CHK_ADD(len, x509_write_name_mod(p, start, arr[i]));

    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

int x509_write_name_mod(unsigned char **p,
                           unsigned char *start,
                           mbedtls_asn1_named_data cur_name)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const char *oid             = (const char *) cur_name.oid.p_arr;
    size_t oid_len              = cur_name.oid.len;
    const unsigned char *name   = cur_name.val.p_arr;
    size_t name_len             = cur_name.val.len;

    // Write correct string tag and value
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tagged_string(p, start,
                                                               cur_name.val.tag,
                                                               (const char *) name,
                                                               name_len));
    // Write OID
    //
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, oid,
                                                     oid_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SET));

    return (int) len;
}

int mbedtls_x509_get_name_mod(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_name_noarr *cur, int *ne)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t set_len;
    const unsigned char *end_set;
    mbedtls_x509_name_noarr *head = cur;
    *ne = 0;

    /* don't use recursion, we'd risk stack overflow if not optimized */
    while (1) {
    
        if ((ret = mbedtls_asn1_get_tag(p, end, &set_len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0) {
            ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
            goto error;
        }

        end_set  = *p + set_len;

        while (1) {
            if ((ret = x509_get_attr_type_value_mod(p, end_set, &head[*ne])) != 0) {
                goto error;
            }

            if (*p == end_set) {
                break;
            }
        }
        *ne = *ne +1;
        if (*p == end) {
            return 0;
        }
        
    }

error:
    /* Skip the first element as we did not allocate it */
    head->next = NULL;

    return ret;
}

int x509_get_attr_type_value_mod(unsigned char **p,
                                    const unsigned char *end,
                                    mbedtls_asn1_named_data_noarr *cur)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    mbedtls_x509_buf_crt *oid;
    mbedtls_x509_buf_crt *val;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
    }

    end = *p + len;

    if ((end - *p) < 1) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    oid = &cur->oid;
    oid->tag = **p;

    if ((ret = mbedtls_asn1_get_tag(p, end, &oid->len, MBEDTLS_ASN1_OID)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
    }

    oid->p = *p;
    *p += oid->len;

    if ((end - *p) < 1) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    if (**p != MBEDTLS_ASN1_BMP_STRING && **p != MBEDTLS_ASN1_UTF8_STRING      &&
        **p != MBEDTLS_ASN1_T61_STRING && **p != MBEDTLS_ASN1_PRINTABLE_STRING &&
        **p != MBEDTLS_ASN1_IA5_STRING && **p != MBEDTLS_ASN1_UNIVERSAL_STRING &&
        **p != MBEDTLS_ASN1_BIT_STRING) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }

    val = &cur->val;
    val->tag = *(*p)++;

    if ((ret = mbedtls_asn1_get_len(p, end, &val->len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME, ret);
    }

    val->p = *p;
    *p += val->len;

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_NAME,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    return 0;
}

int x509_get_crt_ext(unsigned char **p,
                            const unsigned char *end,
                            mbedtls_x509_crt *crt,
                            mbedtls_x509_crt_ext_cb_t cb,
                            void *p_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *end_ext_data /**start_ext_octet*/, *end_ext_octet;
    unsigned char oid_ext1[] = {0xff, 0x20, 0xff};
    unsigned char oid_ext2[] = {0x55, 0x1d, 0x13};
    

    if (*p == end) {
        return 0;
    }

    if ((ret = mbedtls_x509_get_ext(p, end, &crt->v3_ext, 3)) != 0) {
        return ret;
    }

    end = crt->v3_ext.p + crt->v3_ext.len;
    while (*p < end) {
        /*
         * Extension  ::=  SEQUENCE  {
         *      extnID      OBJECT IDENTIFIER,
         *      critical    BOOLEAN DEFAULT FALSE,
         *      extnValue   OCTET STRING  }
         */
        mbedtls_x509_buf extn_oid = { 0, 0, NULL };
        int is_critical = 0; /* DEFAULT FALSE */

        if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        end_ext_data = *p + len;

        /* Get extension ID */
        if ((ret = mbedtls_asn1_get_tag(p, end_ext_data, &extn_oid.len,
                                        MBEDTLS_ASN1_OID)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        extn_oid.tag = MBEDTLS_ASN1_OID;
        extn_oid.p = *p;
        *p += extn_oid.len;

        /* Get optional critical */
        if ((ret = mbedtls_asn1_get_bool(p, end_ext_data, &is_critical)) != 0 &&
            (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        /* Data should be octet string type */
        if ((ret = mbedtls_asn1_get_tag(p, end_ext_data, &len,
                                        MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        end_ext_octet = *p + len;

        if (end_ext_octet != end_ext_data) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                     MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        }
        
        if(memcmp(extn_oid.p, oid_ext2, 3)== 0){
            if ((ret = x509_get_basic_constraints(p, end_ext_octet,
                                                      &crt->ca_istrue, &crt->max_pathlen)) != 0) {
                  
                   return ret;
                }
        }
        else{
            x509_get_dice_tcbInfo(p, end_ext_octet, &crt->dice_tcb_info);
        }
    }

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

int mbedtls_x509_get_ext(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf_crt *ext, int tag)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    /* Extension structure use EXPLICIT tagging. That is, the actual
     * `Extensions` structure is wrapped by a tag-length pair using
     * the respective context-specific tag. */
    ret = mbedtls_asn1_get_tag(p, end, &ext->len,
                               MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    ext->tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag;
    ext->p   = *p;
    end      = *p + ext->len;

    /*
     * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */
    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (end != *p + len) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}


int mbedtls_asn1_get_bool(unsigned char **p,
                          const unsigned char *end,
                          int *val)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_BOOLEAN)) != 0) {
        return ret;
    }

    if (len != 1) {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }

    *val = (**p != 0) ? 1 : 0;
    (*p)++;

    return 0;
}

int mbedtls_x509write_crt_set_basic_constraints(mbedtls_x509write_cert *ctx,
                                                int is_ca, int max_pathlen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[9];
    unsigned char *c = buf + sizeof(buf);
    size_t len = 0;

    for(int i = 0; i < 9; i++)
        buf[i] = 0;

    if (is_ca && max_pathlen > 127) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    if (is_ca) {
        if (max_pathlen >= 0) {
            MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf,
                                                             max_pathlen));
        }
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bool(&c, buf, 1));
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return
        mbedtls_x509write_crt_set_extension(ctx, MBEDTLS_OID_BASIC_CONSTRAINTS,
                                            MBEDTLS_OID_SIZE(MBEDTLS_OID_BASIC_CONSTRAINTS),
                                            is_ca, buf + 9 - len, len);
}

int x509_get_basic_constraints(unsigned char **p,
                                      const unsigned char *end,
                                      int *ca_istrue,
                                      int *max_pathlen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    /*
     * BasicConstraints ::= SEQUENCE {
     *      cA                      BOOLEAN DEFAULT FALSE,
     *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
     */
    *ca_istrue = 0; /* DEFAULT FALSE */
    *max_pathlen = 0; /* endless */

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (*p == end) {
        return 0;
    }

    if ((ret = mbedtls_asn1_get_bool(p, end, ca_istrue)) != 0) {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            ret = mbedtls_asn1_get_int(p, end, ca_istrue);
        }

        if (ret != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }

        if (*ca_istrue != 0) {
            *ca_istrue = 1;
        }
    }

    if (*p == end) {
        return 0;
    }

    if ((ret = mbedtls_asn1_get_int(p, end, max_pathlen)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    /* Do not accept max_pathlen equal to INT_MAX to avoid a signed integer
     * overflow, which is an undefined behavior. */
    if (*max_pathlen == INT_MAX) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_INVALID_LENGTH);
    }

    (*max_pathlen)++;

    return 0;
}


void init_dice_tcbInfo(dice_tcbInfo* tcbInfo){
    tcbInfo->vendor[0] = '\0';
    tcbInfo->l_ven = 0;
    tcbInfo->model[0] = '\0';
    tcbInfo->l_mod = 0;
    tcbInfo->l_ver = 0;
    tcbInfo->version[0] ='\0';
    tcbInfo->svn = -1;
    tcbInfo->layer = -1;
    tcbInfo ->index = -1;
    tcbInfo ->flags[0] =  '\0';
    tcbInfo-> vendorInfo[0] ='\0';
    tcbInfo ->l_vi = 0;
    tcbInfo ->type[0] = '\0';
    tcbInfo->l_ty = 0;
    for(int i = 0; i < 2; i ++){
        tcbInfo->fwids[i].digest[0] ='\0';
        tcbInfo->fwids[i].OID_algho[0] = '0';
        tcbInfo->fwids[i].oid_len = 0;
    } 
}

void set_dice_tcbInfo_vendor(dice_tcbInfo* tcbInfo, unsigned char vendor[], int lv){
    memcpy(tcbInfo->vendor, vendor, lv);
    tcbInfo->l_ven = lv;
}
void set_dice_tcbInfo_version(dice_tcbInfo* tcbInfo, unsigned char version[], int lv){
    memcpy(tcbInfo->version, version, lv);
    tcbInfo->l_ver = lv;
}
void set_dice_tcbInfo_model(dice_tcbInfo* tcbInfo, unsigned char model[], int l){
    memcpy(tcbInfo->model, model, l);
    tcbInfo->l_mod = l;
}
void set_dice_tcbInfo_vi(dice_tcbInfo* tcbInfo, unsigned char vi[], int l){
    memcpy(tcbInfo->vendorInfo, vi, l);
    tcbInfo->l_vi = l;
}
void set_dice_tcbInfo_type(dice_tcbInfo* tcbInfo, unsigned char type[], int l){
    memcpy(tcbInfo->type, type, l);
    tcbInfo->l_ty = l;
}
void set_dice_tcbInfo_measure(dice_tcbInfo* tcbInfo, measure m){
    memcpy(tcbInfo->fwids[0].digest, m.digest, 64);
    memcpy(tcbInfo->fwids[0].OID_algho, m.OID_algho, m.oid_len);
    tcbInfo->fwids[0].oid_len = m.oid_len;
}


int setting_tcbInfo(dice_tcbInfo* dice_tcbInfo, unsigned char vendor[] , int l_ven, unsigned char model[], int l_m, unsigned char version[], int l_ver,
                            int svn, int layer, int index, unsigned char flags[], int l_f, unsigned char vendor_info[], int l_vf, unsigned char type[], int l_t,
                            measure measures[], int l_mea){
                                if((l_ven > 64) ||(l_m > 64)|| (l_ver > 64) ||(l_f > 4)|| (l_vf > 16) ||(l_t > 16)|| (l_mea > 10))
                                    return 1;
                                if((l_ven < 0 ) ||(l_m < 0)|| (l_ver < 0) ||(l_f < 0)|| (l_vf < 0) ||(l_t < 0)|| (l_mea < 0))
                                    return 1;
                                memcpy(dice_tcbInfo->vendor, vendor, l_ven);
                                memcpy(dice_tcbInfo->model, model, l_m);
                                memcpy(dice_tcbInfo->version, version, l_ver);
                                memcpy(dice_tcbInfo->flags, flags, l_f);
                                memcpy(dice_tcbInfo->vendorInfo, vendor_info, l_vf);
                                memcpy(dice_tcbInfo->type, type, l_t);
                                for(int i = 0; i < l_mea; i++){
                                    memcpy(dice_tcbInfo->fwids[i].digest, measures[i].digest, 64);
                                    memcpy(dice_tcbInfo->fwids[i].OID_algho, measures[i].OID_algho, measures[i].oid_len);
                                    dice_tcbInfo->fwids[i].oid_len = measures[i].oid_len;
                                }
                                return 0;
}




/*int mbedtls_x509write_crt_set_dice_tcbInfo(mbedtls_x509write_cert *ctx,
                                                dice_tcbInfo info_struct)*/

int mbedtls_x509write_crt_set_dice_tcbInfo(mbedtls_x509write_cert *ctx,
                                                dice_tcbInfo info_struct, int dim, unsigned char buf[], size_t buf_size)
{
    
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *c = buf + buf_size;
    size_t len = 0;    
    
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf, info_struct.fwids[0].digest,
                                                        64));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, 64));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_OCTET_STRING));
    
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf,
                                                            info_struct.fwids[0].OID_algho, info_struct.fwids[0].oid_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, info_struct.fwids[0].oid_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_OID));


    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf, info_struct.type,
                                                        16));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, 16));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_OCTET_STRING));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf, info_struct.vendorInfo,
                                                        16));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, 16));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_OCTET_STRING));


    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf, info_struct.flags,
                                                        4));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, 4));

    //riferimento la set_basic_connstraint di sopra
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf,
                                                             info_struct.index));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf,
                                                             info_struct.layer));                                                             
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf,
                                                             info_struct.svn));

    //Riferimento x509write_crt.c riga 349
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf, info_struct.version,
                                                        info_struct.l_ver));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf,  info_struct.l_ver));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf, info_struct.model,
                                                         info_struct.l_mod));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf,  info_struct.l_mod));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf, info_struct.vendor,
                                                             info_struct.l_ven));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf,  info_struct.l_ven));                                                        
    
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    const char oid_dice_tcbInfo[] = {0x2, 0x17, 0x85, 0x5, 0x4, 0x1};
    return
        mbedtls_x509write_crt_set_extension(ctx, oid_dice_tcbInfo,
                                            6,
                                            1, buf + dim - len, len);
}

int x509_get_dice_tcbInfo(unsigned char **p,
                                      const unsigned char *end,
                                      dice_tcbInfo* info_struct)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    size_t app_len;
    

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    if (*p == end) {
        return 0;
    }  

    if ((ret = mbedtls_asn1_get_len(p, end, &app_len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SERIAL, ret);
    }

    memcpy(info_struct->vendor, *p, app_len);
    *p += app_len;

    if ((ret = mbedtls_asn1_get_len(p, end, &app_len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SERIAL, ret);
    }

    memcpy(info_struct->model, *p, app_len);
    *p += app_len;

    if ((ret = mbedtls_asn1_get_len(p, end, &app_len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SERIAL, ret);
    }
    memcpy(info_struct->version, *p, app_len);
    *p += app_len;

    ret = mbedtls_asn1_get_int(p, end, &info_struct ->svn);
    ret = mbedtls_asn1_get_int(p, end, &info_struct ->layer);
    ret = mbedtls_asn1_get_int(p, end, &info_struct ->index);

    if ((ret = mbedtls_asn1_get_len(p, end, &app_len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_SERIAL, ret);
    }

    memcpy(info_struct->flags, *p, app_len);    
    *p += app_len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &app_len,
                                    MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }
    
    memcpy(info_struct->vendorInfo, *p, app_len); 
    *p += app_len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &app_len,
                                    MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }
    memcpy(info_struct->type, *p, app_len); 

    *p += app_len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

     if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_OID)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    memcpy(info_struct->fwids[0].OID_algho, *p, len); 
    info_struct->fwids[0].oid_len = len;
    
    *p += len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &app_len,
                                    MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }

    memcpy(info_struct->fwids[0].digest, *p, app_len);
    *p += app_len;

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    
    return 0;
}

int mbedtls_asn1_write_bitstring(unsigned char **p, const unsigned char *start,
                                 const unsigned char *buf, size_t bits)
{
   // int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    size_t unused_bits, byte_len;

    byte_len = (bits + 7) / 8;
    unused_bits = (byte_len * 8) - bits;
    
    if (*p < start || (size_t) (*p - start) < byte_len + 1) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }
    len = byte_len + 1;

    /* Write the bitstring. Ensure the unused bits are zeroed */
    if (byte_len > 0) {
        byte_len--;
        *--(*p) = buf[byte_len] & ~((0x1 << unused_bits) - 1);
        (*p) -= byte_len;
        memcpy(*p, buf, byte_len);
    }

    /* Write unused bits */
    *--(*p) = (unsigned char) unused_bits;

    return (int) len;
}

int mbedtls_asn1_get_bitstring(unsigned char **p, const unsigned char *end,
                               mbedtls_asn1_bitstring *bs)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Certificate type is a single byte bitstring */
    if ((ret = mbedtls_asn1_get_tag(p, end, &bs->len, MBEDTLS_ASN1_BIT_STRING)) != 0) {
        return ret;
    }

    /* Check length, subtract one for actual bit string length */
    if (bs->len < 1) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }
    bs->len -= 1;

    /* Get number of unused bits, ensure unused bits <= 7 */
    bs->unused_bits = **p;
    if (bs->unused_bits > 7) {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }
    (*p)++;

    /* Get actual bitstring */
    bs->p = *p;
    *p += bs->len;

    if (*p != end) {
        return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    return 0;
}

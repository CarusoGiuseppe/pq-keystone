#############
## Headers ##
#############

# General headers
keystone-sm-headers += assert.h cpu.h enclave.h ipi.h mprv.h page.h platform-hook.h \
                        pmp.h safe_math_util.h sm.h sm-sbi.h sm-sbi-opensbi.h thread.h

# Crypto headers
keystone-sm-headers += crypto.h ed25519/ed25519.h ed25519/fe.h ed25519/fixedint.h \
                        ed25519/ge.h ed25519/precomp_data.h ed25519/sc.h \
                        hkdf_sha3_512/hkdf_sha3_512.h hmac_sha3/hmac_sha3.h \
                        sha3/sha3.h falcon512_sm/config.h \
                        falcon512_sm/falcon.h  falcon512_sm/fpr.h \
                        falcon512_sm/inner.h falcon512_sm/my_string.h \
                        x509custom_sm/x509custom.h x509custom_sm/oid_custom.h #\
                        falcon512_sm/deterministic.h falcon512_sm/fixedint.h \
                        dilithium_sm/aes256ctr.h dilithium_sm/api.h dilithium_sm/config.h \
                        dilithium_sm/fips202.h dilithium_sm/my_string.h dilithium_sm/ntt.h \
                        dilithium_sm/packing.h dilithium_sm/params.h dilithium_sm/poly.h \
                        dilithium_sm/polyvec.h dilithium_sm/randombytes.h dilithium_sm/reduce.h \
                        dilithium_sm/rounding.h dilithium_sm/sign.h dilithium_sm/symmetric.h 

                        
                        

# Platform headers
keystone-sm-headers += platform/$(KEYSTONE_PLATFORM)/platform.h

ifeq ($(KEYSTONE_PLATFORM),sifive/fu540)
	keystone-sm-headers += platform/sifive/fu540/waymasks.h
endif

# Plugin headers
keystone-sm-headers += plugins/multimem.h plugins/plugins.h

##################
## Source files ##
##################

# Core files
keystone-sm-sources += attest.c cpu.c enclave.c pmp.c sm.c sm-sbi.c sm-sbi-opensbi.c \
                        thread.c mprv.c sbi_trap_hack.c trap.c ipi.c

# Crypto
keystone-sm-sources += crypto.c sha3/sha3.c ed25519/fe.c ed25519/ge.c ed25519/keypair.c \
                        ed25519/sc.c ed25519/sign.c hkdf_sha3_512/hkdf_sha3_512.c \
                        hmac_sha3/hmac_sha3.c  falcon512_sm/falcon.c \
                        falcon512_sm/fft.c falcon512_sm/fpr.c falcon512_sm/keygen.c \
                        falcon512_sm/my_string.c falcon512_sm/rng.c falcon512_sm/shake.c \
                        falcon512_sm/sign.c falcon512_sm/vrfy.c falcon512_sm/codec.c \
                        falcon512_sm/common.c x509custom_sm/x509custom.c #\
                        falcon512_sm/deterministic.c \
                        dilithium_sm/aes256ctr.c dilithium_sm/symmetric-shake.c \
                        dilithium_sm/fips202.c dilithium_sm/my_string.c dilithium_sm/ntt.c \
                        dilithium_sm/packing.c dilithium_sm/poly.c \
                        dilithium_sm/polyvec.c dilithium_sm/randombytes.c dilithium_sm/reduce.c \
                        dilithium_sm/rounding.c dilithium_sm/sign.c dilithium_sm/symmetric-aes.c  

# Platform
keystone-sm-sources += platform/$(PLATFORM)/platform.c

# Plugin files
keystone-sm-sources += plugins/multimem.c plugins/plugins.c

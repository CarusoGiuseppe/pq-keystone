//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <string>
#include "falcon512/falcon.h"

typedef unsigned char byte;

#define ATTEST_DATA_MAXLEN 1024
#define MDSIZE 64
#define SIGNATURE_SIZE 64 //64
#define PUBLIC_KEY_SIZE 32 //32

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

class PublicKey {
 public:
  byte data[FALCON_PK_SIZE];
  explicit PublicKey(std::string hexstr);
};

class DevicePublicKey : public PublicKey {
 public:
  explicit DevicePublicKey(std::string hexstr) : PublicKey(hexstr) {}
};

class SecurityMonitorPublicKey : public PublicKey {
 public:
  explicit SecurityMonitorPublicKey(std::string hexstr) : PublicKey(hexstr) {}
};

//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <string>

typedef unsigned char byte;

#define ATTEST_DATA_MAXLEN 1024
#define MDSIZE 64
#define SIGNATURE_SIZE 64 //64
#define FALCON_512_SIG_SIZE 809 
#define PUBLIC_KEY_SIZE 32 //32
#define FALCON_512_PK_SIZE 897

class PublicKey {
 public:
  byte data[FALCON_512_PK_SIZE];
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

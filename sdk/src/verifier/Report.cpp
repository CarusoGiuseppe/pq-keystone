//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <Report.hpp>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include "falcon512/falcon.h"

using json11::Json;
std::string
Report::BytesToHex(byte* bytes, size_t len) {
  unsigned int i;
  std::string str;
  for (i = 0; i < len; i += 1) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t)bytes[i];

    str += ss.str();
  }
  return str;
}

void
Report::HexToBytes(byte* bytes, size_t len, std::string hexstr) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    unsigned int data = 0;
    std::stringstream ss;
    ss << hexstr.substr(i * 2, 2);
    ss >> std::hex >> data;
    bytes[i] = (byte)data;
  }
}

void
Report::fromJson(std::string jsonstr) {
  std::string err;
  const auto json = Json::parse(jsonstr, err);

  std::string device_pubkey = json["device_pubkey"].string_value();
  HexToBytes(report.dev_public_key, FALCON_512_PK_SIZE, device_pubkey);

  std::string sm_hash = json["security_monitor"]["hash"].string_value();
  HexToBytes(report.sm.hash, MDSIZE, sm_hash);
  std::string sm_pubkey = json["security_monitor"]["pubkey"].string_value();
  HexToBytes(report.sm.public_key, FALCON_512_PK_SIZE, sm_pubkey);
  std::string sm_signature =
      json["security_monitor"]["signature"].string_value();
  HexToBytes(report.sm.signature, FALCON_512_SIG_SIZE, sm_signature);

  std::string enclave_hash = json["enclave"]["hash"].string_value();
  HexToBytes(report.enclave.hash, MDSIZE, enclave_hash);
  report.enclave.data_len  = json["enclave"]["datalen"].int_value();
  std::string enclave_data = json["enclave"]["data"].string_value();
  HexToBytes(report.enclave.data, report.enclave.data_len, enclave_data);
  std::string enclave_signature = json["enclave"]["signature"].string_value();
  HexToBytes(report.enclave.signature, FALCON_512_SIG_SIZE, enclave_signature);
}

void
Report::fromBytes(byte* bin) {
  std::memcpy(&report, bin, sizeof(struct report_t));
}

std::string
Report::stringfy() {
  if (report.enclave.data_len > ATTEST_DATA_MAXLEN) {
    return "{ \"error\" : \"invalid data length\" }";
  }
  auto json = Json::object{
      {"device_pubkey", BytesToHex(report.dev_public_key, FALCON_512_PK_SIZE)},
      {
          "security_monitor",
          Json::object{
              {"hash", BytesToHex(report.sm.hash, MDSIZE)},
              {"pubkey", BytesToHex(report.sm.public_key, FALCON_512_PK_SIZE)},
              {"signature", BytesToHex(report.sm.signature, FALCON_512_SIG_SIZE)}},
      },
      {
          "enclave",
          Json::object{
              {"hash", BytesToHex(report.enclave.hash, MDSIZE)},
              {"datalen", static_cast<int>(report.enclave.data_len)},
              {"data",
               BytesToHex(report.enclave.data, report.enclave.data_len)},
              {"signature",
               BytesToHex(report.enclave.signature, FALCON_512_SIG_SIZE)},
          },
      },
  };

  return json11::Json(json).dump();
}

void
Report::printJson() {
  std::cout << stringfy() << std::endl;
}

void
Report::printPretty() {
  std::cout << "\t\t=== Security Monitor ===" << std::endl;
  std::cout << "Hash: " << BytesToHex(report.sm.hash, MDSIZE) << std::endl;
  std::cout << "Pubkey: " << BytesToHex(report.sm.public_key, FALCON_512_PK_SIZE)
            << std::endl;
  std::cout << "Signature: " << BytesToHex(report.sm.signature, FALCON_512_SIG_SIZE)
            << std::endl;
  std::cout << std::endl << "\t\t=== Enclave Application ===" << std::endl;
  std::cout << "Hash: " << BytesToHex(report.enclave.hash, MDSIZE) << std::endl;
  std::cout << "Signature: "
            << BytesToHex(report.enclave.signature, FALCON_512_SIG_SIZE)
            << std::endl;
  std::cout << "Enclave Data: "
            << BytesToHex(report.enclave.data, report.enclave.data_len)
            << std::endl;
  std::cout << "\t\t-- Device pubkey --" << std::endl;
  std::cout << BytesToHex(report.dev_public_key, FALCON_512_PK_SIZE) << std::endl;
}

byte*
Report::getEnclaveHash() {
    return report.enclave.hash;
}

byte*
Report::getSmHash() {
    return report.sm.hash;
}

int
Report::verify(
    const byte* expected_enclave_hash, const byte* expected_sm_hash,
    const byte* dev_public_key) {
  /* verify that enclave hash matches */
  int encl_hash_valid =
      memcmp(expected_enclave_hash, report.enclave.hash, MDSIZE) == 0;
      if (encl_hash_valid == 1)
      {
        printf("Enclave Hash matches\n");
      }
      else
      {
        printf("Expected Enclave Hash:\n");
        for (int i = 0; i < MDSIZE; ++i)
        {
          printf("%02x", expected_enclave_hash[i]);
        }
        printf("\nEnclave Hash in Report:\n");
        for (int i = 0; i < MDSIZE; ++i)
        {
          printf("%02x", report.enclave.hash[i]);
        }
        printf("\n");
      }
  int sm_hash_valid = memcmp(expected_sm_hash, report.sm.hash, MDSIZE) == 0;
      if (sm_hash_valid == 1)
      {
        printf("SM Hash matches\n");
      }
      else
      {
        printf("Expected SM Hash:\n");
        for (int i = 0; i < MDSIZE; ++i)
        {
          printf("%02x", expected_sm_hash[i]);
        }
        printf("\nSM Hash in Report:\n");
        for (int i = 0; i < MDSIZE; ++i)
        {
          printf("%02x", report.sm.hash[i]);
        }
        printf("\n");
      }
  int signature_valid = checkSignaturesOnly(dev_public_key);
      if (signature_valid == 1)
      {
        printf("Signatures are correct\n");
      }
  return encl_hash_valid && sm_hash_valid && signature_valid;
}

int
Report::checkSignaturesOnly(const byte* dev_public_key) {
  int sm_valid      = 0;
  int enclave_valid = 0;
  unsigned char tmp[FALCON_TMPSIZE_VERIFY(LOGN_PARAM)];

  /* verify SM report */
  sm_valid = falcon_verify(
      report.sm.signature, FALCON_512_SIG_SIZE, FALCON_SIG_CT, dev_public_key, FALCON_512_PK_SIZE, reinterpret_cast<byte*>(&report.sm), MDSIZE + FALCON_512_PK_SIZE,
      tmp, FALCON_TMPSIZE_VERIFY(LOGN_PARAM));
  /* verify Enclave report */
  enclave_valid = falcon_verify(
      report.enclave.signature, FALCON_512_SIG_SIZE, FALCON_SIG_CT, report.sm.public_key, FALCON_512_PK_SIZE, reinterpret_cast<byte*>(&report.enclave), MDSIZE + sizeof(uint64_t) + report.enclave.data_len,
      tmp, FALCON_TMPSIZE_VERIFY(LOGN_PARAM));
  //the return values are '0' if the signatures are correct, so for correctness of the if condition evaluation we negate the value
  return !(sm_valid && enclave_valid);
}

void*
Report::getDataSection() {
  return report.enclave.data;
}

size_t
Report::getDataSize() {
  return report.enclave.data_len;
}

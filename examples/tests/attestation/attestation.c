//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"
#include "app/string.h"
#include "app/syscall.h"

#include "edge_wrapper.h"

void EAPP_ENTRY eapp_entry(){
  edge_init();

  char* data = "nonce";
  char buffer[4096];

  attest_enclave((void*) buffer, data, 5);

  ocall_copy_report(buffer, 4096);

  EAPP_RETURN(0);
}

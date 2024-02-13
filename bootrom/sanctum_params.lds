. = 0x801fd000; /* the last page before the payload */

  /* ## manufacturer_keys : */

  /* 32 Bytes : device public key */
  PROVIDE( sanctum_ECASM_priv = . );
  . += 0x501;

  /* ## security_monitor_keys : */

  /* 64 Bytes : security monitor hash */
  PROVIDE( sanctum_sm_hash = . );
  . += 0x40;

  /* 32 Bytes : security monitor public key */
  PROVIDE( sanctum_sm_public_key = . );
  . += 0x381;

  /* 64 Bytes : security monitor secret key */
  PROVIDE( sanctum_sm_secret_key = . );
  . += 0x501;

  /* 64 Bytes : security monitor's signature by device */
  PROVIDE( sanctum_sm_signature = . );
  . += 0x329;

/* 64 Bytes : Compound Device Identifier */
PROVIDE( sanctum_CDI = . );
. += 0x40;

/* 512 Bytes : security monitor's certificate */
PROVIDE( sanctum_cert_sm = . );
. += 0x811;

/* 512 Bytes : root certificate */
PROVIDE( sanctum_cert_root = . );
. += 0x75b;

/* 512 Bytes : manufacturer certificate */
PROVIDE( sanctum_cert_man = . );
. += 0x76f;

/* 4 Byte : certificate length */
PROVIDE( sanctum_length_cert = . );
. += 0x04;

/* 4 Byte : root certificate length */
PROVIDE( sanctum_length_cert_root = . );
. += 0x04;

/* 4 Byte : manufacturer certificate length */
PROVIDE( sanctum_length_cert_man = . );
. += 0x04;

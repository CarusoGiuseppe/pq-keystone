/*
 *  Copyright (C) 2020 Fraunhofer AISEC
 *  Authors: Benedikt Kopf <benedikt.kopf@aisec.fraunhofer.de>
 *           Lukas Auer <lukas.auer@aisec.fraunhofer.de>
 *           Mathias Morbitzer <mathias.morbitzer@aisec.fraunhofer.de>
 *
 *  sealing.h
 *
 *  Provides the necessary definitions to derive a seal key
 *
 *  All Rights Reserved. See LICENSE for license details.
 */

#ifndef SEALING_H
#define SEALING_H

#define LOGN_PARAM 9
#define SEALING_KEY_SIZE 128
#define SIGNATURE_SIZE 64//64

#if LOGN_PARAM == 9
#define FALCON_SIG_SIZE 809
#else
#define FALCON_SIG_SIZE 1577
#endif

/* sealing key structure */
struct sealing_key {
  uint8_t key[SEALING_KEY_SIZE];
  uint8_t signature[FALCON_SIG_SIZE];
};

#endif /* SEALING_H */

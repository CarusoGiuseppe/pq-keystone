#include "randombytes.h"

void dilithium_randombytes(uint8_t *out, size_t outlen){
	for(size_t i = 0; i < outlen; i++){
		out[i] = 0x01;
	}
}

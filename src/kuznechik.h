#pragma once

#include <stdint.h>

#define KUZNECHIK_BLOCK_SIZE 16

typedef union {
	uint8_t  b[KUZNECHIK_BLOCK_SIZE];
	uint64_t q[KUZNECHIK_BLOCK_SIZE / 8];
} vect_t;

typedef struct {
	vect_t keys[10]; // round keys
} round_keys_t;

// For testing:
void GOST_Kuz_S(vect_t *in_out);
void GOST_Kuz_S_reverse(vect_t *in_out);

void GOST_Kuz_R(vect_t *in_out);
void GOST_Kuz_R_reverse(vect_t *in_out);

void GOST_Kuz_L(vect_t *in_out);
void GOST_Kuz_L_reverse(vect_t *in_out);

void GOST_Kuz_X(const vect_t *a, const vect_t *b, vect_t *c);

void GOST_Kuz_set_key(uint8_t master_key[128], round_keys_t * rk);

void GOST_Kuz_encrypt_block(const round_keys_t *rk, const vect_t *in, vect_t *out);
void GOST_Kuz_decrypt_block(const round_keys_t *rk, const vect_t *in, vect_t *out);
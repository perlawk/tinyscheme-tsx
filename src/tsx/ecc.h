#ifndef __ECC_H
#define __ECC_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <netinet/in.h>

//#ifdef __LP64__
//#define ptr_t long
//#else
#define ptr_t uint32_t
//#endif

#define memmove(d, s, l)   bcopy(s, d, l)

#define MACRO(A) do { A; } while(0)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define CHARS2INT(ptr) ntohl(*(ptr_t *)(ptr))
#define INT2CHARS(ptr, val) MACRO( *(ptr_t*)(ptr) = htonl(val) )
#define DEV_RANDOM "/dev/urandom"
#define FATAL(s) MACRO( perror(s); exit(255) )
#define DEGREE 409
#define MARGIN 3
#define NUMWORDS ((DEGREE + MARGIN + 31) / 32)
#define ECIES_OVERHEAD (8 * NUMWORDS + 8)

#define bitstr_getbit(A, idx) ((A[(idx) / 32] >> ((idx) % 32)) & 1)
#define bitstr_setbit(A, idx) MACRO( A[(idx) / 32] |= 1 << ((idx) % 32) )
#define bitstr_clrbit(A, idx) MACRO( A[(idx) / 32] &= ~(1 << ((idx) % 32)) )

#define bitstr_clear(A) MACRO( memset(A, 0, sizeof(bitstr_t)) )
#define bitstr_copy(A, B) MACRO( memcpy(A, B, sizeof(bitstr_t)) )
#define bitstr_swap(A, B) MACRO( bitstr_t h; \
		      bitstr_copy(h, A); bitstr_copy(A, B); bitstr_copy(B, h) )
#define bitstr_is_equal(A, B) (! memcmp(A, B, sizeof(bitstr_t)))

typedef ptr_t bitstr_t[NUMWORDS];
typedef bitstr_t elem_t;
typedef bitstr_t exp_t;
elem_t coeff_b, base_x, base_y;

#define point_is_zero(x, y) (bitstr_is_clear(x) && bitstr_is_clear(y))
#define point_set_zero(x, y) MACRO( bitstr_clear(x); bitstr_clear(y) )
#define point_copy(x1, y1, x2, y2) MACRO( bitstr_copy(x1, x2); \
		bitstr_copy(y1, y2) )

int bitstr_is_clear(const bitstr_t);
int bitstr_sizeinbits(const bitstr_t);
void bitstr_lshift(bitstr_t, const bitstr_t, int);
void bitstr_import(bitstr_t, const char *);
void bitstr_export(char *, const bitstr_t);
void bitstr_to_hex(char *, const bitstr_t);
int bitstr_parse(bitstr_t, const char *);

int field_is1(const elem_t);
void field_add(elem_t, const elem_t, const elem_t);
void field_mult(elem_t, const elem_t, const elem_t);
void field_invert(elem_t, const elem_t);

int is_point_on_curve(const elem_t, const elem_t);
void point_double(elem_t, elem_t);
void point_add(elem_t, elem_t, const elem_t, const elem_t);
void point_mult(elem_t, elem_t, const exp_t);

void get_random_exponent(exp_t);

void XTEA_init_key(ptr_t *, const char *);
void XTEA_encipher_block(char *, const ptr_t *);
void XTEA_ctr_crypt(char *, int, const char *);
void XTEA_cbcmac(char *, const char *, int, const char *);
void XTEA_davies_meyer(char *, const char *, int);

int ECIES_embedded_public_key_validation(const elem_t, const elem_t);
int ECIES_public_key_validation(const char *, const char *);
void ECIES_kdf(char *, char *, const elem_t, const elem_t, const elem_t);

void ECIES_encryption(char *, const char *, int, const char *, const char *);
int ECIES_decryption(char *, const char *, int, const char *);


/* void encryption_decryption_demo(const char *text, const char *public_x, const char *public_y, const char *private); */
void ECIES_init(void);

#endif

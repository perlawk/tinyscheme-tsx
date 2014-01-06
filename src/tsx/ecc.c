/* 
	This program implements the ECIES public key encryption scheme based on the
	NIST B409 elliptic curve and the XTEA block cipher. The code was written
	as an accompaniment for an article published in phrack #63 and is released to
	the public domain.

	Modified by kkirov to work with files.
	10.09.2007

	Modified by kkirov to use B409 curve.
	04.08.2005
*/

#include "ecc.h"
#include <unistd.h>

int bitstr_is_clear(const bitstr_t x)
{
	int i;
	for(i = 0; i < NUMWORDS && ! *x++; i++);
	return i == NUMWORDS;
}

/* return the number of the highest one-bit + 1 */
int bitstr_sizeinbits(const bitstr_t x)
{
	int i;
	ptr_t mask;
	for(x += NUMWORDS, i = 32 * NUMWORDS; i > 0 && ! *--x; i -= 32);
	if (i)
		for(mask = 1 << 31; ! (*x & mask); mask >>= 1, i--);
	return i;
}

/* left-shift by 'count' digits */
void bitstr_lshift(bitstr_t A, const bitstr_t B, int count)
{
	int i, offs = 4 * (count / 32);
	memmove((void*)(A + offs), B, sizeof(bitstr_t) - offs);
	memset(A, 0, offs);
	if (count %= 32) {
		for(i = NUMWORDS - 1; i > 0; i--)
			A[i] = (A[i] << count) | (A[i - 1] >> (32 - count));
		A[0] <<= count;
	}
}

/* (raw) import from a byte array */
void bitstr_import(bitstr_t x, const char *s)
{
	int i;
	for(x += NUMWORDS, i = 0; i < NUMWORDS; i++, s += 4)
		*--x = CHARS2INT(s);
}

/* (raw) export to a byte array */
void bitstr_export(char *s, const bitstr_t x)
{
	int i;
	for(x += NUMWORDS, i = 0; i < NUMWORDS; i++, s += 4)
		INT2CHARS(s, *--x);
}

/* export as hex string (null-terminated!) */
void bitstr_to_hex(char *s, const bitstr_t x)
{
	int i;
	for(x += NUMWORDS, i = 0; i < NUMWORDS; i++, s += 8)
		sprintf(s, "%08x", *--x);
}

/* import from a hex string */
int bitstr_parse(bitstr_t x, const char *s)
{
	int len;
	if ((s[len = strspn(s, "0123456789abcdefABCDEF")]) ||
			(len > NUMWORDS * 8))
		return -1;
	bitstr_clear(x);
	x += len / 8;
	if (len % 8) {
		sscanf(s, "%08x", x);
		*x >>= 32 - 4 * (len % 8);
		s += len % 8;
		len &= ~7;
	}
	for(; *s; s += 8)
		sscanf(s, "%08x", --x);
	return len;
}

/******************************************************************************/

elem_t poly;                                      /* the reduction polynomial */

#define field_set1(A) MACRO( A[0] = 1; memset(A + 1, 0, sizeof(elem_t) - 4) )

int field_is1(const elem_t x)
{
	int i;
	if (*x++ != 1) return 0;
	for(i = 1; i < NUMWORDS && ! *x++; i++);
	return i == NUMWORDS;
}

void field_add(elem_t z, const elem_t x, const elem_t y)    /* field addition */
{
	int i;
	for(i = 0; i < NUMWORDS; i++)
		*z++ = *x++ ^ *y++;
}

#define field_add1(A) MACRO( A[0] ^= 1 )

/* field multiplication */
void field_mult(elem_t z, const elem_t x, const elem_t y)
{
	elem_t b;
	int i, j;
	/* assert(z != y); */
	bitstr_copy(b, x);
	if (bitstr_getbit(y, 0))
		bitstr_copy(z, x);
	else
		bitstr_clear(z);
	for(i = 1; i < DEGREE; i++) {
		for(j = NUMWORDS - 1; j > 0; j--)
			b[j] = (b[j] << 1) | (b[j - 1] >> 31);
		b[0] <<= 1;
		if (bitstr_getbit(b, DEGREE))
			field_add(b, b, poly);
		if (bitstr_getbit(y, i))
			field_add(z, z, b);
	}
}

void field_invert(elem_t z, const elem_t x)                /* field inversion */
{
	elem_t u, v, g, h;
	int i;
	bitstr_copy(u, x);
	bitstr_copy(v, poly);
	bitstr_clear(g);
	field_set1(z);
	while (! field_is1(u)) {
		i = bitstr_sizeinbits(u) - bitstr_sizeinbits(v);
		if (i < 0) {
			bitstr_swap(u, v); bitstr_swap(g, z); i = -i;
		}
		bitstr_lshift(h, v, i);
		field_add(u, u, h);
		bitstr_lshift(h, g, i);
		field_add(z, z, h);
	}
}

/******************************************************************************/

/* The following routines do the ECC arithmetic. Elliptic curve points
	are represented by pairs (x,y) of elem_t. It is assumed that curve
	coefficient 'a' is equal to 1 (this is the case for all NIST binary
	curves). Coefficient 'b' is given in 'coeff_b'.  '(base_x, base_y)'
	is a point that generates a large prime order group.             */

/* check if y^2 + x*y = x^3 + *x^2 + coeff_b holds */
int is_point_on_curve(const elem_t x, const elem_t y)
{
	elem_t a, b;
	if (point_is_zero(x, y))
		return 1;
	field_mult(a, x, x);
	field_mult(b, a, x);
	field_add(a, a, b);
	field_add(a, a, coeff_b);
	field_mult(b, y, y);
	field_add(a, a, b);
	field_mult(b, x, y);
	return bitstr_is_equal(a, b);
}

void point_double(elem_t x, elem_t y)               /* double the point (x,y) */
{
	if (! bitstr_is_clear(x)) {
		elem_t a;
		field_invert(a, x);
		field_mult(a, a, y);
		field_add(a, a, x);
		field_mult(y, x, x);
		field_mult(x, a, a);
		field_add1(a);        
		field_add(x, x, a);
		field_mult(a, a, x);
		field_add(y, y, a);
	}
	else
		bitstr_clear(y);
}

/* add two points together (x1, y1) := (x1, y1) + (x2, y2) */
void point_add(elem_t x1, elem_t y1, const elem_t x2, const elem_t y2)
{
	if (! point_is_zero(x2, y2)) {
		if (point_is_zero(x1, y1))
			point_copy(x1, y1, x2, y2);
		else {
			if (bitstr_is_equal(x1, x2)) {
				if (bitstr_is_equal(y1, y2))
					point_double(x1, y1);
				else 
					point_set_zero(x1, y1);
			}
			else {
				elem_t a, b, c, d;
				field_add(a, y1, y2);
				field_add(b, x1, x2);
				field_invert(c, b);
				field_mult(c, c, a);
				field_mult(d, c, c);
				field_add(d, d, c);
				field_add(d, d, b);
				field_add1(d);
				field_add(x1, x1, d);
				field_mult(a, x1, c);
				field_add(a, a, d);
				field_add(y1, y1, a);
				bitstr_copy(x1, d);
			}
		}
	}
}

/******************************************************************************/

exp_t base_order;

/* point multiplication via double-and-add algorithm */
void point_mult(elem_t x, elem_t y, const exp_t exp)
{
	elem_t X, Y;
	int i;
	point_set_zero(X, Y);
	for(i = bitstr_sizeinbits(exp) - 1; i >= 0; i--) {
		point_double(X, Y);
		if (bitstr_getbit(exp, i))
			point_add(X, Y, x, y);
	}
	point_copy(x, y, X, Y);
}

/* draw a random value 'exp' with 1 <= exp < n */
void get_random_exponent(exp_t exp)
{
	char buf[4 * NUMWORDS];
   int fh, r, s;
   do {
      if ((fh = open(DEV_RANDOM, O_RDONLY)) < 0)
         FATAL(DEV_RANDOM);
      for(r = 0; r < 4 * NUMWORDS; r += s)
         if ((s = read(fh, buf + r, 4 * NUMWORDS - r)) <= 0)
            FATAL(DEV_RANDOM);
      if (close(fh) < 0)
         FATAL(DEV_RANDOM);
      bitstr_import(exp, buf);
      for(r = bitstr_sizeinbits(base_order) - 1; r < NUMWORDS * 32; r++)
         bitstr_clrbit(exp, r);
   } while(bitstr_is_clear(exp));
}

/******************************************************************************/

void XTEA_init_key(ptr_t *k, const char *key)
{
	k[0] = CHARS2INT(key);
	k[1] = CHARS2INT(key + 4);
	k[2] = CHARS2INT(key + 8); 
	k[3] = CHARS2INT(key + 12);
}

/* the XTEA block cipher */
void XTEA_encipher_block(char *data, const ptr_t *k)
{
	ptr_t sum = 0, delta = 0x9e3779b9, y, z;
	int i;
	y = CHARS2INT(data); z = CHARS2INT(data + 4);
	for(i = 0; i < 32; i++) {
		y += ((z << 4 ^ z >> 5) + z) ^ (sum + k[sum & 3]);
		sum += delta;
		z += ((y << 4 ^ y >> 5) + y) ^ (sum + k[sum >> 11 & 3]);
	}
	INT2CHARS(data, y); INT2CHARS(data + 4, z);
}
/* encrypt in CTR mode */
void XTEA_ctr_crypt(char *data, int size, const char *key) 
{
	ptr_t k[4], ctr = 0;
	int len, i;
	char buf[8];
	XTEA_init_key(k, key);
	while(size) {
		INT2CHARS(buf, 0); INT2CHARS(buf + 4, ctr++);
		XTEA_encipher_block(buf, k);
		len = MIN(8, size);
		for(i = 0; i < len; i++)
			*data++ ^= buf[i];
		size -= len;
	}
}

/* calculate the CBC MAC */
void XTEA_cbcmac(char *mac, const char *data, int size, const char *key)
{
	ptr_t k[4];
	int len, i;
	XTEA_init_key(k, key);
	INT2CHARS(mac, 0);
	INT2CHARS(mac + 4, size);
	XTEA_encipher_block(mac, k);
	while(size) {
		len = MIN(8, size);
		for(i = 0; i < len; i++)
			mac[i] ^= *data++;
		XTEA_encipher_block(mac, k);
		size -= len;
	}
}

/* modified(!) Davies-Meyer construction.*/
void XTEA_davies_meyer(char *out, const char *in, int ilen)
{
	ptr_t k[4];
	char buf[8];
	int i;
	memset(out, 0, 8);
	while(ilen--) {
		XTEA_init_key(k, in);
		memcpy(buf, out, 8);
		XTEA_encipher_block(buf, k);
		for(i = 0; i < 8; i++)
			out[i] ^= buf[i];
		in += 16;
	}
}

/******************************************************************************/

/* check that a given elem_t-pair is a valid point on the curve != 'o' */
int ECIES_embedded_public_key_validation(const elem_t Px, const elem_t Py)
{
	return (bitstr_sizeinbits(Px) > DEGREE) || (bitstr_sizeinbits(Py) > DEGREE) ||
		point_is_zero(Px, Py) || ! is_point_on_curve(Px, Py) ? -1 : 1;
}

/* same thing, but check also that (Px,Py) generates a group of order n */
int ECIES_public_key_validation(const char *Px, const char *Py)
{
	elem_t x, y;
	if ((bitstr_parse(x, Px) < 0) || (bitstr_parse(y, Py) < 0))
		return -1;
	if (ECIES_embedded_public_key_validation(x, y) < 0)
		return -1;
	point_mult(x, y, base_order);
	return point_is_zero(x, y) ? 1 : -1;
}

void ECIES_kdf(char *k1, char *k2, const elem_t Zx,     /* a non-standard KDF */
		const elem_t Rx, const elem_t Ry)
{
	int bufsize = (3 * (4 * NUMWORDS) + 1 + 15) & ~15;
	char buf[bufsize];
	memset(buf, 0, bufsize);
	bitstr_export(buf, Zx);
	bitstr_export(buf + 4 * NUMWORDS, Rx);
	bitstr_export(buf + 8 * NUMWORDS, Ry);
	buf[12 * NUMWORDS] = 0; XTEA_davies_meyer(k1, buf, bufsize / 16);
	buf[12 * NUMWORDS] = 1; XTEA_davies_meyer(k1 + 8, buf, bufsize / 16);
	buf[12 * NUMWORDS] = 2; XTEA_davies_meyer(k2, buf, bufsize / 16);
	buf[12 * NUMWORDS] = 3; XTEA_davies_meyer(k2 + 8, buf, bufsize / 16);
}

/* ECIES encryption; the resulting cipher text message will be
	(len + ECIES_OVERHEAD) bytes long */
void ECIES_encryption(char *msg, const char *text, int len, 
		const char *Px, const char *Py)
{
	elem_t Rx, Ry, Zx, Zy;
	char k1[16], k2[16];
	exp_t k;
	do {
		get_random_exponent(k);
		bitstr_parse(Zx, Px);
		bitstr_parse(Zy, Py);
		point_mult(Zx, Zy, k);
		point_double(Zx, Zy);                           /* cofactor h = 2 on B409 */
	} while(point_is_zero(Zx, Zy));
	point_copy(Rx, Ry, base_x, base_y);
	point_mult(Rx, Ry, k);
	ECIES_kdf(k1, k2, Zx, Rx, Ry);

	bitstr_export(msg, Rx);
	bitstr_export(msg + 4 * NUMWORDS, Ry);
	memcpy(msg + 8 * NUMWORDS, text, len);
	XTEA_ctr_crypt(msg + 8 * NUMWORDS, len, k1);
	XTEA_cbcmac(msg + 8 * NUMWORDS + len, msg + 8 * NUMWORDS, len, k2);
}

/* ECIES decryption */
int ECIES_decryption(char *text, const char *msg, int len, 
		const char *privkey)
{
	elem_t Rx, Ry, Zx, Zy;
	char k1[16], k2[16], mac[8];
	exp_t d;
	bitstr_import(Rx, msg);
	bitstr_import(Ry, msg + 4 * NUMWORDS);
	if (ECIES_embedded_public_key_validation(Rx, Ry) < 0)
		return -1;
	bitstr_parse(d, privkey);
	point_copy(Zx, Zy, Rx, Ry);
	point_mult(Zx, Zy, d);
	point_double(Zx, Zy);                             /* cofactor h = 2 on B409 */
	if (point_is_zero(Zx, Zy))
		return -1;
	ECIES_kdf(k1, k2, Zx, Rx, Ry);

	XTEA_cbcmac(mac, msg + 8 * NUMWORDS, len, k2);
	if (memcmp(mac, msg + 8 * NUMWORDS + len, 8))
		return -1;
	memcpy(text, msg + 8 * NUMWORDS, len);
	XTEA_ctr_crypt(text, len, k1);
	return 1;
}

/*
void encryption_decryption_demo(const char *text, const char *public_x,
      const char *public_y, const char *private)
{
	int len = strlen(text);
   char encrypted[1024 + ECIES_OVERHEAD];
   char decrypted[1024];

   printf("plain text: %s\n", text);
   ECIES_encryption(encrypted, text, len, public_x, public_y);

   if (ECIES_decryption(decrypted, encrypted, len, private) < 0)
      printf("decryption failed!\n");
   else
      printf("after encryption/decryption: %s\n", decrypted);
}

*/

/*
char *ECIES_public_x;
char *ECIES_public_y;
char *ECIES_private;
*/

void ECIES_init()
{
   bitstr_parse(poly, "2000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000001");
   bitstr_parse(coeff_b, "021a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f");
   bitstr_parse(base_x, "15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7");
   bitstr_parse(base_y, "061b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706");
   bitstr_parse(base_order, "10000000000000000000000000000000000000000000000000001e2aad6a612f33307be5Fa47c3c9e052f838164cd37d9a21173");

/*
	ECIES_public_x = "1ce57ca5b54032c4180c6c7b2d72cb9c5c193906f9853bc5abd666b85d45cf0485d2deda0e7611488ef49b8a3d030a659d77f8d";
	ECIES_public_y = "04dd80aebfa90861336c2f69e79f5e94a7ff8864b43ac16ecc2dd3890b109b8b83613893f5c6a39a2e39255156f5abbfb699261";
	ECIES_private  = "06a7a6c5fdd5f3a28874a90f33e8bba901685e28974a0146b958ff9af37501584468bfeaad58e3af70e3f6aa104a8b804b708f2";
*/

	/*
	      encryption_decryption_demo("This secret demo message will be ECIES encrypted",
      "1ce57ca5b54032c4180c6c7b2d72cb9c5c193906f9853bc5abd666b85d45cf0485d2deda0e7611488ef49b8a3d030a659d77f8d",
      "04dd80aebfa90861336c2f69e79f5e94a7ff8864b43ac16ecc2dd3890b109b8b83613893f5c6a39a2e39255156f5abbfb699261",
      "06a7a6c5fdd5f3a28874a90f33e8bba901685e28974a0146b958ff9af37501584468bfeaad58e3af70e3f6aa104a8b804b708f2");
	*/
}

/* TomsFastMath, a fast ISO C bignum library.
 *
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 *
 * Tom St Denis, tomstdenis@gmail.com
 */
#ifndef TFM_H_
#define TFM_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>

typedef struct tfm_fp_int_struct tfm_fp_int;

#include <silccrypto.h>

#undef CRYPT

#ifdef SILC_X86_64
#define TFM_X86_64
#endif /* SILC_X86_64 */

#ifdef SILC_I386
#define TFM_X86
#ifdef SILC_CPU_SSE2
#define TFM_SSE2
#endif /* SILC_CPU_SSE2 */
#endif /* SILC_I386 */

#ifndef MIN
   #define MIN(x,y) ((x)<(y)?(x):(y))
#endif

#ifndef MAX
   #define MAX(x,y) ((x)>(y)?(x):(y))
#endif

/* externally define this symbol to ignore the default settings, useful for changing the build from the make process */
#ifndef TFM_ALREADY_SET

/* do we want the large set of small multiplications ?
   Enable these if you are going to be doing a lot of small (<= 16 digit) multiplications say in ECC
   Or if you're on a 64-bit machine doing RSA as a 1024-bit integer == 16 digits ;-)
 */
#define TFM_SMALL_SET

/* do we want huge code
   Enable these if you are doing 20, 24, 28, 32, 48, 64 digit multiplications (useful for RSA)
   Less important on 64-bit machines as 32 digits == 2048 bits
 */
#define TFM_MUL20
#define TFM_MUL24
#define TFM_MUL28
#define TFM_MUL32
#define TFM_MUL48
#define TFM_MUL64

#define TFM_SQR20
#define TFM_SQR24
#define TFM_SQR28
#define TFM_SQR32
#define TFM_SQR48
#define TFM_SQR64

/* do we want some overflow checks
   Not required if you make sure your numbers are within range (e.g. by default a modulus for tfm_fp_exptmod() can only be upto 2048 bits long)
 */
#define TFM_CHECK

/* Is the target a P4 Prescott
 */
/* #define TFM_PRESCOTT */

/* Do we want timing resistant tfm_fp_exptmod() ?
 * This makes it slower but also timing invariant with respect to the exponent
 */
/* #define TFM_TIMING_RESISTANT */

#endif

/* Max size of any number in bits.  Basically the largest size you will be multiplying
 * should be half [or smaller] of TFM_FP_MAX_SIZE-four_digit
 *
 * You can externally define this or it defaults to 4096-bits [allowing multiplications upto 2048x2048 bits ]
 */
#ifndef TFM_FP_MAX_SIZE
   #define TFM_FP_MAX_SIZE           (8192+(8*DIGIT_BIT))
#endif

/* will this lib work? */
#if (CHAR_BIT & 7)
   #error CHAR_BIT must be a multiple of eight.
#endif
#if TFM_FP_MAX_SIZE % CHAR_BIT
   #error TFM_FP_MAX_SIZE must be a multiple of CHAR_BIT
#endif

/* autodetect x86-64 and make sure we are using 64-bit digits with x86-64 asm */
#if defined(__x86_64__)
   #if defined(TFM_X86) || defined(TFM_SSE2) || defined(TFM_ARM)
       #error x86-64 detected, x86-32/SSE2/ARM optimizations are not valid!
   #endif
   #if !defined(TFM_X86_64) && !defined(TFM_NO_ASM)
      #define TFM_X86_64
   #endif
#endif
#if defined(TFM_X86_64)
    #if !defined(TFM_FP_64BIT)
       #define TFM_FP_64BIT
    #endif
#endif

/* try to detect x86-32 */
#if defined(__i386__) && !defined(TFM_SSE2)
   #if defined(TFM_X86_64) || defined(TFM_ARM)
       #error x86-32 detected, x86-64/ARM optimizations are not valid!
   #endif
   #if !defined(TFM_X86) && !defined(TFM_NO_ASM)
      #define TFM_X86
   #endif
#endif

/* make sure we're 32-bit for x86-32/sse/arm/ppc32 */
#if (defined(TFM_X86) || defined(TFM_SSE2) || defined(TFM_ARM) || defined(TFM_PPC32)) && defined(TFM_FP_64BIT)
   #warning x86-32, SSE2 and ARM, PPC32 optimizations require 32-bit digits (undefining)
   #undef TFM_FP_64BIT
#endif

/* multi asms? */
#ifdef TFM_X86
   #define TFM_ASM
#endif
#ifdef TFM_X86_64
   #ifdef TFM_ASM
      #error TFM_ASM already defined!
   #endif
   #define TFM_ASM
#endif
#ifdef TFM_SSE2
   #ifdef TFM_ASM
      #error TFM_ASM already defined!
   #endif
   #define TFM_ASM
#endif
#ifdef TFM_ARM
   #ifdef TFM_ASM
      #error TFM_ASM already defined!
   #endif
   #define TFM_ASM
#endif
#ifdef TFM_PPC32
   #ifdef TFM_ASM
      #error TFM_ASM already defined!
   #endif
   #define TFM_ASM
#endif
#ifdef TFM_PPC64
   #ifdef TFM_ASM
      #error TFM_ASM already defined!
   #endif
   #define TFM_ASM
#endif
#ifdef TFM_AVR32
   #ifdef TFM_ASM
      #error TFM_ASM already defined!
   #endif
   #define TFM_ASM
#endif

/* we want no asm? */
#ifdef TFM_NO_ASM
   #undef TFM_X86
   #undef TFM_X86_64
   #undef TFM_SSE2
   #undef TFM_ARM
   #undef TFM_PPC32
   #undef TFM_PPC64
   #undef TFM_AVR32
   #undef TFM_ASM
#endif

/* ECC helpers */
#ifdef TFM_ECC192
   #ifdef TFM_FP_64BIT
       #define TFM_MUL3
       #define TFM_SQR3
   #else
       #define TFM_MUL6
       #define TFM_SQR6
   #endif
#endif

#ifdef TFM_ECC224
   #ifdef TFM_FP_64BIT
       #define TFM_MUL4
       #define TFM_SQR4
   #else
       #define TFM_MUL7
       #define TFM_SQR7
   #endif
#endif

#ifdef TFM_ECC256
   #ifdef TFM_FP_64BIT
       #define TFM_MUL4
       #define TFM_SQR4
   #else
       #define TFM_MUL8
       #define TFM_SQR8
   #endif
#endif

#ifdef TFM_ECC384
   #ifdef TFM_FP_64BIT
       #define TFM_MUL6
       #define TFM_SQR6
   #else
       #define TFM_MUL12
       #define TFM_SQR12
   #endif
#endif

#ifdef TFM_ECC521
   #ifdef TFM_FP_64BIT
       #define TFM_MUL9
       #define TFM_SQR9
   #else
       #define TFM_MUL17
       #define TFM_SQR17
   #endif
#endif


/* some default configurations.
 */
#if defined(TFM_FP_64BIT)
   /* for GCC only on supported platforms */
#ifndef CRYPT
   typedef SilcUInt64 ulong64;
#endif
   typedef ulong64            tfm_fp_digit;
   typedef unsigned long      tfm_fp_word __attribute__ ((mode(TI)));
#else
   /* this is to make porting into LibTomCrypt easier :-) */
#ifndef CRYPT
   #if defined(_MSC_VER) || defined(__BORLANDC__)
      typedef unsigned __int64   ulong64;
      typedef signed __int64     long64;
   #else
      typedef unsigned long long ulong64;
      typedef signed long long   long64;
   #endif
#endif
   typedef unsigned long      tfm_fp_digit;
   typedef ulong64            tfm_fp_word;
#endif

/* # of digits this is */
#define DIGIT_BIT  (int)((CHAR_BIT) * sizeof(tfm_fp_digit))
#define TFM_FP_MASK    (tfm_fp_digit)(-1)
#define TFM_FP_SIZE    (TFM_FP_MAX_SIZE/DIGIT_BIT)

/* signs */
#define TFM_FP_ZPOS     0
#define TFM_FP_NEG      1

/* return codes */
#define TFM_FP_OKAY     0
#define TFM_FP_VAL      1
#define TFM_FP_MEM      2

/* equalities */
#define TFM_FP_LT        -1   /* less than */
#define TFM_FP_EQ         0   /* equal to */
#define TFM_FP_GT         1   /* greater than */

/* replies */
#define TFM_FP_YES        1   /* yes response */
#define TFM_FP_NO         0   /* no response */

/* a FP type */
struct tfm_fp_int_struct {
  SilcStack stack;
  tfm_fp_digit *dp;
  unsigned int used;
  unsigned int alloc : 31;
  unsigned int sign  : 1;
};

/* functions */

/* initialize [or zero] an fp int */
#define tfm_fp_init(a) tfm_fp_sinit(NULL, a)
#define tfm_fp_sinit(s, a) 						\
  { (a)->stack = s; (a)->dp = NULL; (a)->alloc = (a)->used = (a)->sign = 0; }
int tfm_fp_init_size(SilcStack stack, tfm_fp_int *a, int size);
void tfm_fp_zero(tfm_fp_int *a);

/* zero/even/odd ? */
#define tfm_fp_iszero(a) (((a)->used == 0) ? TFM_FP_YES : TFM_FP_NO)
#define tfm_fp_iseven(a) (((a)->used >= 0 && (((a)->dp[0] & 1) == 0)) ? TFM_FP_YES : TFM_FP_NO)
#define tfm_fp_isodd(a)  (((a)->used > 0  && (((a)->dp[0] & 1) == 1)) ? TFM_FP_YES : TFM_FP_NO)

/* set to a small digit */
int tfm_fp_set(tfm_fp_int *a, tfm_fp_digit b);

/* copy from a to b */
int tfm_fp_copy(tfm_fp_int *a, tfm_fp_int *b);
int tfm_fp_init_copy(tfm_fp_int *a, tfm_fp_int *b, SilcStack stack);
void tfm_fp_exch(tfm_fp_int *a, tfm_fp_int *b);

/* clamp digits */
#define tfm_fp_clamp(a)   { while ((a)->used && (a)->dp[(a)->used-1] == 0) --((a)->used); (a)->sign = (a)->used ? (a)->sign : TFM_FP_ZPOS; }

/* negate and absolute */
#define tfm_fp_neg(a, b)  { tfm_fp_copy(a, b); (b)->sign ^= 1; tfm_fp_clamp(b); }
#define tfm_fp_abs(a, b)  { tfm_fp_copy(a, b); (b)->sign  = 0; }

/* right shift x digits */
void tfm_fp_rshd(tfm_fp_int *a, int x);

/* left shift x digits */
int tfm_fp_lshd(tfm_fp_int *a, int x);

/* signed comparison */
int tfm_fp_cmp(tfm_fp_int *a, tfm_fp_int *b);

/* unsigned comparison */
int tfm_fp_cmp_mag(tfm_fp_int *a, tfm_fp_int *b);

/* power of 2 operations */
int tfm_fp_div_2d(tfm_fp_int *a, int b, tfm_fp_int *c, tfm_fp_int *d);
int tfm_fp_mod_2d(tfm_fp_int *a, int b, tfm_fp_int *c);
int tfm_fp_mul_2d(tfm_fp_int *a, int b, tfm_fp_int *c);
int tfm_fp_2expt (tfm_fp_int *a, int b);
int tfm_fp_mul_2(tfm_fp_int *a, tfm_fp_int *c);
int tfm_fp_div_2(tfm_fp_int *a, tfm_fp_int *c);

/* Counts the number of lsbs which are zero before the first zero bit */
int tfm_fp_cnt_lsb(tfm_fp_int *a);

/* c = a + b */
int tfm_fp_add(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c);

/* c = a - b */
int tfm_fp_sub(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c);

/* c = a * b */
int tfm_fp_mul(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c);

/* b = a*a  */
int tfm_fp_sqr(tfm_fp_int *a, tfm_fp_int *b);

/* a/b => cb + d == a */
int tfm_fp_div(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c, tfm_fp_int *d);

/* c = a mod b, 0 <= c < b  */
int tfm_fp_mod(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c);

/* compare against a single digit */
int tfm_fp_cmp_d(tfm_fp_int *a, tfm_fp_digit b);

/* c = a + b */
int tfm_fp_add_d(tfm_fp_int *a, tfm_fp_digit b, tfm_fp_int *c);

/* c = a - b */
int tfm_fp_sub_d(tfm_fp_int *a, tfm_fp_digit b, tfm_fp_int *c);

/* c = a * b */
int tfm_fp_mul_d(tfm_fp_int *a, tfm_fp_digit b, tfm_fp_int *c);

/* a/b => cb + d == a */
int tfm_fp_div_d(tfm_fp_int *a, tfm_fp_digit b, tfm_fp_int *c, tfm_fp_digit *d);

/* c = a mod b, 0 <= c < b  */
int tfm_fp_mod_d(tfm_fp_int *a, tfm_fp_digit b, tfm_fp_digit *c);

/* ---> number theory <--- */
/* d = a + b (mod c) */
int tfm_fp_addmod(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c, tfm_fp_int *d);

/* d = a - b (mod c) */
int tfm_fp_submod(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c, tfm_fp_int *d);

/* d = a * b (mod c) */
int tfm_fp_mulmod(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c, tfm_fp_int *d);

/* c = a * a (mod b) */
int tfm_fp_sqrmod(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c);

/* c = 1/a (mod b) */
int tfm_fp_invmod(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c);

/* c = (a, b) */
int tfm_fp_gcd(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c);

/* c = [a, b] */
int tfm_fp_lcm(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c);

int tfm_fp_sqrt(tfm_fp_int *arg, tfm_fp_int *ret);
int tfm_fp_expt_d(tfm_fp_int * a, tfm_fp_digit b, tfm_fp_int * c);
int tfm_fp_xor(tfm_fp_int * a, tfm_fp_int * b, tfm_fp_int * c);
int tfm_fp_and(tfm_fp_int * a, tfm_fp_int * b, tfm_fp_int * c);
int tfm_fp_or(tfm_fp_int * a, tfm_fp_int * b, tfm_fp_int * c);

/* setups the montgomery reduction */
int tfm_fp_montgomery_setup(tfm_fp_int *a, tfm_fp_digit *mp);

/* computes a = B**n mod b without division or multiplication useful for
 * normalizing numbers in a Montgomery system.
 */
int tfm_fp_montgomery_calc_normalization(tfm_fp_int *a, tfm_fp_int *b);

/* computes x/R == x (mod N) via Montgomery Reduction */
int tfm_fp_montgomery_reduce(tfm_fp_int *a, tfm_fp_int *m, tfm_fp_digit mp);

/* d = a**b (mod c) */
int tfm_fp_exptmod(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c, tfm_fp_int *d);

/* radix conersions */
int tfm_fp_count_bits(tfm_fp_int *a);

int tfm_fp_unsigned_bin_size(tfm_fp_int *a);
void tfm_fp_read_unsigned_bin(tfm_fp_int *a, unsigned char *b, int c);
void tfm_fp_to_unsigned_bin(tfm_fp_int *a, unsigned char *b);

int tfm_fp_signed_bin_size(tfm_fp_int *a);
void tfm_fp_to_signed_bin(tfm_fp_int *a, unsigned char *b);

int tfm_fp_read_radix(tfm_fp_int *a, char *str, int radix);
int tfm_fp_toradix(tfm_fp_int *a, char *str, int radix);
int tfm_fp_toradix_n(tfm_fp_int * a, char *str, int radix, int maxlen);
int tfm_fp_radix_size(tfm_fp_int *a, int radix, int *size);


/* VARIOUS LOW LEVEL STUFFS */
int s_tfm_fp_add(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c);
int s_tfm_fp_sub(tfm_fp_int *a, tfm_fp_int *b, tfm_fp_int *c);
void tfm_fp_reverse(unsigned char *s, int len);

int tfm_fp_mul_comba(tfm_fp_int *A, tfm_fp_int *B, tfm_fp_int *C);

#ifdef TFM_SMALL_SET
void tfm_fp_mul_comba_small(tfm_fp_int *A, tfm_fp_int *B, tfm_fp_int *C);
#endif

#ifdef TFM_MUL20
void tfm_fp_mul_comba20(tfm_fp_int *A, tfm_fp_int *B, tfm_fp_int *C);
#endif
#ifdef TFM_MUL24
void tfm_fp_mul_comba24(tfm_fp_int *A, tfm_fp_int *B, tfm_fp_int *C);
#endif
#ifdef TFM_MUL28
void tfm_fp_mul_comba28(tfm_fp_int *A, tfm_fp_int *B, tfm_fp_int *C);
#endif
#ifdef TFM_MUL32
void tfm_fp_mul_comba32(tfm_fp_int *A, tfm_fp_int *B, tfm_fp_int *C);
#endif
#ifdef TFM_MUL48
void tfm_fp_mul_comba48(tfm_fp_int *A, tfm_fp_int *B, tfm_fp_int *C);
#endif
#ifdef TFM_MUL64
void tfm_fp_mul_comba64(tfm_fp_int *A, tfm_fp_int *B, tfm_fp_int *C);
#endif

int tfm_fp_sqr_comba(tfm_fp_int *A, tfm_fp_int *B);

#ifdef TFM_SMALL_SET
void tfm_fp_sqr_comba_small(tfm_fp_int *A, tfm_fp_int *B);
#endif

#ifdef TFM_SQR20
void tfm_fp_sqr_comba20(tfm_fp_int *A, tfm_fp_int *B);
#endif
#ifdef TFM_SQR24
void tfm_fp_sqr_comba24(tfm_fp_int *A, tfm_fp_int *B);
#endif
#ifdef TFM_SQR28
void tfm_fp_sqr_comba28(tfm_fp_int *A, tfm_fp_int *B);
#endif
#ifdef TFM_SQR32
void tfm_fp_sqr_comba32(tfm_fp_int *A, tfm_fp_int *B);
#endif
#ifdef TFM_SQR48
void tfm_fp_sqr_comba48(tfm_fp_int *A, tfm_fp_int *B);
#endif
#ifdef TFM_SQR64
void tfm_fp_sqr_comba64(tfm_fp_int *A, tfm_fp_int *B);
#endif

#endif

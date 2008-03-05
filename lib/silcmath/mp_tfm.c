/*

  mp_tfm.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silccrypto.h"
#include "mp_tfm.h"

static void silc_mp_set_errno(int err)
{
  if (err == TFM_FP_VAL)
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
  else if (err == TFM_FP_MEM)
    silc_set_errno(SILC_ERR_OUT_OF_MEMORY);
}

SilcBool silc_mp_init(SilcMPInt *mp)
{
  tfm_fp_init(mp);
  return TRUE;
}

SilcBool silc_mp_sinit(SilcStack stack, SilcMPInt *mp)
{
  if (stack)
    stack = silc_stack_alloc(0, stack);
  tfm_fp_sinit(stack, mp);
  return TRUE;
}

void silc_mp_uninit(SilcMPInt *mp)
{
  tfm_fp_zero(mp);
}

size_t silc_mp_size(SilcMPInt *mp)
{
  return tfm_fp_unsigned_bin_size(mp);
}

size_t silc_mp_sizeinbase(SilcMPInt *mp, int base)
{
  int size = 0;
  tfm_fp_radix_size(mp, base, &size);
  if (size > 1)
    size--;
  return size;
}

SilcBool silc_mp_set(SilcMPInt *dst, SilcMPInt *src)
{
  int ret;
  if ((ret = tfm_fp_copy(src, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_set_ui(SilcMPInt *dst, SilcUInt32 ui)
{
  int ret;
  if ((ret = tfm_fp_set(dst, ui))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_set_si(SilcMPInt *dst, SilcInt32 si)
{
  int ret;
  if ((ret = tfm_fp_set(dst, si))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_set_str(SilcMPInt *dst, const char *str, int base)
{
  int ret;
  if ((ret = tfm_fp_read_radix(dst, (char *)str, base))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcUInt32 silc_mp_get_ui(SilcMPInt *mp)
{
  tfm_fp_int *tmp = mp;
  return tmp->used > 0 ? tmp->dp[0] : 0;
}

char *silc_mp_get_str(char *str, SilcMPInt *mp, int base)
{
  if (tfm_fp_toradix(mp, str, base) != TFM_FP_OKAY)
    return NULL;
  return str;
}

SilcBool silc_mp_add(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  int ret;
  if ((ret = tfm_fp_add(mp1, mp2, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_add_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  int ret;
  if ((ret = tfm_fp_add_d(mp1, (tfm_fp_digit)ui, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_sub(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  int ret;
  if ((ret = tfm_fp_sub(mp1, mp2, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_sub_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  int ret;
  if ((ret = tfm_fp_sub_d(mp1, (tfm_fp_digit)ui, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_mul(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  int ret;
  if ((ret = tfm_fp_mul(mp1, mp2, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_mul_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  int ret;
  if ((ret = tfm_fp_mul_d(mp1, (tfm_fp_digit)ui, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_mul_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  int ret;
  if ((ret = tfm_fp_mul_2d(mp1, exp, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_sqrt(SilcMPInt *dst, SilcMPInt *src)
{
  int ret;
  if ((ret = tfm_fp_sqrt(src, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_div(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  int ret;
  if ((ret = tfm_fp_div(mp1, mp2, dst, NULL))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_div_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  int ret;
  if ((ret = tfm_fp_div_d(mp1, (tfm_fp_digit)ui, dst, NULL))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_div_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1,
		    SilcMPInt *mp2)
{
  int ret;
  if ((ret = tfm_fp_div(mp1, mp2, q, r))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_div_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  int ret;
  if ((ret = tfm_fp_div_2d(mp1, exp, dst, NULL))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_div_2exp_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1,
			 SilcUInt32 exp)
{
  int ret;
  if ((ret = tfm_fp_div_2d(mp1, exp, q, r))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  int ret;
  if ((ret = tfm_fp_mod(mp1, mp2, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  tfm_fp_digit d;
  int ret;

  if ((ret = tfm_fp_mod_d(mp1, ui, &d))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  if ((ret = silc_mp_set_ui(dst, d))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_mod_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  int ret;
  if ((ret = tfm_fp_mod_2d(mp1, ui, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_pow_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  int ret;
  if ((ret = tfm_fp_expt_d(mp1, (tfm_fp_digit)exp, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_pow_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp,
		     SilcMPInt *mod)
{
  int ret;
  if ((ret = tfm_fp_exptmod(mp1, exp, mod, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_pow_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp,
			    SilcMPInt *mod)
{
  SilcMPInt tmp;
  int ret;

  if ((ret = silc_mp_init(&tmp))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  if ((ret = silc_mp_set_ui(&tmp, exp))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  if ((ret = silc_mp_pow_mod(dst, mp1, &tmp, mod))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  silc_mp_uninit(&tmp);
  return TRUE;
}

SilcBool silc_mp_gcd(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  int ret;
  if ((ret = tfm_fp_gcd(mp1, mp2, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

int silc_mp_cmp(SilcMPInt *mp1, SilcMPInt *mp2)
{
  return tfm_fp_cmp(mp1, mp2);
}

int silc_mp_cmp_si(SilcMPInt *mp1, SilcInt32 si)
{
  return tfm_fp_cmp_d(mp1, si);
}

int silc_mp_cmp_ui(SilcMPInt *mp1, SilcUInt32 ui)
{
  return tfm_fp_cmp_d(mp1, ui);
}

SilcBool silc_mp_abs(SilcMPInt *dst, SilcMPInt *src)
{
  tfm_fp_abs(src, dst);
  return TRUE;
}

SilcBool silc_mp_neg(SilcMPInt *dst, SilcMPInt *src)
{
  tfm_fp_neg(src, dst);
  return TRUE;
}

SilcBool silc_mp_and(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  int ret;
  if ((ret = tfm_fp_and(mp1, mp2, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_or(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  int ret;
  if ((ret = tfm_fp_or(mp1, mp2, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_xor(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  int ret;
  if ((ret = tfm_fp_xor(mp1, mp2, dst))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

SilcBool silc_mp_modinv(SilcMPInt *inv, SilcMPInt *a, SilcMPInt *n)
{
  int ret;
  if ((ret = tfm_fp_invmod(a, n, inv))) {
    silc_mp_set_errno(ret);
    return FALSE;
  }
  return TRUE;
}

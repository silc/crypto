/*

  mpbin.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silccrypto.h"

/* Encodes MP integer into binary data. Returns allocated data that
   must be free'd by the caller. If `len' is provided the destination
   buffer is allocated that large. If zero then the size is approximated. */

unsigned char *silc_mp_mp2bin(SilcMPInt *val, SilcUInt32 len,
			      SilcUInt32 *ret_len)
{
  SilcUInt32 size;
  unsigned char *ret;

  size = (len ? len : ((silc_mp_sizeinbase(val, 2) + 7) / 8));
  ret = silc_calloc(size, sizeof(*ret));
  if (!ret)
    return NULL;

  silc_mp_mp2bin_noalloc(val, ret, size);

  if (ret_len)
    *ret_len = size;

  return ret;
}

/* Samve as above but does not allocate any memory.  The encoded data is
   returned into `dst' and it's length to the `ret_len'. */

void silc_mp_mp2bin_noalloc(SilcMPInt *val, unsigned char *dst,
			    SilcUInt32 dst_len)
{
  int i;
  SilcUInt32 size = dst_len;
  SilcMPInt tmp;

  silc_mp_init(&tmp);
  silc_mp_set(&tmp, val);

  for (i = size; i > 0; i--) {
    dst[i - 1] = (unsigned char)(silc_mp_get_ui(&tmp) & 0xff);
    silc_mp_div_2exp(&tmp, &tmp, 8);
  }

  silc_mp_uninit(&tmp);
}

/* Decodes binary data into MP integer. The integer sent as argument
   must be initialized. */

void silc_mp_bin2mp(unsigned char *data, SilcUInt32 len, SilcMPInt *ret)
{
  int i;

  silc_mp_set_ui(ret, 0);

  for (i = 0; i < len; i++) {
    silc_mp_mul_2exp(ret, ret, 8);
    silc_mp_add_ui(ret, ret, data[i]);
  }
}

/* MP integer encoding with silc_buffer_format. */

int silc_mp_format(SilcStack stack, SilcBuffer buffer,
		   void *value, void *context)
{
  SilcMPInt *mp = value;
  unsigned char *m;
  SilcUInt32 m_len;
  int ret;

  /* Encode */
  m = silc_mp_mp2bin(mp, 0, &m_len);
  if (!m)
    return -1;

  ret = silc_buffer_sformat(stack, buffer,
			    SILC_STR_UINT32(m_len),
			    SILC_STR_DATA(m, m_len),
			    SILC_STR_END);

  silc_free(m);

  return ret;
}

/* MP integer decoding with silc_buffer_unformat. */

int silc_mp_unformat(SilcStack stack, SilcBuffer buffer,
		     void **value, void *context)
{
  SilcMPInt *mp = *value;
  unsigned char *m;
  SilcUInt32 m_len;
  int ret;

  ret = silc_buffer_sunformat(stack, buffer,
			      SILC_STR_UI32_NSTRING(&m, &m_len),
			      SILC_STR_END);
  if (ret < 0)
    return ret;

  silc_mp_bin2mp(m, m_len, mp);

  return ret;
}

/*

  softacc.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 -  2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silccrypto.h"
#include "softacc.h"
#include "softacc_i.h"

/* Software accelerator is a thread-pool system where computationally
   expensive operations are executed in multiple threads for the purpose of
   off-loading and balancing the computations across multiple processors. */

/************************** Types and definitions ***************************/

/* Software accelerator operations */
const SilcAcceleratorStruct silc_softacc =
{
  "softacc", silc_softacc_init, silc_softacc_uninit,
#ifdef SILC_DIST_SOFTACC_PKCS
  softacc_pkcs,
#else /* !SILC_DIST_SOFTACC_PKCS */
  NULL,
#endif /* SILC_DIST_SOFTACC_PKCS */
#ifdef SILC_DIST_SOFTACC_CIPHER
  softacc_cipher,
#else /* !SILC_DIST_SOFTACC_CIPHER */
  NULL,
#endif /* SILC_DIST_SOFTACC_CIPHER */
};

/***************************** Accelerator API ******************************/

/* Initialize software accelerator */

SilcBool silc_softacc_init(SilcSchedule schedule, va_list va)
{
  SilcSoftacc sa;
  char *opt;

  /* If already initialized, uninitialize first. */
  sa = silc_global_get_var("softacc", FALSE);
  if (sa)
    silc_softacc_uninit();

  sa = silc_global_set_var("softacc", sizeof(*sa), NULL, FALSE);
  if (!sa)
    return FALSE;

  sa->schedule = schedule;
  sa->min_threads = SILC_SOFTACC_MIN_THREADS;
  sa->max_threads = SILC_SOFTACC_MAX_THREADS;
  sa->cipher_threads = SILC_SOFTACC_CIPHER_THREADS;
  sa->cipher_blocks = SILC_SOFTACC_CIPHER_BLOCKS;
  sa->cipher_streams = SILC_SOFTACC_CIPHER_STREAMS;

  /* Get options */
  while ((opt = va_arg(va, char *))) {
    if (!strcmp(opt, "min_threads"))
      sa->min_threads = va_arg(va, SilcUInt32);
    else if (!strcmp(opt, "max_threads"))
      sa->max_threads = va_arg(va, SilcUInt32);
    else if (!strcmp(opt, "cipher_threads"))
      sa->cipher_threads = va_arg(va, SilcUInt32);
    else if (!strcmp(opt, "cipher_blocks"))
      sa->cipher_blocks = va_arg(va, SilcUInt32);
    else if (!strcmp(opt, "cipher_streams"))
      sa->cipher_streams = va_arg(va, SilcUInt32);
  }

  if (!sa->cipher_streams || !sa->cipher_blocks || !sa->cipher_threads)
    return FALSE;

  SILC_LOG_DEBUG(("Initialize software accelerator, min_threads %d, "
		  "max_threads %d", sa->min_threads, sa->max_threads));

  /* Start the thread pool */
  sa->tp = silc_thread_pool_alloc(NULL, sa->min_threads,
				  sa->max_threads, TRUE);
  if (!sa->tp) {
    silc_global_del_var("softacc", FALSE);
    return FALSE;
  }

  return TRUE;
}

/* Uninitialize */

SilcBool silc_softacc_uninit(void)
{
  SilcSoftacc sa;

  sa = silc_global_get_var("softacc", FALSE);
  if (!sa)
    return FALSE;

  SILC_LOG_DEBUG(("Uninitialize software accelerator"));

  silc_thread_pool_free(sa->tp, TRUE);
  silc_global_del_var("softacc", FALSE);

  return TRUE;
}

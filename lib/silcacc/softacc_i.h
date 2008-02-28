/*

  softacc_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SOFTACC_I_H
#define SOFTACC_I_H

#if SILC_SOFTACC_DEBUG_ON == 1
#define SILC_SOFTACC_DEBUG(fmt) SILC_LOG_DEBUG(fmt)
#else
#define SILC_SOFTACC_DEBUG(fmt)
#endif /* SILC_SOFTACC_DEBUG_ON == 1 */

/* Defaults */
#define SILC_SOFTACC_MIN_THREADS 0
#define SILC_SOFTACC_MAX_THREADS 4
#define SILC_SOFTACC_CIPHER_THREADS 2
#define SILC_SOFTACC_CIPHER_BLOCKS 4096
#define SILC_SOFTACC_CIPHER_STREAMS (SILC_SOFTACC_CIPHER_THREADS * 2)

/* Software accelerator context */
typedef struct {
  SilcSchedule schedule;	         /* Scheduler */
  SilcThreadPool tp;			 /* The thread pool */

  /* Options */
  SilcUInt32 min_threads;
  SilcUInt32 max_threads;
  SilcUInt32 cipher_threads;
  SilcUInt32 cipher_blocks;
  SilcUInt32 cipher_streams;
} *SilcSoftacc;

/* Accelerator API */
SilcBool silc_softacc_init(SilcSchedule schedule, va_list va);
SilcBool silc_softacc_uninit(void);

#ifdef SILC_DIST_SOFTACC_PKCS
extern const SilcPKCSAlgorithm softacc_pkcs[];

SILC_PKCS_ALG_IMPORT_PUBLIC_KEY(silc_softacc_acc_public_key);
SILC_PKCS_ALG_PUBLIC_KEY_FREE(silc_softacc_free_public_key);
SILC_PKCS_ALG_IMPORT_PRIVATE_KEY(silc_softacc_acc_private_key);
SILC_PKCS_ALG_PRIVATE_KEY_FREE(silc_softacc_free_private_key);
SILC_PKCS_ALG_ENCRYPT(silc_softacc_encrypt);
SILC_PKCS_ALG_DECRYPT(silc_softacc_decrypt);
SILC_PKCS_ALG_SIGN(silc_softacc_sign);
SILC_PKCS_ALG_VERIFY(silc_softacc_verify);
#endif /* SILC_DIST_SOFTACC_PKCS */

#ifdef SILC_DIST_SOFTACC_CIPHER
extern const SilcCipherObject softacc_cipher[];

SILC_CIPHER_API_SET_KEY(softacc_cipher_aes);
SILC_CIPHER_API_ENCRYPT(softacc_cipher_aes);
SILC_CIPHER_API_SET_IV(softacc_cipher_aes);

SILC_CIPHER_API_SET_KEY(softacc_cipher);
SILC_CIPHER_API_SET_IV(softacc_cipher);
SILC_CIPHER_API_ENCRYPT(softacc_cipher);
SILC_CIPHER_API_INIT(softacc_cipher);
SILC_CIPHER_API_UNINIT(softacc_cipher);
#endif /* SILC_DIST_SOFTACC_CIPHER */

#endif /* SOFTACC_I_H */

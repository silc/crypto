/*

  silcacc_cipher.c

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

#include "silccrypto.h"

/************************** Types and definitions ***************************/

SILC_CIPHER_API_SET_KEY(acc_cipher);
SILC_CIPHER_API_SET_IV(acc_cipher);
SILC_CIPHER_API_ENCRYPT(acc_cipher);
SILC_CIPHER_API_DECRYPT(acc_cipher);
SILC_CIPHER_API_INIT(acc_cipher);
SILC_CIPHER_API_UNINIT(acc_cipher);

/* Accelerated cipher */
typedef struct SilcAcceleratorCipherStruct {
  SilcCipher cipher;		/* Associated cipher */
  SilcCipher acc_cipher;	/* Accelerator cipher */
} *SilcAcceleratorCipher;

/************************** Accelerator Cipher API **************************/

/* The Cipher API for the accelerated cipher is simply a wrapper.  It
   calls the SILC Cipher API for the accelerator cipher. */

const SilcCipherObject silc_acc_ciph =
{
  "silc_acc_cipher",
  "silc_acc_cipher",

  silc_acc_cipher_set_key,
  silc_acc_cipher_set_iv,
  silc_acc_cipher_encrypt,
  silc_acc_cipher_decrypt,
  silc_acc_cipher_init,
  silc_acc_cipher_uninit,

  0, 0, 0, 0
};

SILC_CIPHER_API_SET_KEY(acc_cipher)
{
  SilcAcceleratorCipher c = context;

  /* Set key for the associated cipher too */
  silc_cipher_set_key(c->cipher, key, keylen, encryption);

  /* Set key for accelerator */
  return silc_cipher_set_key(c->acc_cipher, key, keylen, encryption);
}

SILC_CIPHER_API_SET_IV(acc_cipher)
{
  SilcAcceleratorCipher c = context;

  /* Set IV for the associated cipher too */
  silc_cipher_set_iv(c->cipher, iv);

  /* Set IV for accelerator */
  silc_cipher_set_iv(c->acc_cipher, iv);
}

SILC_CIPHER_API_ENCRYPT(acc_cipher)
{
  SilcAcceleratorCipher c = context;
  return silc_cipher_encrypt(c->acc_cipher, src, dst, len, iv);
}

SILC_CIPHER_API_DECRYPT(acc_cipher)
{
  SilcAcceleratorCipher c = context;
  return silc_cipher_decrypt(c->acc_cipher, src, dst, len, iv);
}

SILC_CIPHER_API_INIT(acc_cipher)
{
  /* This operation is never called */
  return NULL;
}

SILC_CIPHER_API_UNINIT(acc_cipher)
{
  SilcAcceleratorCipher c = context;
  SilcCipherObject *acc_ops = c->acc_cipher->cipher;

  /* Free the accelerator cipher and its operations we allocated earlier. */
  silc_cipher_free(c->acc_cipher);
  silc_free(acc_ops);

  /* Free our operations too */
  silc_free(ops);
}

/*************************** SILC Accelerator API ***************************/

/* Accelerate cipher */

SilcCipher silc_acc_cipher(SilcAccelerator acc, SilcCipher cipher)
{
  SilcCipher c;
  SilcAcceleratorCipher acc_cipher;
  const SilcCipherObject *alg;
  int i;

  if (!acc || !cipher)
    return NULL;

  SILC_LOG_DEBUG(("Accelerate cipher %p with accelerator %s",
		  cipher, acc->name));

  if (!acc->cipher) {
    SILC_LOG_ERROR(("Accelerator '%s' does not support cipher acceleration ",
		    acc->name));
    return NULL;
  }

  if (silc_acc_get_cipher(NULL, cipher)) {
    SILC_LOG_DEBUG(("Cipher %p is already accelerated", cipher));
    return NULL;
  }

  /* Check that accelerator supports this cipher algorithm */
  alg = cipher->cipher;
  for (i = 0; acc->cipher[i].alg_name; i++) {
    if ((!strcmp(acc->cipher[i].alg_name, alg->alg_name) ||
	 !strcmp(acc->cipher[i].alg_name, "any")) &&
	(acc->cipher[i].mode == alg->mode ||
	 acc->cipher[i].mode == 0) &&
	(acc->cipher[i].key_len == alg->key_len ||
	 acc->cipher[i].key_len == 0)) {
      alg = NULL;
      break;
    }
  }
  if (alg) {
    SILC_LOG_DEBUG(("Accelerator %s does not support %s (mode %d) "
		    "acceleration", acc->name, alg->name, alg->mode));
    return NULL;
  }

  /* Allocate cipher context for the SILC Cipher API */
  c = silc_calloc(1, sizeof(*c));
  if (!c)
    return NULL;

  /* Allocate cipher operations */
  c->cipher = silc_calloc(1, sizeof(SilcCipherObject));
  if (!c->cipher) {
    silc_free(c);
    return NULL;
  }
  *c->cipher = silc_acc_ciph;

  /* Allocate cipher context */
  c->context = acc_cipher = silc_calloc(1, sizeof(*acc_cipher));
  if (!acc_cipher) {
    silc_free(c->cipher);
    silc_free(c);
    return NULL;
  }
  acc_cipher->cipher = cipher;

  /* Allocate the actual algorithm accelerator. */
  acc_cipher->acc_cipher = silc_calloc(1, sizeof(*acc_cipher->acc_cipher));
  if (!acc_cipher->acc_cipher) {
    silc_free(c->cipher);
    silc_free(c);
    silc_free(acc_cipher);
  }

  /* Initialize the algorithm accelerator */
  acc_cipher->acc_cipher->context =
    acc->cipher[i].init((struct SilcCipherObjectStruct *)&acc->cipher[i]);
  if (!acc_cipher->acc_cipher->context) {
    silc_free(c->cipher);
    silc_free(c);
    silc_free(acc_cipher->acc_cipher);
    silc_free(acc_cipher);
    return NULL;
  }

  /* Allocate algorithm accelerator operations */
  acc_cipher->acc_cipher->cipher = silc_calloc(1, sizeof(SilcCipherObject));
  if (!acc_cipher->acc_cipher->cipher) {
    silc_free(c->cipher);
    silc_free(c);
    silc_free(acc_cipher->acc_cipher->context);
    silc_free(acc_cipher->acc_cipher);
    silc_free(acc_cipher);
    return NULL;
  }

  /* Set algorithm accelerator operations.  They are copied from the
     accelerator, but algorithm specific things come from associated
     cipher.  This way accelerators get the associated cipher details. */
  *acc_cipher->acc_cipher->cipher = acc->cipher[i];
  acc_cipher->acc_cipher->cipher->alg_name =
    (char *)silc_cipher_get_alg_name(cipher);
  acc_cipher->acc_cipher->cipher->key_len = silc_cipher_get_key_len(cipher);
  acc_cipher->acc_cipher->cipher->block_len =
    silc_cipher_get_block_len(cipher);
  acc_cipher->acc_cipher->cipher->iv_len = silc_cipher_get_iv_len(cipher);

  /* Set for the accelerator cipher too */
  c->cipher->key_len = silc_cipher_get_key_len(cipher);
  c->cipher->block_len = silc_cipher_get_block_len(cipher);
  c->cipher->iv_len = silc_cipher_get_iv_len(cipher);

  /* Start the accelerator.  The accelerator is started by setting key
     with NULL key. */
  if (!silc_cipher_set_key(acc_cipher->acc_cipher, NULL, 0, FALSE)) {
    SilcCipherObject *ops = acc_cipher->acc_cipher->cipher;
    silc_cipher_free(acc_cipher->acc_cipher);
    silc_free(ops);
    silc_free(c->cipher);
    silc_free(c);
    return NULL;
  }

  SILC_LOG_DEBUG(("New accelerated cipher %p", c));

  return c;
}

/* Return underlaying cipher from accelerated cipher. */

SilcCipher silc_acc_get_cipher(SilcAccelerator acc, SilcCipher cipher)
{
  SilcAcceleratorCipher acc_cipher;

  if (!cipher || cipher->cipher != &silc_acc_ciph)
    return NULL;

  acc_cipher = cipher->context;

  return acc_cipher->cipher;
}

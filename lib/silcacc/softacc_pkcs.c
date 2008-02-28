/*

  softacc_pkcs.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 - 2008 Pekka Riikonen

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

/* The public and private key accelerator.  We perform the public key and
   private key operations in threads.  Threads are run in the thread pool. */

/************************** Types and definitions ***************************/

/* Software accelerator PKCS algorithm operations */
const SilcPKCSAlgorithm softacc_pkcs[] =
{
  {
    "any", "any", NULL, NULL,
    silc_softacc_acc_public_key,
    NULL, NULL, NULL, NULL,
    silc_softacc_free_public_key,
    silc_softacc_acc_private_key,
    NULL, NULL,
    silc_softacc_free_private_key,
    silc_softacc_encrypt,
    silc_softacc_decrypt,
    silc_softacc_sign,
    silc_softacc_verify,
  },

  {
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL
  }
};

/* Software accelerator public key */
typedef struct {
  SilcPublicKey key;			 /* Accelerated public key */
} *SilcSoftaccPublicKey;

/* Software accelerator private key */
typedef struct {
  SilcPrivateKey key;			 /* Accelerated private key */
} *SilcSoftaccPrivateKey;

/* Execution types */
typedef enum {
  SILC_SOFTACC_ENCRYPT,
  SILC_SOFTACC_DECRYPT,
  SILC_SOFTACC_SIGN,
  SILC_SOFTACC_VERIFY,
} SilcSoftaccType;

/* Executor context */
typedef struct {
  SilcStack stack;			 /* Executor stack */
  void *context;			 /* Callback context */
  SilcSoftaccType type;			 /* Execution type */
  SilcAsyncOperationStruct op;		 /* Operation for aborting */

  unsigned char *src;			 /* Source data */
  unsigned char *data;			 /* More source data */
  SilcUInt32 src_len;
  SilcUInt32 data_len;
  SilcHash hash;			 /* Hash function to use */
  SilcRng rng;				 /* RNG, may be NULL */

  union {
    SilcPublicKey public_key;
    SilcPrivateKey private_key;
  } key;

  union {
    SilcPKCSEncryptCb encrypt_cb;
    SilcPKCSDecryptCb decrypt_cb;
    SilcPKCSSignCb sign_cb;
    SilcPKCSVerifyCb verify_cb;
  } cb;

  unsigned char *result_data;
  SilcUInt32 result_len;

  unsigned int result       : 1;
  unsigned int compute_hash : 1;
  unsigned int aborted      : 1;
} *SilcSoftaccExec;

/****************************** PKCS ALG API ********************************/

/* Abort operation */

void silc_softacc_pkcs_abort(SilcAsyncOperation op, void *context)
{
  SilcSoftaccExec e = context;
  e->aborted = TRUE;
}

/* Accelerator completion, executed in main thread. */

SILC_TASK_CALLBACK(silc_softacc_pkcs_completion)
{
  SilcSoftaccExec e = context;
  SilcStack stack = e->stack;

  /* At the latest, abort is catched here in the main thread.  Don't
     deliver callback if we were aborted */
  if (e->aborted)
    goto out;

  SILC_LOG_DEBUG(("Call completion, result=%s", e->result ? "Ok" : "failed"));

  /* Call completion callback */
  switch (e->type) {
  case SILC_SOFTACC_ENCRYPT:
    e->cb.encrypt_cb(e->result, e->result_data, e->result_len, e->context);
    break;

  case SILC_SOFTACC_DECRYPT:
    e->cb.decrypt_cb(e->result, e->result_data, e->result_len, e->context);
    break;

  case SILC_SOFTACC_SIGN:
    e->cb.sign_cb(e->result, e->result_data, e->result_len, e->context);
    break;

  case SILC_SOFTACC_VERIFY:
    e->cb.verify_cb(e->result, e->context);
    break;
  }

 out:
  silc_sfree(stack, e->src);
  silc_sfree(stack, e->data);
  silc_sfree(stack, e->result_data);
  silc_sfree(stack, e);
  silc_stack_free(stack);
}

/* Callback for encrypt, decrypt and signature */

void silc_softacc_pkcs_data_cb(SilcBool success, const unsigned char *data,
			       SilcUInt32 data_len, void *context)
{
  SilcSoftaccExec e = context;
  SilcStack stack = e->stack;

  /* Pop e->src */
  silc_stack_pop(stack);

  if (success)
    e->result_data = silc_smemdup(stack, data, data_len);
  e->result_len = data_len;
  e->result = success;
}

/* Verification callback */

void silc_softacc_pkcs_verify_cb(SilcBool success, void *context)
{
  SilcSoftaccExec e = context;
  SilcStack stack = e->stack;

  /* Pop e->src and e->data from memory */
  silc_stack_pop(stack);

  e->result = success;
}

/* Accelerator thread */

void silc_softacc_pkcs_thread(SilcSchedule schedule, void *context)
{
  SilcSoftaccExec e = context;

  if (e->aborted)
    return;

  SILC_LOG_DEBUG(("Execute type %d", e->type));

  /* Call the operation */
  switch (e->type) {
  case SILC_SOFTACC_ENCRYPT:
    silc_pkcs_encrypt(e->key.public_key, e->src, e->src_len, e->rng,
		      silc_softacc_pkcs_data_cb, e);
    break;

  case SILC_SOFTACC_DECRYPT:
    silc_pkcs_decrypt(e->key.private_key, e->src, e->src_len,
		      silc_softacc_pkcs_data_cb, e);
    break;

  case SILC_SOFTACC_SIGN:
    silc_pkcs_sign(e->key.private_key, e->src, e->src_len, e->compute_hash,
		   e->hash, e->rng, silc_softacc_pkcs_data_cb, e);
    break;

  case SILC_SOFTACC_VERIFY:
    silc_pkcs_verify(e->key.public_key, e->src, e->src_len, e->data,
		     e->data_len, e->hash, silc_softacc_pkcs_verify_cb, e);
    break;
  }
}

/* Accelerate public key */

SILC_PKCS_ALG_IMPORT_PUBLIC_KEY(silc_softacc_acc_public_key)
{
  SilcSoftaccPublicKey pubkey;
  SilcSoftacc sa;

  sa = silc_global_get_var("softacc", FALSE);
  if (!sa || !sa->schedule) {
    SILC_LOG_ERROR(("Software accelerator not initialized"));
    return FALSE;
  }

  pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    return FALSE;
  pubkey->key = key;

  *ret_public_key = pubkey;

  return TRUE;
}

/* Accelerate private key */

SILC_PKCS_ALG_IMPORT_PRIVATE_KEY(silc_softacc_acc_private_key)
{
  SilcSoftaccPrivateKey privkey;
  SilcSoftacc sa;

  sa = silc_global_get_var("softacc", FALSE);
  if (!sa || !sa->schedule) {
    SILC_LOG_ERROR(("Software accelerator not initialized"));
    return FALSE;
  }

  privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey)
    return FALSE;
  privkey->key = key;

  *ret_private_key = privkey;

  return TRUE;
}

/* Free public key */

SILC_PKCS_ALG_PUBLIC_KEY_FREE(silc_softacc_free_public_key)
{
  silc_free(public_key);
}

/* Free private key */

SILC_PKCS_ALG_PRIVATE_KEY_FREE(silc_softacc_free_private_key)
{
  silc_free(private_key);
}

/* Accelerated encrypt */

SILC_PKCS_ALG_ENCRYPT(silc_softacc_encrypt)
{
  SilcSoftaccPublicKey pubkey = public_key;
  SilcStack stack;
  SilcSoftaccExec e;
  SilcSoftacc sa;

  SILC_LOG_DEBUG(("Encrypt"));

  sa = silc_global_get_var("softacc", FALSE);
  if (!sa || !sa->schedule) {
    SILC_LOG_ERROR(("Software accelerator not initialized"));
    encrypt_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  stack = silc_stack_alloc(2048, silc_crypto_stack());

  e = silc_scalloc(stack, 1, sizeof(*e));
  if (!e) {
    silc_stack_free(stack);
    encrypt_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  silc_stack_push(stack, NULL);

  e->stack = stack;
  e->type = SILC_SOFTACC_ENCRYPT;
  e->src = silc_smemdup(stack, src, src_len);
  e->src_len = src_len;
  e->rng = rng;
  e->key.public_key = pubkey->key;
  e->cb.encrypt_cb = encrypt_cb;
  e->context = context;
  silc_async_init(&e->op, silc_softacc_pkcs_abort, NULL, e);

  /* Run */
  silc_thread_pool_run(sa->tp, TRUE, sa->schedule, silc_softacc_pkcs_thread, e,
		       silc_softacc_pkcs_completion, e);

  return &e->op;
}

/* Acceleted decrypt */

SILC_PKCS_ALG_DECRYPT(silc_softacc_decrypt)
{
  SilcSoftaccPrivateKey privkey = private_key;
  SilcStack stack;
  SilcSoftaccExec e;
  SilcSoftacc sa;

  SILC_LOG_DEBUG(("Decrypt"));

  sa = silc_global_get_var("softacc", FALSE);
  if (!sa || !sa->schedule) {
    SILC_LOG_ERROR(("Software accelerator not initialized"));
    decrypt_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  stack = silc_stack_alloc(2048, silc_crypto_stack());

  e = silc_scalloc(stack, 1, sizeof(*e));
  if (!e) {
    silc_stack_free(stack);
    decrypt_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  silc_stack_push(stack, NULL);

  e->stack = stack;
  e->type = SILC_SOFTACC_DECRYPT;
  e->src = silc_smemdup(stack, src, src_len);
  e->src_len = src_len;
  e->key.private_key = privkey->key;
  e->cb.decrypt_cb = decrypt_cb;
  e->context = context;
  silc_async_init(&e->op, silc_softacc_pkcs_abort, NULL, e);

  /* Run */
  silc_thread_pool_run(sa->tp, TRUE, sa->schedule, silc_softacc_pkcs_thread, e,
		       silc_softacc_pkcs_completion, e);

  return &e->op;
}

/* Accelerated signature */

SILC_PKCS_ALG_SIGN(silc_softacc_sign)
{
  SilcSoftaccPrivateKey privkey = private_key;
  SilcStack stack;
  SilcSoftaccExec e;
  SilcSoftacc sa;

  SILC_LOG_DEBUG(("Sign"));

  sa = silc_global_get_var("softacc", FALSE);
  if (!sa || !sa->schedule) {
    SILC_LOG_ERROR(("Software accelerator not initialized"));
    sign_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  stack = silc_stack_alloc(2048, silc_crypto_stack());

  e = silc_scalloc(stack, 1, sizeof(*e));
  if (!e) {
    silc_stack_free(stack);
    sign_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  silc_stack_push(stack, NULL);

  e->stack = stack;
  e->type = SILC_SOFTACC_SIGN;
  e->rng = rng;
  e->src = silc_smemdup(stack, src, src_len);
  e->src_len = src_len;
  e->compute_hash = compute_hash;
  e->hash = hash;
  e->key.private_key = privkey->key;
  e->cb.sign_cb = sign_cb;
  e->context = context;
  silc_async_init(&e->op, silc_softacc_pkcs_abort, NULL, e);

  /* Run */
  silc_thread_pool_run(sa->tp, TRUE, sa->schedule, silc_softacc_pkcs_thread, e,
		       silc_softacc_pkcs_completion, e);

  return &e->op;
}

/* Accelerated verification */

SILC_PKCS_ALG_VERIFY(silc_softacc_verify)
{
  SilcSoftaccPublicKey pubkey = public_key;
  SilcStack stack;
  SilcSoftaccExec e;
  SilcSoftacc sa;

  SILC_LOG_DEBUG(("Verify"));

  sa = silc_global_get_var("softacc", FALSE);
  if (!sa || !sa->schedule) {
    SILC_LOG_ERROR(("Software accelerator not initialized"));
    verify_cb(FALSE, context);
    return NULL;
  }

  stack = silc_stack_alloc(2048, silc_crypto_stack());

  e = silc_scalloc(stack, 1, sizeof(*e));
  if (!e) {
    silc_stack_free(stack);
    verify_cb(FALSE, context);
    return NULL;
  }

  silc_stack_push(stack, NULL);

  e->stack = stack;
  e->type = SILC_SOFTACC_VERIFY;
  e->src = silc_smemdup(stack, signature, signature_len);
  e->src_len = signature_len;
  e->data = silc_smemdup(stack, data, data_len);
  e->data_len = data_len;
  e->hash = hash;
  e->key.public_key = pubkey->key;
  e->cb.verify_cb = verify_cb;
  e->context = context;
  silc_async_init(&e->op, silc_softacc_pkcs_abort, NULL, e);

  /* Run */
  silc_thread_pool_run(sa->tp, TRUE, sa->schedule, silc_softacc_pkcs_thread, e,
		       silc_softacc_pkcs_completion, e);

  return &e->op;
}

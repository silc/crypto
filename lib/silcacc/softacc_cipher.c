/*

  softacc_cipher.c

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

/* #define SILC_SOFTACC_DEBUG_ON 1 */

#include "silccrypto.h"
#include "softacc.h"
#include "softacc_i.h"
#include "aes_internal.h"

/* Version 1.0 */

/* Cipher accelerator accelerates ciphers using counter mode by precomputing
   the CTR key stream in threads.  Encryption and decryption uses the
   precomputed key stream and gets significant speed improvement in the
   process.  The threads are reserved from the thread pool and they remain
   reserved as long as the cipher is accelerated.

   As a queue we use SilcThreadQueue from SRT which handles locking and
   waiting automatically and supports multiple pipes for multiple key
   streams, so it makes this whole thing very simple.

   This can accelerate any cipher but AES is especially optimized.

   Problems:

   To get the absolutely maximum performance out one must assign lots of
   RAM to softacc.

*/

/*
  Benchmarks (version 1.0):

  4-core: 2 x dual-core Xeon 5160 3GHz (Woodcrest), 4 GB RAM
  -----------------------------------------------------------------------
  cipher_threads = 4, cipher_blocks = 65536, cipher_streams = 32:
  aes-128-ctr:     728042.34 KB   710.98 MB   5687.83 Mbit / sec
  aes-192-ctr:     634662.85 KB   619.79 MB   4958.30 Mbit / sec
  aes-256-ctr:     555215.22 KB   542.20 MB   4337.62 Mbit / sec

  default settings, cipher_threads = 4:
  aes-128-ctr:     625568.94 KB   610.91 MB   4887.26 Mbit / sec
  aes-192-ctr:     572719.08 KB   559.30 MB   4474.37 Mbit / sec
  aes-256-ctr:     506930.88 KB   495.05 MB   3960.40 Mbit / sec

  8-core: 2 x quad-core Xeon E5345 2.33GHz (Clovertown), 4 GB RAM
  -----------------------------------------------------------------------
  cipher_threads = 8, cipher_blocks = 65536, cipher_streams = 64:
  aes-128-ctr:    1162373.93 KB  1135.13 MB   9081.05 Mbit / sec
  aes-192-ctr:     994808.64 KB   971.49 MB   7771.94 Mbit / sec
  aes-256-ctr:     874370.93 KB   853.88 MB   6831.02 Mbit / sec

  default settings, cipher_threads = 8:
  aes-128-ctr:     805157.74 KB   786.29 MB   6290.29 Mbit / sec
  aes-192-ctr:     733164.28 KB   715.98 MB   5727.85 Mbit / sec
  aes-256-ctr:     664677.98 KB   649.10 MB   5192.80 Mbit / sec

  Test setup:
  - Linux 2.6.20 x86-64
  - GCC 4.1.2
  - Yasm 0.5.0.1591
  - nice -n -20 lib/silcacc/tests/test_softacc_cipher

*/

/************************** Types and definitions ***************************/

/* Software accelerator cipher operations */
const SilcCipherObject softacc_cipher[] =
{
  /* AES */
  {
    "aes", "aes",
    silc_softacc_cipher_aes_set_key,
    silc_softacc_cipher_aes_set_iv,
    silc_softacc_cipher_aes_encrypt,
    silc_softacc_cipher_aes_encrypt,
    silc_softacc_cipher_init,
    silc_softacc_cipher_uninit,
    0, 0, 0,
    SILC_CIPHER_MODE_CTR, 	/* Only CTR mode can be accelerated */
  },

  /* All other ciphers */
  {
    "any", "any",
    silc_softacc_cipher_set_key,
    silc_softacc_cipher_set_iv,
    silc_softacc_cipher_encrypt,
    silc_softacc_cipher_encrypt,
    silc_softacc_cipher_init,
    silc_softacc_cipher_uninit,
    0, 0, 0,
    SILC_CIPHER_MODE_CTR, 	/* Only CTR mode can be accelerated */
  },

  {
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, 0, 0, 0, 0,
  }
};

/* Block size */
#define SILC_KEYSTREAM_BLOCK SILC_CIPHER_MAX_IV_SIZE

/* Thread stop signal */
#define SILC_KEYSTREAM_STOP (void *)0x01

/* Key stream context */
typedef struct {
  SilcUInt32 key_index;			      /* Key index in queue */
  unsigned char ctr[SILC_CIPHER_MAX_IV_SIZE]; /* Counter */
  unsigned char key[0];			      /* Key stream begins here */
} *SilcSoftaccCipherKeyStream;

/* Accelerator cipher context */
typedef struct SilcSoftaccCipherStruct {
  union {
    AesContext aes;			      /* AES */
    SilcCipher ecb;		              /* Other ciphers in ECB mode */
  } c;

  SilcThreadQueue queue;		      /* Key stream queue */
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE];  /* Current counter */
  SilcSoftaccCipherKeyStream *key_stream;     /* Key streams */
  SilcSoftaccCipherKeyStream cur;	      /* Current key stream */
  SilcUInt32 cur_block;			      /* Current block in key stream */
  SilcUInt32 cur_index;			      /* Current key stream index */
  SilcUInt32 pad;			      /* Partial block offset */
  SilcUInt32 num_key_stream;		      /* Number of key streams */
  SilcUInt32 cipher_blocks;		      /* Number of cipher blocks */
  unsigned int cipher_threads : 31;	      /* Number of cipher threads */
  unsigned int key_set : 1;		      /* Set when key is set */
} *SilcSoftaccCipher;

/************************** Static utility functions ************************/

/* Add value to MSB ordered counter. */

static inline
void silc_softacc_add_ctr(unsigned char *ctr, SilcUInt32 block_len,
			  SilcUInt32 val)
{
  SilcUInt16 q = 0;
  int i;

  if (!val)
    return;

  for (i = block_len - 1; i >= 0; i--) {
    q += ctr[i] + (val & 0xff);
    ctr[i] = (q & 0xff);
    val >>= 8;
    q >>= 8;
    if (!val && !q)
      return;
  }
}

/*********************************** AES ************************************/

#define SILC_AES_BLOCK 16

/* Thread destructor */

static SILC_TASK_CALLBACK(silc_softacc_cipher_aes_completion)
{
  SilcSoftaccCipher c = context;
  int i;

  /* Disconnect from key stream queue */
  if (silc_thread_queue_disconnect(c->queue))
    return;

  for (i = 0; i < c->num_key_stream; i++)
    silc_free(c->key_stream[i]);
  silc_free(c->key_stream);
  memset(c, 0, sizeof(*c));
  silc_free(c);
}

/* Key stream computation thread */

void silc_softacc_cipher_aes_thread(SilcSchedule schedule, void *context)
{
  SilcSoftaccCipher c = context;
  SilcThreadQueue queue = c->queue;
  SilcSoftaccCipherKeyStream key;
  SilcUInt32 i, num_key_stream = c->num_key_stream;
  SilcUInt32 cipher_blocks = c->cipher_blocks;
  SilcInt32 k;
  unsigned char *enc_ctr;

  SILC_SOFTACC_DEBUG(("Start CTR precomputation thread"));

  /* Connect to the key stream queue */
  silc_thread_queue_connect(queue);

  /* Process key streams.  We wait for empty key streams to come from the
     last pipe in the queue.  Here we precompute the key stream and put them
     back to the queue. */
  while (1) {
    key = silc_thread_queue_pop(queue, num_key_stream, TRUE);
    if (key == SILC_KEYSTREAM_STOP)
      break;

    SILC_SOFTACC_DEBUG(("Precompute key stream %p, index %d", key,
			key->key_index));

    /* Encrypt */
    enc_ctr = key->key;
    for (i = 0; i < cipher_blocks; i++) {
      for (k = SILC_AES_BLOCK - 1; k >= 0; k--)
	if (++key->ctr[k])
	  break;
      aes_encrypt(key->ctr, enc_ctr, &c->c.aes.u.enc);
      enc_ctr += SILC_AES_BLOCK;
    }

    SILC_SOFTACC_DEBUG(("Precomputed key stream %p, index %d", key,
			key->key_index));

    /* Update counter */
    silc_softacc_add_ctr(key->ctr, SILC_AES_BLOCK,
			 (num_key_stream - 1) * cipher_blocks);

    /* Put it back to queue */
    silc_thread_queue_push(queue, key->key_index, key, FALSE);
  }

  SILC_SOFTACC_DEBUG(("End CTR precomputation thread"));
}

/* Set IV.  Also, reset current block, discarding any remaining unused bits in
   the current key block. */

SILC_CIPHER_API_SET_IV(softacc_cipher_aes)
{
  SilcSoftaccCipher c = context;
  SilcSoftaccCipherKeyStream key;
  SilcUInt32 i;

  /* If IV is NULL we start new block */
  if (!iv) {
    SILC_SOFTACC_DEBUG(("Start new block"));

    if (c->pad < SILC_AES_BLOCK) {
      c->pad = SILC_AES_BLOCK;

      /* Start new block */
      if (++c->cur_block == c->cipher_blocks) {
        SILC_SOFTACC_DEBUG(("Push empty key stream %p index %d back to queue",
			    c->cur, c->cur->key_index));
        silc_thread_queue_push(c->queue, c->num_key_stream, c->cur, FALSE);
        c->cur_index = (c->cur_index + 1) % c->cipher_blocks;
        c->cur_block = 0;
        c->cur = NULL;
      }
    }
  } else {
    /* Start new IV */
    SILC_SOFTACC_DEBUG(("Start new counter"));

    memcpy(c->iv, iv, SILC_AES_BLOCK);

    if (!c->key_set)
      return;

    /* Push current key stream back to queue.  We need all of them there
       below. */
    if (c->cur)
      silc_thread_queue_push(c->queue, c->cur->key_index, c->cur, FALSE);

    /* We must get all key streams and update them */
    for (i = 0; i < c->num_key_stream; i++) {
      key = silc_thread_queue_pop(c->queue, i, TRUE);
      memcpy(key->ctr, c->iv, SILC_AES_BLOCK);
      silc_softacc_add_ctr(key->ctr, SILC_AES_BLOCK, i * c->cipher_blocks);
      silc_thread_queue_push(c->queue, c->num_key_stream, key, FALSE);
    }

    c->cur = NULL;
    c->cur_index = 0;
    c->cur_block = 0;
    c->pad = SILC_AES_BLOCK;
  }
}

/* Accelerate cipher */

SILC_CIPHER_API_SET_KEY(softacc_cipher_aes)
{
  SilcSoftaccCipher c = context;
  SilcSoftacc sa;
  SilcUInt32 i;

  /* If key is present set it.  If it is NULL this is initialization call. */
  if (key) {
    SILC_SOFTACC_DEBUG(("Set key for accelerator %s %p", ops->alg_name, c));

    aes_encrypt_key(key, keylen, &c->c.aes.u.enc);
    c->key_set = TRUE;

    /* Set the counters for each key stream and push them to the queue for
       precompuptation. */
    for (i = 0; i < c->num_key_stream; i++) {
      memcpy(c->key_stream[i]->ctr, c->iv, SILC_AES_BLOCK);
      silc_softacc_add_ctr(c->key_stream[i]->ctr, SILC_AES_BLOCK,
			   i * c->cipher_blocks);
      silc_thread_queue_push(c->queue, c->num_key_stream, c->key_stream[i],
			     FALSE);
    }

    return TRUE;
  }

  /* Initialize the accelerator for this cipher */
  SILC_LOG_DEBUG(("Initialize accelerator for %s %p", ops->alg_name, c));

  sa = silc_global_get_var("softacc", FALSE);
  if (!sa) {
    SILC_LOG_ERROR(("Software accelerator not initialized"));
    return FALSE;
  }

  /* Start the queue with sa->cipher_blocks many key streams.  One extra pipe
     in the queue is used as a return pipe for empty key streams. */
  c->cipher_blocks = sa->cipher_blocks;
  c->cipher_threads = sa->cipher_threads;
  c->num_key_stream = sa->cipher_streams;
  c->key_stream = silc_calloc(c->num_key_stream, sizeof(*c->key_stream));
  if (!c->key_stream)
    return FALSE;
  for (i = 0; i < c->num_key_stream; i++) {
    c->key_stream[i] = silc_malloc(sizeof(**c->key_stream) +
				   (c->cipher_blocks * SILC_AES_BLOCK));
    if (!c->key_stream[i])
      return FALSE;
    c->key_stream[i]->key_index = i;
  }
  c->queue = silc_thread_queue_alloc(c->num_key_stream + 1, TRUE);
  if (!c->queue)
    return FALSE;

  /* Start the threads.  If thread starting fails, we can't accelerate the
     cipher.  The uninit operation will clean up any started threads. */
  for (i = 0; i < sa->cipher_threads; i++)
    if (!silc_thread_pool_run(sa->tp, FALSE, NULL,
			      silc_softacc_cipher_aes_thread,
			      c, silc_softacc_cipher_aes_completion, c))
      return FALSE;

  return TRUE;
}

/* Accelerated encryption/decryption in CTR mode */

SILC_CIPHER_API_ENCRYPT(softacc_cipher_aes)
{
  SilcSoftaccCipher c = context;
  SilcSoftaccCipherKeyStream key;
  SilcUInt32 pad = c->pad, block = c->cur_block;
  SilcUInt32 blocks, cipher_blocks = c->cipher_blocks;
  unsigned char *enc_ctr;

  key = c->cur;
  if (!key) {
    c->cur = key = silc_thread_queue_pop(c->queue, c->cur_index, TRUE);
    SILC_SOFTACC_DEBUG(("Got key stream %p, index %d", key, key->key_index));
  }

  enc_ctr = key->key + (block << 4);

  /* Compute partial block */
  if (pad < SILC_AES_BLOCK) {
    while (len-- > 0) {
      *dst++ = *src++ ^ enc_ctr[pad++];
      if (pad == SILC_AES_BLOCK) {
	enc_ctr += SILC_AES_BLOCK;
	if (++block == cipher_blocks) {
	  /* Push the used up key stream back to the queue */
	  SILC_SOFTACC_DEBUG(("Push empty key stream %p index %d back to queue",
			      key, key->key_index));
	  silc_thread_queue_push(c->queue, c->num_key_stream, key, FALSE);

	  /* Get new key stream from queue */
	  c->cur_index = (c->cur_index + 1) % c->num_key_stream;
	  c->cur = key = silc_thread_queue_pop(c->queue, c->cur_index, TRUE);
	  SILC_SOFTACC_DEBUG(("Got key stream %p, index %d", key,
			      key->key_index));
	  enc_ctr = key->key;
	  block = 0;
	}
	break;
      }
    }
  }

  /* Compute full blocks */
  blocks = len >> 4;
  len -= (blocks << 4);
  while (blocks--) {
    /* CTR mode */
#ifndef WORDS_BIGENDIAN
    *(SilcUInt64 *)dst = (*(SilcUInt64 *)src ^
			  *(SilcUInt64 *)enc_ctr);
    *(SilcUInt64 *)(dst + 8) = (*(SilcUInt64 *)(src + 8) ^
				*(SilcUInt64 *)(enc_ctr + 8));
#else
    SilcUInt64 dst_tmp, src_tmp, enc_ctr_tmp;

    SILC_GET64_MSB(src_tmp, src);
    SILC_GET64_MSB(enc_ctr_tmp, enc_ctr);
    dst_tmp = src_tmp ^ enc_ctr_tmp;
    SILC_PUT64_MSB(dst_tmp, dst);

    SILC_GET64_MSB(src_tmp, src + 8);
    SILC_GET64_MSB(enc_ctr_tmp, enc_ctr + 8);
    dst_tmp = src_tmp ^ enc_ctr_tmp;
    SILC_PUT64_MSB(dst_tmp, dst + 8);
#endif /* !WORDS_BIGENDIAN */

    src += SILC_AES_BLOCK;
    dst += SILC_AES_BLOCK;
    enc_ctr += SILC_AES_BLOCK;

    if (++block == cipher_blocks) {
      /* Push the used up key stream back to the queue */
      SILC_SOFTACC_DEBUG(("Push empty key stream %p index %d back to queue",
			  key, key->key_index));
      silc_thread_queue_push(c->queue, c->num_key_stream, key, FALSE);

      /* Get new key stream from queue */
      c->cur_index = (c->cur_index + 1) % c->num_key_stream;
      c->cur = key = silc_thread_queue_pop(c->queue, c->cur_index, TRUE);
      SILC_SOFTACC_DEBUG(("Got key stream %p, index %d", key, key->key_index));
      enc_ctr = key->key;
      block = 0;
    }
  }

  /* Compute partial block */
  if (len > 0) {
    pad = 0;
    while (len-- > 0)
      *dst++ = *src++ ^ enc_ctr[pad++];
  }

  c->cur_block = block;
  c->pad = pad;

  return TRUE;
}

/****************************** Other ciphers *******************************/

/* Thread destructor */

static SILC_TASK_CALLBACK(silc_softacc_cipher_completion)
{
  SilcSoftaccCipher c = context;
  int i;

  /* Disconnect from key stream queue */
  if (silc_thread_queue_disconnect(c->queue))
    return;

  silc_cipher_free(c->c.ecb);
  for (i = 0; i < c->num_key_stream; i++)
    silc_free(c->key_stream[i]);
  silc_free(c->key_stream);
  memset(c, 0, sizeof(*c));
  silc_free(c);
}

/* Key stream computation thread */

void silc_softacc_cipher_thread(SilcSchedule schedule, void *context)
{
  SilcSoftaccCipher c = context;
  SilcThreadQueue queue = c->queue;
  SilcSoftaccCipherKeyStream key = NULL;
  SilcUInt32 i, block_len, num_key_stream = c->num_key_stream;
  SilcUInt32 cipher_blocks = c->cipher_blocks;
  SilcInt32 k;
  unsigned char *enc_ctr;

  SILC_SOFTACC_DEBUG(("Start CTR precomputation thread"));

  block_len = silc_cipher_get_block_len(c->c.ecb);

  /* Connect to the key stream queue */
  silc_thread_queue_connect(queue);

  /* Process key streams.  We wait for empty key streams to come from the
     last pipe in the queue.  Here we precompute the key stream and put them
     back to the queue. */
  while (1) {
    key = silc_thread_queue_pop(queue, num_key_stream, TRUE);
    if (key == SILC_KEYSTREAM_STOP)
      break;

    SILC_SOFTACC_DEBUG(("Precompute key stream %p, index %d", key,
			key->key_index));

    /* Encrypt */
    enc_ctr = key->key;
    for (i = 0; i < cipher_blocks; i++) {
      for (k = block_len - 1; k >= 0; k--)
	if (++key->ctr[k])
	  break;
      c->c.ecb->cipher->encrypt(c->c.ecb, c->c.ecb->cipher, c->c.ecb->context,
				key->ctr, enc_ctr, block_len, NULL);
      enc_ctr += block_len;
    }

    SILC_SOFTACC_DEBUG(("Precomputed key stream %p, index %d", key,
			key->key_index));

    /* Update counter */
    silc_softacc_add_ctr(key->ctr, block_len,
			 (num_key_stream - 1) * cipher_blocks);

    /* Put it back to queue */
    silc_thread_queue_push(queue, key->key_index, key, FALSE);
  }

  SILC_SOFTACC_DEBUG(("End CTR precomputation thread"));
}

/* Accelerate cipher */

SILC_CIPHER_API_SET_KEY(softacc_cipher)
{
  SilcSoftaccCipher c = context;
  SilcSoftacc sa;
  SilcUInt32 i;

  /* If key is present set it.  If it is NULL this is initialization call. */
  if (key) {
    SILC_SOFTACC_DEBUG(("Set key for accelerator %s %p", ops->alg_name, c));

    SILC_VERIFY(c->c.ecb && c->queue);

    if (!silc_cipher_set_key(c->c.ecb, key, keylen, TRUE))
      return FALSE;
    c->key_set = TRUE;

    /* Set the counters for each key stream and push them to the queue for
       precompuptation. */
    for (i = 0; i < c->num_key_stream; i++) {
      memcpy(c->key_stream[i]->ctr, c->iv, silc_cipher_get_iv_len(c->c.ecb));
      silc_softacc_add_ctr(c->key_stream[i]->ctr,
			   silc_cipher_get_block_len(c->c.ecb),
			   i * c->cipher_blocks);
      silc_thread_queue_push(c->queue, c->num_key_stream, c->key_stream[i],
			     FALSE);
    }

    return TRUE;
  }

  /* Initialize the accelerator for this cipher */
  SILC_LOG_DEBUG(("Initialize accelerator for %s %p", ops->alg_name, c));

  sa = silc_global_get_var("softacc", FALSE);
  if (!sa) {
    SILC_LOG_ERROR(("Software accelerator not initialized"));
    return FALSE;
  }

  /* Allocate cipher in ECB mode.  It is used to encrypt the key stream. */
  if (!silc_cipher_alloc_full(ops->alg_name, ops->key_len,
			      SILC_CIPHER_MODE_ECB, &c->c.ecb))
    return FALSE;

  /* Start the queue with sa->cipher_blocks many key streams.  One extra pipe
     in the queue is used as a return pipe for empty key streams. */
  c->cipher_blocks = sa->cipher_blocks;
  c->cipher_threads = sa->cipher_threads;
  c->num_key_stream = sa->cipher_streams;
  c->key_stream = silc_calloc(c->num_key_stream, sizeof(*c->key_stream));
  if (!c->key_stream)
    return FALSE;
  for (i = 0; i < c->num_key_stream; i++) {
    c->key_stream[i] = silc_malloc(sizeof(**c->key_stream) +
				   (c->cipher_blocks *
				    silc_cipher_get_block_len(c->c.ecb)));
    if (!c->key_stream[i])
      return FALSE;
    c->key_stream[i]->key_index = i;
  }
  c->queue = silc_thread_queue_alloc(c->num_key_stream + 1, TRUE);
  if (!c->queue)
    return FALSE;

  /* Start the threads.  If thread starting fails, we can't accelerate the
     cipher.  The uninit operation will clean up any started threads. */
  for (i = 0; i < sa->cipher_threads; i++)
    if (!silc_thread_pool_run(sa->tp, FALSE, NULL, silc_softacc_cipher_thread,
			      c, silc_softacc_cipher_completion, c))
      return FALSE;

  return TRUE;
}

/* Set IV.  Also, reset current block, discarding any remaining unused bits in
   the current key block. */

SILC_CIPHER_API_SET_IV(softacc_cipher)
{
  SilcSoftaccCipher c = context;
  SilcSoftaccCipherKeyStream key;
  SilcUInt32 i, block_len, iv_len;

  block_len = silc_cipher_get_block_len(c->c.ecb);
  iv_len = silc_cipher_get_iv_len(c->c.ecb);

  if (c->pad > block_len)
    c->pad = block_len;

  /* If IV is NULL we start new block */
  if (!iv) {
    SILC_SOFTACC_DEBUG(("Start new block"));

    if (c->pad < block_len) {
      c->pad = block_len;

      /* Start new block */
      if (++c->cur_block == c->cipher_blocks) {
        SILC_SOFTACC_DEBUG(("Push empty key stream %p index %d back to queue",
			    c->cur, c->cur->key_index));
        silc_thread_queue_push(c->queue, c->num_key_stream, c->cur, FALSE);
        c->cur_index = (c->cur_index + 1) % c->cipher_blocks;
        c->cur_block = 0;
        c->cur = NULL;
      }
    }
  } else {
    /* Start new IV */
    SILC_SOFTACC_DEBUG(("Start new counter"));

    memcpy(c->iv, iv, iv_len);

    if (!c->key_set)
      return;

    /* Push current key stream back to queue.  We need all of them there
       below. */
    if (c->cur)
      silc_thread_queue_push(c->queue, c->cur->key_index, c->cur, FALSE);

    /* We must get all key streams and update them. */
    for (i = 0; i < c->num_key_stream; i++) {
      key = silc_thread_queue_pop(c->queue, i, TRUE);
      memcpy(key->ctr, c->iv, iv_len);
      silc_softacc_add_ctr(key->ctr, iv_len, i * c->cipher_blocks);
      silc_thread_queue_push(c->queue, c->num_key_stream, key, FALSE);
    }

    c->cur = NULL;
    c->cur_index = 0;
    c->cur_block = 0;
    c->pad = block_len;
  }
}

SILC_CIPHER_API_ENCRYPT(softacc_cipher)
{
  SilcSoftaccCipher c = context;
  SilcSoftaccCipherKeyStream key;
  SilcUInt32 pad = c->pad, block = c->cur_block;
  SilcUInt32 cipher_blocks = c->cipher_blocks;
  SilcUInt32 blocks, block_len, i;
  unsigned char *enc_ctr;

  key = c->cur;
  if (!key) {
    c->cur = key = silc_thread_queue_pop(c->queue, c->cur_index, TRUE);
    SILC_SOFTACC_DEBUG(("Got key stream %p, index %d", key, key->key_index));
  }

  block_len = c->c.ecb->cipher->block_len;
  enc_ctr = key->key + (block * block_len);

  /* Compute partial block */
  if (pad < block_len) {
    while (len-- > 0) {
      *dst++ = *src++ ^ enc_ctr[pad++];
      if (pad == block_len) {
	enc_ctr += block_len;
	if (++block == cipher_blocks) {
	  /* Push the used up key stream back to the queue */
	  SILC_SOFTACC_DEBUG(("Push empty key stream %p index %d back to queue",
			      key, key->key_index));
	  silc_thread_queue_push(c->queue, c->num_key_stream, key, FALSE);

	  /* Get new key stream from queue */
	  c->cur_index = (c->cur_index + 1) % c->num_key_stream;
	  c->cur = key = silc_thread_queue_pop(c->queue, c->cur_index, TRUE);
	  SILC_SOFTACC_DEBUG(("Got key stream %p, index %d", key,
			      xskey->key_index));
	  enc_ctr = key->key;
	  block = 0;
	}
	break;
      }
    }
  }

  /* Compute full blocks */
  blocks = (len / block_len);
  len -= (blocks * block_len);
  while (blocks--) {
    /* CTR mode */
#ifndef WORDS_BIGENDIAN
    for (i = 0; i < block_len / sizeof(SilcUInt64); i++)
      *(SilcUInt64 *)(dst + (i * sizeof(SilcUInt64))) =
	*(SilcUInt64 *)(src + (i * sizeof(SilcUInt64))) ^
	*(SilcUInt64 *)(enc_ctr + (i * sizeof(SilcUInt64)));
#else
    SilcUInt64 dst_tmp, src_tmp, enc_ctr_tmp;

    for (i = 0; i < block_len / sizeof(SilcUInt64); i++) {
      SILC_GET64_MSB(src_tmp, src + (i * sizeof(SilcUInt64)));
      SILC_GET64_MSB(enc_ctr_tmp, enc_ctr + (i * sizeof(SilcUInt64)));
      dst_tmp = src_tmp ^ enc_ctr_tmp;
      SILC_PUT64_MSB(dst_tmp, dst + (i * sizeof(SilcUInt64)));
    }
#endif /* !WORDS_BIGENDIAN */

    src += block_len;
    dst += block_len;
    enc_ctr += block_len;

    if (++block == cipher_blocks) {
      /* Push the used up key stream back to the queue */
      SILC_SOFTACC_DEBUG(("Push empty key stream %p index %d back to queue",
			  key, key->key_index));
      silc_thread_queue_push(c->queue, c->num_key_stream, key, FALSE);

      /* Get new key stream from queue */
      c->cur_index = (c->cur_index + 1) % c->num_key_stream;
      c->cur = key = silc_thread_queue_pop(c->queue, c->cur_index, TRUE);
      SILC_SOFTACC_DEBUG(("Got key stream %p, index %d", key,
			  key->key_index));
      enc_ctr = key->key;
      block = 0;
    }
  }

  /* Compute partial block */
  if (len > 0) {
    pad = 0;
    while (len-- > 0)
      *dst++ = *src++ ^ enc_ctr[pad++];
  }

  c->cur_block = block;
  c->pad = pad;

  return TRUE;
}

/* Return accelerator cipher context */

SILC_CIPHER_API_INIT(softacc_cipher)
{
  SilcSoftaccCipher c = silc_calloc(1, sizeof(*c));

  if (!c)
    return NULL;

  c->pad = 16;

  return c;
}

/* Uninitialize the cipher accelerator */

SILC_CIPHER_API_UNINIT(softacc_cipher)
{
  SilcSoftaccCipher c = context;
  int i;

  /* Stop threads */
  if (c->queue) {
    for (i = 0; i < c->cipher_threads; i++)
      silc_thread_queue_push(c->queue, c->num_key_stream,
			     SILC_KEYSTREAM_STOP, FALSE);

    /* Disconnect from key stream queue */
    if (silc_thread_queue_disconnect(c->queue))
      return;
  }

  silc_free(c->key_stream);
  memset(c, 0, sizeof(*c));
  silc_free(c);
}

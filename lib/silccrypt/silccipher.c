/*

  silccipher.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silccrypto.h"
#include "ciphers.h"		/* Includes cipher definitions */

#ifndef SILC_SYMBIAN
/* Dynamically registered list of ciphers. */
SilcDList silc_cipher_list = NULL;
#endif /* SILC_SYMBIAN */

/* Macro to define cipher to cipher list */
#define SILC_CDEF(name, alg_name, cipher, keylen, blocklen, ivlen, mode)\
{ name, alg_name, silc_##cipher##_set_key, silc_##cipher##_set_iv,	\
  silc_##cipher##_encrypt, silc_##cipher##_decrypt,			\
  silc_##cipher##_init, silc_##cipher##_uninit, keylen, blocklen, ivlen, mode }

/* Static list of ciphers for silc_cipher_register_default(). */
const SilcCipherObject silc_default_ciphers[] =
{
  SILC_CDEF("aes-256-ctr", "aes", aes, 256, 16, 16, SILC_CIPHER_MODE_CTR),
  SILC_CDEF("aes-192-ctr", "aes", aes, 192, 16, 16, SILC_CIPHER_MODE_CTR),
  SILC_CDEF("aes-128-ctr", "aes", aes, 128, 16, 16, SILC_CIPHER_MODE_CTR),
  SILC_CDEF("aes-256-cbc", "aes", aes, 256, 16, 16, SILC_CIPHER_MODE_CBC),
  SILC_CDEF("aes-192-cbc", "aes", aes, 192, 16, 16, SILC_CIPHER_MODE_CBC),
  SILC_CDEF("aes-128-cbc", "aes", aes, 128, 16, 16, SILC_CIPHER_MODE_CBC),
  SILC_CDEF("aes-256-cfb", "aes", aes, 256, 16, 16, SILC_CIPHER_MODE_CFB),
  SILC_CDEF("aes-192-cfb", "aes", aes, 192, 16, 16, SILC_CIPHER_MODE_CFB),
  SILC_CDEF("aes-128-cfb", "aes", aes, 128, 16, 16, SILC_CIPHER_MODE_CFB),
  SILC_CDEF("aes-256-ecb", "aes", aes, 256, 16, 16, SILC_CIPHER_MODE_ECB),
  SILC_CDEF("aes-192-ecb", "aes", aes, 192, 16, 16, SILC_CIPHER_MODE_ECB),
  SILC_CDEF("aes-128-ecb", "aes", aes, 128, 16, 16, SILC_CIPHER_MODE_ECB),
  SILC_CDEF("twofish-256-ctr", "twofish", twofish, 256, 16, 16, SILC_CIPHER_MODE_CTR),
  SILC_CDEF("twofish-192-ctr", "twofish", twofish, 192, 16, 16, SILC_CIPHER_MODE_CTR),
  SILC_CDEF("twofish-128-ctr", "twofish", twofish, 128, 16, 16, SILC_CIPHER_MODE_CTR),
  SILC_CDEF("twofish-256-cbc", "twofish", twofish, 256, 16, 16, SILC_CIPHER_MODE_CBC),
  SILC_CDEF("twofish-192-cbc", "twofish", twofish, 192, 16, 16, SILC_CIPHER_MODE_CBC),
  SILC_CDEF("twofish-128-cbc", "twofish", twofish, 128, 16, 16, SILC_CIPHER_MODE_CBC),
  SILC_CDEF("twofish-256-cfb", "twofish", twofish, 256, 16, 16, SILC_CIPHER_MODE_CFB),
  SILC_CDEF("twofish-192-cfb", "twofish", twofish, 192, 16, 16, SILC_CIPHER_MODE_CFB),
  SILC_CDEF("twofish-128-cfb", "twofish", twofish, 128, 16, 16, SILC_CIPHER_MODE_CFB),
  SILC_CDEF("twofish-256-ecb", "twofish", twofish, 256, 16, 16, SILC_CIPHER_MODE_ECB),
  SILC_CDEF("twofish-192-ecb", "twofish", twofish, 192, 16, 16, SILC_CIPHER_MODE_ECB),
  SILC_CDEF("twofish-128-ecb", "twofish", twofish, 128, 16, 16, SILC_CIPHER_MODE_ECB),
  SILC_CDEF("cast5-128-ctr", "cast5", cast5, 128, 8, 8, SILC_CIPHER_MODE_CTR),
  SILC_CDEF("cast5-128-cbc", "cast5", cast5, 128, 8, 8, SILC_CIPHER_MODE_CBC),
  SILC_CDEF("cast5-128-cfb", "cast5", cast5, 128, 8, 8, SILC_CIPHER_MODE_CFB),
  SILC_CDEF("cast5-128-ecb", "cast5", cast5, 128, 8, 8, SILC_CIPHER_MODE_ECB),
  SILC_CDEF("des-56-ctr", "des", des, 56, 8, 8, SILC_CIPHER_MODE_CTR),
  SILC_CDEF("des-56-cbc", "des", des, 56, 8, 8, SILC_CIPHER_MODE_CBC),
  SILC_CDEF("des-56-cfb", "des", des, 56, 8, 8, SILC_CIPHER_MODE_CFB),
  SILC_CDEF("des-56-ecb", "des", des, 56, 8, 8, SILC_CIPHER_MODE_ECB),
  SILC_CDEF("3des-168-ctr", "3des", 3des, 168, 8, 8, SILC_CIPHER_MODE_CTR),
  SILC_CDEF("3des-168-cbc", "3des", 3des, 168, 8, 8, SILC_CIPHER_MODE_CBC),
  SILC_CDEF("3des-168-cfb", "3des", 3des, 168, 8, 8, SILC_CIPHER_MODE_CFB),
  SILC_CDEF("3des-168-ecb", "3des", 3des, 168, 8, 8, SILC_CIPHER_MODE_ECB),
#ifdef SILC_DEBUG
  SILC_CDEF("none", "none", none, 0, 0, 0, 0),
#endif /* SILC_DEBUG */
  { NULL, NULL, NULL, 0, 0, 0, 0 }
};

/* Register new cipher */

SilcBool silc_cipher_register(const SilcCipherObject *cipher)
{
#ifndef SILC_SYMBIAN
  SilcCipherObject *new;

  SILC_LOG_DEBUG(("Registering new cipher `%s'", cipher->name));

  /* Check if exists already */
  if (silc_cipher_list) {
    SilcCipherObject *entry;
    silc_dlist_start(silc_cipher_list);
    while ((entry = silc_dlist_get(silc_cipher_list))) {
      if (!strcmp(entry->name, cipher->name))
	return FALSE;
    }
  }

  new = silc_calloc(1, sizeof(*new));
  if (!new)
    return FALSE;
  new->name = strdup(cipher->name);
  if (!new->name) {
    silc_free(new);
    return FALSE;
  }
  new->key_len = cipher->key_len;
  new->block_len = cipher->block_len;
  new->iv_len = cipher->iv_len;
  new->set_key = cipher->set_key;
  new->set_iv = cipher->set_iv;
  new->encrypt = cipher->encrypt;
  new->decrypt = cipher->decrypt;
  new->init = cipher->init;
  new->uninit = cipher->uninit;
  new->mode = cipher->mode;

  /* Add to list */
  if (silc_cipher_list == NULL)
    silc_cipher_list = silc_dlist_init();
  silc_dlist_add(silc_cipher_list, new);

#endif /* SILC_SYMBIAN */
  return TRUE;
}

/* Unregister a cipher */

SilcBool silc_cipher_unregister(SilcCipherObject *cipher)
{
#ifndef SILC_SYMBIAN
  SilcCipherObject *entry;

  SILC_LOG_DEBUG(("Unregistering cipher"));

  if (!silc_cipher_list)
    return FALSE;

  silc_dlist_start(silc_cipher_list);
  while ((entry = silc_dlist_get(silc_cipher_list))) {
    if (cipher == SILC_ALL_CIPHERS || entry == cipher) {
      silc_dlist_del(silc_cipher_list, entry);
      silc_free(entry->name);
      silc_free(entry);

      if (silc_dlist_count(silc_cipher_list) == 0) {
	silc_dlist_uninit(silc_cipher_list);
	silc_cipher_list = NULL;
      }

      return TRUE;
    }
  }

#endif /* SILC_SYMBIAN */
  return FALSE;
}

/* Register default ciphers */

SilcBool silc_cipher_register_default(void)
{
  /* We use builtin ciphers */
  return TRUE;
}

/* Unregister all ciphers */

SilcBool silc_cipher_unregister_all(void)
{
#ifndef SILC_SYMBIAN
  SilcCipherObject *entry;

  if (!silc_cipher_list)
    return FALSE;

  silc_dlist_start(silc_cipher_list);
  while ((entry = silc_dlist_get(silc_cipher_list))) {
    silc_cipher_unregister(entry);
    if (!silc_cipher_list)
      break;
  }
#endif /* SILC_SYMBIAN */
  return TRUE;
}

/* Allocates a new SILC cipher object. Function returns 1 on succes and 0
   on error. The allocated cipher is returned in new_cipher argument. The
   caller must set the key to the cipher after this function has returned
   by calling the ciphers set_key function. */

SilcBool silc_cipher_alloc(const char *name, SilcCipher *new_cipher)
{
  SilcCipherObject *entry = NULL;
  int i;

  SILC_LOG_DEBUG(("Allocating new cipher object"));

#ifndef SILC_SYMBIAN
  /* First check registered list of ciphers */
  if (silc_cipher_list) {
    silc_dlist_start(silc_cipher_list);
    while ((entry = silc_dlist_get(silc_cipher_list))) {
      if (!strcmp(entry->name, name))
	break;
    }
  }
#endif /* SILC_SYMBIAN */

  if (!entry) {
    /* Check builtin list of ciphers */
    for (i = 0; silc_default_ciphers[i].name; i++) {
      if (!strcmp(silc_default_ciphers[i].name, name)) {
	entry = (SilcCipherObject *)&(silc_default_ciphers[i]);
	break;
      }
    }
  }

  if (entry) {
    *new_cipher = silc_calloc(1, sizeof(**new_cipher));
    if (!(*new_cipher))
      return FALSE;
    (*new_cipher)->cipher = entry;
    (*new_cipher)->context = entry->init(entry);
    if (!(*new_cipher)->context) {
      silc_free(*new_cipher);
      return FALSE;
    }

    return TRUE;
  }

  return FALSE;
}

/* Allocate cipher */

SilcBool silc_cipher_alloc_full(const char *alg_name, SilcUInt32 key_len,
                                SilcCipherMode mode, SilcCipher *new_cipher)
{
  char name[64];
  const char *mode_name;

  switch (mode) {
  case SILC_CIPHER_MODE_ECB:
    mode_name = "ecb";
    break;
  case SILC_CIPHER_MODE_CBC:
    mode_name = "cbc";
    break;
  case SILC_CIPHER_MODE_CTR:
    mode_name = "ctr";
    break;
  case SILC_CIPHER_MODE_CFB:
    mode_name = "cfb";
    break;
  case SILC_CIPHER_MODE_OFB:
    mode_name = "ofb";
    break;
  default:
    return FALSE;
    break;
  }

  silc_snprintf(name, sizeof(name), "%s-%d-%s", alg_name, key_len, mode_name);

  return silc_cipher_alloc(name, new_cipher);
}

/* Free's the given cipher. */

void silc_cipher_free(SilcCipher cipher)
{
  if (cipher) {
    cipher->cipher->uninit(cipher->cipher, cipher->context);
    memset(cipher, 0, sizeof(*cipher));
    silc_free(cipher);
  }
}

/* Returns TRUE if cipher `name' is supported. */

SilcBool silc_cipher_is_supported(const char *name)
{
  SilcCipherObject *entry;
  int i;

#ifndef SILC_SYMBIAN
  /* First check registered list of ciphers */
  if (silc_cipher_list) {
    silc_dlist_start(silc_cipher_list);
    while ((entry = silc_dlist_get(silc_cipher_list))) {
      if (!strcmp(entry->name, name))
	return TRUE;
    }
  }
#endif /* SILC_SYMBIAN */

  /* Check builtin list of ciphers */
  for (i = 0; silc_default_ciphers[i].name; i++)
    if (!strcmp(silc_default_ciphers[i].name, name))
      return TRUE;

  return FALSE;
}

/* Returns comma separated list of supported ciphers. */

char *silc_cipher_get_supported(SilcBool only_registered)
{
  SilcCipherObject *entry, *entry2;
  char *list = NULL;
  int i, len = 0;

#ifndef SILC_SYMBIAN
  if (silc_cipher_list) {
    silc_dlist_start(silc_cipher_list);
    while ((entry = silc_dlist_get(silc_cipher_list))) {
      len += strlen(entry->name);
      list = silc_realloc(list, len + 1);

      memcpy(list + (len - strlen(entry->name)),
	     entry->name, strlen(entry->name));
      memcpy(list + len, ",", 1);
      len++;
    }
  }
#endif /* SILC_SYMBIAN */

  if (!only_registered || !silc_cipher_list) {
    for (i = 0; silc_default_ciphers[i].name; i++) {
      entry = (SilcCipherObject *)&(silc_default_ciphers[i]);

      if (silc_cipher_list) {
	silc_dlist_start(silc_cipher_list);
	while ((entry2 = silc_dlist_get(silc_cipher_list))) {
	  if (!strcmp(entry2->name, entry->name))
	    break;
	}
	if (entry2)
	  continue;
      }

      len += strlen(entry->name);
      list = silc_realloc(list, len + 1);

      memcpy(list + (len - strlen(entry->name)),
	     entry->name, strlen(entry->name));
      memcpy(list + len, ",", 1);
      len++;
    }
  }

  list[len - 1] = 0;

  return list;
}

/* Encrypts */

SilcBool silc_cipher_encrypt(SilcCipher cipher, const unsigned char *src,
			     unsigned char *dst, SilcUInt32 len,
			     unsigned char *iv)
{
  return cipher->cipher->encrypt(cipher, cipher->cipher,
				 cipher->context, src, dst, len,
				 iv ? iv : cipher->iv);
}

/* Decrypts */

SilcBool silc_cipher_decrypt(SilcCipher cipher, const unsigned char *src,
			     unsigned char *dst, SilcUInt32 len,
			     unsigned char *iv)
{
  return cipher->cipher->decrypt(cipher, cipher->cipher,
				 cipher->context, src, dst, len,
				 iv ? iv : cipher->iv);
}

/* Sets the key for the cipher */

SilcBool silc_cipher_set_key(SilcCipher cipher, const unsigned char *key,
			     SilcUInt32 keylen, SilcBool encryption)
{
  return cipher->cipher->set_key(cipher, cipher->cipher, cipher->context,
				 (void *)key, keylen, encryption);
}

/* Sets the IV (initial vector) for the cipher. */

void silc_cipher_set_iv(SilcCipher cipher, const unsigned char *iv)
{
  if (iv)
    memmove(cipher->iv, iv, cipher->cipher->iv_len);
  cipher->cipher->set_iv(cipher, cipher->cipher, cipher->context, cipher->iv);
}

/* Returns the IV (initial vector) of the cipher. */

unsigned char *silc_cipher_get_iv(SilcCipher cipher)
{
  return cipher->iv;
}

/* Returns the key length of the cipher. */

SilcUInt32 silc_cipher_get_key_len(SilcCipher cipher)
{
  return cipher->cipher->key_len;
}

/* Returns the block size of the cipher. */

SilcUInt32 silc_cipher_get_block_len(SilcCipher cipher)
{
  return cipher->cipher->block_len;
}

/* Returns the IV length of the cipher. */

SilcUInt32 silc_cipher_get_iv_len(SilcCipher cipher)
{
  return cipher->cipher->iv_len;
}

/* Returns the name of the cipher */

const char *silc_cipher_get_name(SilcCipher cipher)
{
  return (const char *)cipher->cipher->name;
}

/* Returns the algorithm name of the cipher */

const char *silc_cipher_get_alg_name(SilcCipher cipher)
{
  return (const char *)cipher->cipher->alg_name;
}

/* Returns cipher mode */

SilcCipherMode silc_cipher_get_mode(SilcCipher cipher)
{
  return cipher->cipher->mode;
}

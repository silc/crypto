/*

  silcmac.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1999 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silccrypto.h"

/* MAC context */
struct SilcMacStruct {
  SilcMacObject *mac;
  SilcHash hash;
  unsigned char inner_pad[64];
  unsigned char outer_pad[64];
  unsigned char *key;
  unsigned int key_len        : 31;
  unsigned int allocated_hash : 1;   /* TRUE if the hash was allocated */
};

#ifndef SILC_SYMBIAN
/* List of dynamically registered MACs. */
SilcDList silc_mac_list = NULL;
#endif /* SILC_SYMBIAN */

/* Default macs for silc_mac_register_default(). */
const SilcMacObject silc_default_macs[] =
{
  { "hmac-sha256-96", 12 },
  { "hmac-sha512-96", 12 },
  { "hmac-sha1-96", 12 },
  { "hmac-md5-96", 12 },
  { "hmac-sha256", 32 },
  { "hmac-sha512", 64 },
  { "hmac-sha1", 20 },
  { "hmac-md5", 16 },

  { NULL, 0 }
};

static void silc_mac_init_internal(SilcMac mac, unsigned char *key,
				    SilcUInt32 key_len)
{
  SilcHash hash = mac->hash;
  SilcUInt32 block_len;
  unsigned char hvalue[SILC_HASH_MAXLEN];
  int i;

  memset(mac->inner_pad, 0, sizeof(mac->inner_pad));
  memset(mac->outer_pad, 0, sizeof(mac->outer_pad));

  block_len = silc_hash_block_len(hash);

  /* If the key length is more than block size of the hash function, the
     key is hashed. */
  if (key_len > block_len) {
    silc_hash_make(hash, key, key_len, hvalue);
    key = hvalue;
    key_len = silc_hash_len(hash);
  }

  /* Copy the key into the pads */
  memcpy(mac->inner_pad, key, key_len);
  memcpy(mac->outer_pad, key, key_len);

  /* XOR the key with pads */
  for (i = 0; i < block_len; i++) {
    mac->inner_pad[i] ^= 0x36;
    mac->outer_pad[i] ^= 0x5c;
  }
}

/* Registers a new MAC */

SilcBool silc_mac_register(const SilcMacObject *mac)
{
#ifndef SILC_SYMBIAN
  SilcMacObject *new;

  SILC_LOG_DEBUG(("Registering new MAC `%s'", mac->name));

  /* Check for existing */
  if (silc_mac_list) {
    SilcMacObject *entry;
    silc_dlist_start(silc_mac_list);
    while ((entry = silc_dlist_get(silc_mac_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, mac->name))
	return FALSE;
    }
  }

  new = silc_calloc(1, sizeof(*new));
  if (!new)
    return FALSE;
  new->name = strdup(mac->name);
  new->len = mac->len;

  /* Add to list */
  if (silc_mac_list == NULL)
    silc_mac_list = silc_dlist_init();
  silc_dlist_add(silc_mac_list, new);

#endif /* SILC_SYMBIAN */
  return TRUE;
}

/* Unregister a MAC */

SilcBool silc_mac_unregister(SilcMacObject *mac)
{
#ifndef SILC_SYMBIAN
  SilcMacObject *entry;

  SILC_LOG_DEBUG(("Unregistering MAC"));

  if (!silc_mac_list)
    return FALSE;

  silc_dlist_start(silc_mac_list);
  while ((entry = silc_dlist_get(silc_mac_list)) != SILC_LIST_END) {
    if (mac == SILC_ALL_MACS || entry == mac) {
      silc_dlist_del(silc_mac_list, entry);
      silc_free(entry->name);
      silc_free(entry);

      if (silc_dlist_count(silc_mac_list) == 0) {
	silc_dlist_uninit(silc_mac_list);
	silc_mac_list = NULL;
      }

      return TRUE;
    }
  }

#endif /* SILC_SYMBIAN */
  return FALSE;
}

/* Register default MACs */

SilcBool silc_mac_register_default(void)
{
  /* We use builtin MACs */
  return TRUE;
}

/* Unregister all MACs */

SilcBool silc_mac_unregister_all(void)
{
#ifndef SILC_SYMBIAN
  SilcMacObject *entry;

  if (!silc_mac_list)
    return FALSE;

  silc_dlist_start(silc_mac_list);
  while ((entry = silc_dlist_get(silc_mac_list)) != SILC_LIST_END) {
    silc_mac_unregister(entry);
    if (!silc_mac_list)
      break;
  }
#endif /* SILC_SYMBIAN */
  return TRUE;
}

/* Allocates a new SilcMac object of name of `name'.  The `hash' may
   be provided as argument.  If provided it is used as the hash function
   of the MAC.  If it is NULL then the hash function is allocated and
   the name of the hash algorithm is derived from the `name'. */

SilcBool silc_mac_alloc(const char *name, SilcMac *new_mac)
{
  SilcMacObject *entry = NULL;
  SilcHash hash = NULL;
  int i;

  SILC_LOG_DEBUG(("Allocating new MAC"));

  /* Allocate the new object */
  *new_mac = silc_calloc(1, sizeof(**new_mac));
  if (!(*new_mac))
    return FALSE;

  if (!hash) {
    char *tmp = strdup(name), *hname;

    hname = tmp;
    if (strchr(hname, '-'))
      hname = strchr(hname, '-') + 1;
    if (strchr(hname, '-'))
      *strchr(hname, '-') = '\0';

    if (!silc_hash_alloc(hname, &hash)) {
      silc_free(tmp);
      silc_free(*new_mac);
      *new_mac = NULL;
      return FALSE;
    }

    (*new_mac)->allocated_hash = TRUE;
    silc_free(tmp);
  }

  (*new_mac)->hash = hash;

#ifndef SILC_SYMBIAN
  /* Check registered list of MACs */
  if (silc_mac_list) {
    silc_dlist_start(silc_mac_list);
    while ((entry = silc_dlist_get(silc_mac_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name)) {
	(*new_mac)->mac = entry;
	return TRUE;
      }
    }
  }
#endif /* SILC_SYMBIAN */

  if (!entry) {
    /* Check builtin list of MACs */
    for (i = 0; silc_default_macs[i].name; i++) {
      if (!strcmp(silc_default_macs[i].name, name)) {
	(*new_mac)->mac = (SilcMacObject *)&(silc_default_macs[i]);
	return TRUE;
      }
    }
  }

  silc_free(*new_mac);
  *new_mac = NULL;
  return FALSE;
}

/* Free's the SilcMac object. */

void silc_mac_free(SilcMac mac)
{
  if (mac) {
    if (mac->allocated_hash)
      silc_hash_free(mac->hash);

    if (mac->key) {
      memset(mac->key, 0, mac->key_len);
      silc_free(mac->key);
    }

    silc_free(mac);
  }
}

/* Returns the length of the MAC that the MAC will produce. */

SilcUInt32 silc_mac_len(SilcMac mac)
{
  return mac->mac->len;
}

/* Get hash context */

SilcHash silc_mac_get_hash(SilcMac mac)
{
  return mac->hash;
}

/* Return name of mac */

const char *silc_mac_get_name(SilcMac mac)
{
  return mac->mac->name;
}

/* Returns TRUE if MAC `name' is supported. */

SilcBool silc_mac_is_supported(const char *name)
{
  SilcMacObject *entry;
  int i;

  if (!name)
    return FALSE;

#ifndef SILC_SYMBIAN
  if (silc_mac_list) {
    silc_dlist_start(silc_mac_list);
    while ((entry = silc_dlist_get(silc_mac_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name))
	return TRUE;
    }
  }
#endif /* SILC_SYMBIAN */

  for (i = 0; silc_default_macs[i].name; i++)
    if (!strcmp(silc_default_macs[i].name, name))
      return TRUE;

  return FALSE;
}

/* Returns comma separated list of supported MACs. */

char *silc_mac_get_supported()
{
  SilcMacObject *entry, *entry2;
  char *list = NULL;
  int len = 0, i;

#ifndef SILC_SYMBIAN
  if (silc_mac_list) {
    silc_dlist_start(silc_mac_list);
    while ((entry = silc_dlist_get(silc_mac_list)) != SILC_LIST_END) {
      len += strlen(entry->name);
      list = silc_realloc(list, len + 1);

      memcpy(list + (len - strlen(entry->name)),
	     entry->name, strlen(entry->name));
      memcpy(list + len, ",", 1);
      len++;
    }
  }
#endif /* SILC_SYMBIAN */


  for (i = 0; silc_default_macs[i].name; i++) {
    entry = (SilcMacObject *)&(silc_default_macs[i]);

    if (silc_mac_list) {
      silc_dlist_start(silc_mac_list);
      while ((entry2 = silc_dlist_get(silc_mac_list)) != SILC_LIST_END) {
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

  list[len - 1] = 0;

  return list;
}

/* Sets the MAC key used in the MAC creation */

void silc_mac_set_key(SilcMac mac, const unsigned char *key,
		       SilcUInt32 key_len)
{
  if (mac->key) {
    memset(mac->key, 0, mac->key_len);
    silc_free(mac->key);
  }
  mac->key = silc_malloc(key_len);
  if (!mac->key)
    return;
  mac->key_len = key_len;
  memcpy(mac->key, key, key_len);
}

/* Return MAC key */

const unsigned char *silc_mac_get_key(SilcMac mac, SilcUInt32 *key_len)
{
  if (key_len)
    *key_len = mac->key_len;
  return (const unsigned char *)mac->key;
}

/* Create the MAC. This is thee make_mac function pointer.  This
   uses the internal key set with silc_mac_set_key. */

void silc_mac_make(SilcMac mac, unsigned char *data,
		    SilcUInt32 data_len, unsigned char *return_hash,
		    SilcUInt32 *return_len)
{
  SILC_LOG_DEBUG(("Making MAC for message"));

  silc_mac_init(mac);
  silc_mac_update(mac, data, data_len);
  silc_mac_final(mac, return_hash, return_len);
}

/* Creates MAC just as above except that this doesn't use the internal
   key. The key is sent as argument to the function. */

void silc_mac_make_with_key(SilcMac mac, unsigned char *data,
			     SilcUInt32 data_len,
			     unsigned char *key, SilcUInt32 key_len,
			     unsigned char *return_hash,
			     SilcUInt32 *return_len)
{
  SILC_LOG_DEBUG(("Making MAC for message"));

  silc_mac_init_with_key(mac, key, key_len);
  silc_mac_update(mac, data, data_len);
  silc_mac_final(mac, return_hash, return_len);
}

/* Creates the MAC just as above except that the hash value is truncated
   to the truncated_len sent as argument. NOTE: One should not truncate to
   less than half of the length of original hash value. However, this
   routine allows these dangerous truncations. */

void silc_mac_make_truncated(SilcMac mac, unsigned char *data,
			      SilcUInt32 data_len,
			      SilcUInt32 truncated_len,
			      unsigned char *return_hash)
{
  unsigned char hvalue[SILC_HASH_MAXLEN];

  SILC_LOG_DEBUG(("Making MAC for message"));

  silc_mac_init(mac);
  silc_mac_update(mac, data, data_len);
  silc_mac_final(mac, return_hash, NULL);
  memcpy(return_hash, hvalue, truncated_len);
  memset(hvalue, 0, sizeof(hvalue));
}

/* Init MAC for silc_mac_update and silc_mac_final. */

void silc_mac_init(SilcMac mac)
{
  silc_mac_init_with_key(mac, mac->key, mac->key_len);
}

/* Same as above but with specific key */

void silc_mac_init_with_key(SilcMac mac, const unsigned char *key,
			     SilcUInt32 key_len)
{
  SilcHash hash = mac->hash;
  silc_mac_init_internal(mac, (unsigned char *)key, key_len);
  silc_hash_init(hash);
  silc_hash_update(hash, mac->inner_pad, silc_hash_block_len(hash));
}

/* Add data to be used in the MAC computation. */

void silc_mac_update(SilcMac mac, const unsigned char *data,
		      SilcUInt32 data_len)
{
  SilcHash hash = mac->hash;
  silc_hash_update(hash, data, data_len);
}

/* Compute the final MAC. */

void silc_mac_final(SilcMac mac, unsigned char *return_hash,
		    SilcUInt32 *return_len)
{
  SilcHash hash = mac->hash;
  unsigned char digest[SILC_HASH_MAXLEN];

  silc_hash_final(hash, digest);
  silc_hash_init(hash);
  silc_hash_update(hash, mac->outer_pad, silc_hash_block_len(hash));
  silc_hash_update(hash, digest, silc_hash_len(hash));
  silc_hash_final(hash, digest);
  memcpy(return_hash, digest, mac->mac->len);
  memset(digest, 0, sizeof(digest));

  if (return_len)
    *return_len = mac->mac->len;
}

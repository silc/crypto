/*

  silcmac.h

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

#ifndef SILCMAC_H
#define SILCMAC_H

/****h* silccrypt/MAC Interface
 *
 * DESCRIPTION
 *
 * The Message Authentication Code interface for computing MAC values for
 * authentication purposes.  The MAC is usually used in combination with
 * encryption to provide authentication.
 *
 * EXAMPLE
 *
 * SilcMac hmac;
 *
 * // Allocate HMAC
 * silc_mac_alloc(SILC_MAC_HMAC_SHA256, &hmac);
 *
 * // Set secret key to the MAC
 * silc_mac_set_key(hmac, key, key_len);
 *
 * // Compute MAC
 * unsigned char mac[SILC_MAC_MAXLEN];
 * SilcUInt32 mac_len;
 *
 * silc_mac_make(hmac, data, data_len, digest, &mac_len);
 *
 * // Free MAC
 * silc_mac_free(hmac);
 *
 ***/

/****s* silccrypt/SilcMac
 *
 * NAME
 *
 *    typedef struct SilcMacStruct *SilcMac;
 *
 * DESCRIPTION
 *
 *    This context is the actual MAC context and is allocated
 *    by silc_mac_alloc and given as argument usually to all
 *    silc_mac_* functions.  It is freed by the silc_mac_free
 *    function.
 *
 ***/
typedef struct SilcMacStruct *SilcMac;

/****d* silccrypt/MACs
 *
 * NAME
 *
 *    MAC Algorithms
 *
 * DESCRIPTION
 *
 *    Supported MAC algorithm names.  These names can be given as argument
 *    to silc_mac_alloc.
 *
 * SOURCE
 */

/* HMAC with SHA-256, MAC truncated to 96 bits */
#define SILC_MAC_HMAC_SHA256_96   "hmac-sha256-96"

/* HMAC with SHA-512, MAC truncated to 96 bits */
#define SILC_MAC_HMAC_SHA512_96   "hmac-sha512-96"

/* HMAC with SHA-1, MAC truncated to 96 bits */
#define SILC_MAC_HMAC_SHA1_96     "hmac-sha1-96"

/* HMAC with MD5, MAC truncated to 96 bits */
#define SILC_MAC_HMAC_MD5_96      "hmac-md5-96"

/* HMAC with SHA-256 */
#define SILC_MAC_HMAC_SHA256      "hmac-sha256"

/* HMAC with SHA-512 */
#define SILC_MAC_HMAC_SHA512      "hmac-sha512"

/* HMAC with SHA-1 */
#define SILC_MAC_HMAC_SHA1        "hmac-sha1"

/* HMAC with MD5 */
#define SILC_MAC_HMAC_MD5         "hmac-md5"
/***/

/****d* silccrypt/SILC_MAC_MAXLEN
 *
 * NAME
 *
 *    #define SILC_MAC_MAXLEN 64
 *
 * DESCRIPTION
 *
 *    Maximum size of digest any algorithm supported by SILC Crypto Toolkit
 *    would produce.  You can use this to define static digest buffers and
 *    safely use it with any hash function.
 *
 ***/
#define SILC_MAC_MAXLEN 64

/* MAC implementation object */
typedef struct {
  char *name;
  SilcUInt32 len;
} SilcMacObject;

/* Marks for all MACs. This can be used in silc_mac_unregister
   to unregister all MACs at once. */
#define SILC_ALL_MACS ((SilcMacObject *)1)

/* Default MACs for silc_mac_register_default(). */
extern DLLAPI const SilcMacObject silc_default_macs[];

/* Prototypes */

/****f* silccrypt/silc_mac_register
 *
 * SYNOPSIS
 *
 *    SilcBool silc_mac_register(const SilcMacObject *mac);
 *
 * DESCRIPTION
 *
 *    Registers a new MAC into Crypto Toolkit. This function can be used
 *    at the initialization.  All registered MACs should be unregistered
 *    with silc_mac_unregister.  Returns FALSE on error.  Usually this
 *    function is not needed.  The default MAC algorithms are automatically
 *    registered.  This can be used to change the order of the registered
 *    MAC algorithms by re-registering them in desired order, or add new
 *    algorithms.
 *
 ***/
SilcBool silc_mac_register(const SilcMacObject *mac);

/****f* silccrypt/silc_mac_unregister
 *
 * SYNOPSIS
 *
 *    SilcBool silc_mac_unregister(SilcMacObject *mac);
 *
 * DESCRIPTION
 *
 *    Unregister a MAC from SILC by the MAC structure `mac'.  This
 *    should be called for all MACs registered with silc_mac_register.
 *    Returns FALSE on error.
 *
 ***/
SilcBool silc_mac_unregister(SilcMacObject *mac);

/****f* silccrypt/silc_mac_register_default
 *
 * SYNOPSIS
 *
 *    SilcBool silc_mac_register_default(void);
 *
 * DESCRIPTION
 *
 *    Registers all default MACs into the SILC.  These are the MACs
 *    that are builtin in the sources.  Application need not call this
 *    directly.  By calling silc_crypto_init this function is called.
 *
 ***/
SilcBool silc_mac_register_default(void);

/****f* silccrypt/silc_mac_unregister_all
 *
 * SYNOPSIS
 *
 *    SilcBool silc_mac_unregister_all(void);
 *
 * DESCRIPTION
 *
 *    Unregisters all registered MACs.  Application need not call this
 *    directly.  By calling silc_crypto_uninit this function is called.
 *
 ***/
SilcBool silc_mac_unregister_all(void);

/****f* silccrypt/silc_mac_alloc
 *
 * SYNOPSIS
 *
 *    SilcBool silc_mac_alloc(const char *name, SilcMac *new_mac);
 *
 * DESCRIPTION
 *
 *    Allocates a new SilcMac object of name of `name'.  Returns FALSE if
 *    such MAC does not exist.  After the MAC is allocated a key must be
 *    set for it by calling silc_mac_set_key.
 *
 *    See MACs for supported MAC algorithms.
 *
 ***/
SilcBool silc_mac_alloc(const char *name, SilcMac *new_mac);

/****f* silccrypt/silc_mac_free
 *
 * SYNOPSIS
 *
 *    void silc_mac_free(SilcMac mac);
 *
 * DESCRIPTION
 *
 *    Frees the allocated MAC context.  The key that may have been set
 *    with the silc_mac_set_key is also destroyed.
 *
 ***/
void silc_mac_free(SilcMac mac);

/****f* silccrypt/silc_mac_is_supported
 *
 * SYNOPSIS
 *
 *    SilcBool silc_mac_is_supported(const char *name);
 *
 * DESCRIPTION
 *
 *    Returns TRUE if the MAC indicated by the `name' exists.
 *
 ***/
SilcBool silc_mac_is_supported(const char *name);

/****f* silccrypt/silc_mac_get_supported
 *
 * SYNOPSIS
 *
 *    char *silc_mac_get_supported(void);
 *
 * DESCRIPTION
 *
 *    Returns comma (`,') separated list of registered MACs.  The caller
 *    must free the returned pointer.
 *
 ***/
char *silc_mac_get_supported(void);

/****f* silccrypt/silc_mac_len
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_mac_len(SilcMac mac);
 *
 * DESCRIPTION
 *
 *    Returns the length of the MAC that the MAC will produce.
 *
 ***/
SilcUInt32 silc_mac_len(SilcMac mac);

/****f* silccrypt/silc_mac_get_name
 *
 * SYNOPSIS
 *
 *    const char *silc_mac_get_name(SilcMac mac);
 *
 * DESCRIPTION
 *
 *    Returns the name of the MAC context.
 *
 ***/
const char *silc_mac_get_name(SilcMac mac);

/****f* silccrypt/silc_mac_get_hash
 *
 * SYNOPSIS
 *
 *    SilcHash silc_mac_get_hash(SilcMac mac);
 *
 * DESCRIPTION
 *
 *    Returns the SilcHash context that has been associated with the
 *    MAC context or NULL if the `mac' doesn't use hash function.  In effect
 *    with HMACs this returns the underlaying hash function.  The caller
 *    must not free the returned context.
 *
 ***/
SilcHash silc_mac_get_hash(SilcMac hmac);

/****f* silccrypt/silc_mac_set_key
 *
 * SYNOPSIS
 *
 *    void silc_mac_set_key(SilcMac mac, const unsigned char *key,
 *                          SilcUInt32 key_len);
 *
 * DESCRIPTION
 *
 *    Sets the key to be used in the MAC operation.  This must be set
 *    before calling silc_mac_make or silc_mac_final functions.  If
 *    you do not want to set the key you can still produce a MAC by
 *    calling the silc_mac_make_with_key where you give the key as
 *    argument.  Usually application still wants to set the key.
 *
 ***/
void silc_mac_set_key(SilcMac mac, const unsigned char *key,
		      SilcUInt32 key_len);

/****f* silccrypt/silc_mac_get_key
 *
 * SYNOPSIS
 *
 *    const unsigned char *
 *    silc_mac_get_key(SilcMac mac, SilcUInt32 *key_len);
 *
 * DESCRIPTION
 *
 *    Returns the key data from the `mac' set with silc_hamc_set_key.
 *    The caller must not free the returned pointer.
 *
 ***/
const unsigned char *silc_mac_get_key(SilcMac mac, SilcUInt32 *key_len);

/****f* silccrypt/silc_mac_make
 *
 * SYNOPSIS
 *
 *    void silc_mac_make(SilcMac mac, unsigned char *data,
 *                       SilcUInt32 data_len, unsigned char *return_hash,
 *                       SilcUInt32 *return_len);
 *
 * DESCRIPTION
 *
 *    Computes a MAC from a data buffer indicated by the `data' of the
 *    length of `data_len'.  The returned MAC is copied into the
 *    `return_hash' pointer which must be at least the size of the
 *    value silc_mac_len returns.  The returned length is still
 *    returned to `return_len'.
 *
 ***/
void silc_mac_make(SilcMac mac, unsigned char *data,
		   SilcUInt32 data_len, unsigned char *return_hash,
		   SilcUInt32 *return_len);

/****f* silccrypt/silc_mac_make_with_key
 *
 * SYNOPSIS
 *
 *    void silc_mac_make_with_key(SilcMac mac, unsigned char *data,
 *                                SilcUInt32 data_len,
 *                                unsigned char *key, SilcUInt32 key_len,
 *                                unsigned char *return_hash,
 *                                SilcUInt32 *return_len);
 *
 * DESCRIPTION
 *
 *    Same as the silc_mac_make but takes the key for the MAC as argument.
 *    If this is used the key that may have been set by calling
 *    silc_mac_set_key is ignored.
 *
 ***/
void silc_mac_make_with_key(SilcMac mac, unsigned char *data,
			    SilcUInt32 data_len,
			    unsigned char *key, SilcUInt32 key_len,
			    unsigned char *return_hash,
			    SilcUInt32 *return_len);

/****f* silccrypt/silc_mac_make_truncated
 *
 * SYNOPSIS
 *
 *    void silc_mac_make_truncated(SilcMac mac,
 *                                 unsigned char *data,
 *                                 SilcUInt32 data_len,
 *                                 SilcUInt32 truncated_len,
 *                                 unsigned char *return_hash);
 *
 * DESCRIPTION
 *
 *    Same as the silc_mac_make except that the returned MAC is
 *    truncated to the length indicated by the `truncated_len'.  Some
 *    special applications may need this function.  The `return_hash'
 *    must be at least the size of `truncated_len'.
 *
 * NOTES
 *
 *    For security reasons, one should not truncate to less than half
 *    of the length of the true MAC lenght.  However, since this routine
 *    may be used to non-critical applications this allows these dangerous
 *    truncations.
 *
 ***/
void silc_mac_make_truncated(SilcMac mac,
			     unsigned char *data,
			     SilcUInt32 data_len,
			     SilcUInt32 truncated_len,
			     unsigned char *return_hash);

/****f* silccrypt/silc_mac_init
 *
 * SYNOPSIS
 *
 *    void silc_mac_init(SilcMac mac);
 *
 * DESCRIPTION
 *
 *    Sometimes calling the silc_mac_make might not be the most
 *    optimal case of doing MACs.  If you have a lot of different data
 *    that you need to put together for computing a MAC you may either
 *    put them into a buffer and compute the MAC from the buffer by
 *    calling the silc_mac_make, or you can use the silc_mac_init,
 *    silc_mac_update and silc_mac_final to do the MAC.  This function
 *    prepares the allocated MAC context for this kind of MAC
 *    computation.  The caller must have been called the function
 *    silc_mac_set_key before calling this function.  To add the
 *    data to be used in the MAC computation call the silc_mac_update
 *    function.
 *
 ***/
void silc_mac_init(SilcMac mac);

/****f* silccrypt/silc_mac_init_with_key
 *
 * SYNOPSIS
 *
 *    void silc_mac_init_with_key(SilcMac mac, const unsigned char *key,
 *                                SilcUInt32 key_len);
 *
 * DESCRIPTION
 *
 *    Same as silc_mac_init but initializes with specific key.  The
 *    key that may have been set with silc_mac_set_key is ignored.
 *
 ***/
void silc_mac_init_with_key(SilcMac mac, const unsigned char *key,
			    SilcUInt32 key_len);

/****f* silccrypt/silc_mac_update
 *
 * SYNOPSIS
 *
 *    void silc_mac_update(SilcMac mac, const unsigned char *data,
 *                         SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    This function may be called to add data to be used in the MAC
 *    computation.  This can be called multiple times to add data from
 *    many sources before actually performing the MAC.  Once you've
 *    added all the data you need you can call the silc_mac_final to
 *    actually produce the MAC.
 *
 * EXAMPLE
 *
 *    unsigned char mac[20];
 *    SilcUInt32 mac_len;
 *
 *    silc_mac_init(mac);
 *    silc_mac_update(mac, data, data_len);
 *    silc_mac_update(mac, more_data, more_data_len);
 *    silc_mac_final(hac, mac, &mac_len);
 *
 ***/
void silc_mac_update(SilcMac mac, const unsigned char *data,
		     SilcUInt32 data_len);

/****f* silccrypt/silc_mac_final
 *
 * SYNOPSIS
 *
 *    void silc_mac_final(SilcMac mac, unsigned char *return_hash,
 *                        SilcUInt32 *return_len);
 *
 * DESCRIPTION
 *
 *    This function is used to produce the final MAC from the data
 *    that has been added to the MAC context by calling the
 *    silc_mac_update function.  The MAC is copied in to the
 *    `return_hash' pointer which must be at least the size that
 *    the silc_mac_len returns.  The length of the MAC is still
 *    returned into `return_len'.
 *
 ***/
void silc_mac_final(SilcMac mac, unsigned char *return_hash,
		    SilcUInt32 *return_len);

/* Backwards support for old HMAC API */
#define SilcHmac SilcMac
#define SilcHmacObject SilcMacObject
#define SILC_ALL_HMACS SILC_ALL_MACS
#define silc_default_hmacs silc_default_macs
#define silc_hmac_register silc_mac_register
#define silc_hmac_unregister silc_mac_unregister
#define silc_hmac_register_default silc_mac_register_default
#define silc_hmac_unregister_all silc_mac_unregister_all
#define silc_hmac_alloc(name, hash, new_hmac) silc_mac_alloc(name, new_hmac)
#define silc_hmac_free silc_mac_free
#define silc_hmac_is_supported silc_mac_is_supported
#define silc_hmac_get_supported silc_mac_get_supported
#define silc_hmac_len silc_mac_len
#define silc_hmac_get_hash silc_mac_get_hash
#define silc_hmac_get_name silc_mac_get_name
#define silc_hmac_set_key silc_mac_set_key
#define silc_hmac_get_key silc_mac_get_key
#define silc_hmac_make silc_mac_make
#define silc_hmac_init_with_key silc_mac_init_with_key
#define silc_hmac_update silc_mac_update
#define silc_hmac_final silc_mac_final

#endif /* SILCMAC_H */

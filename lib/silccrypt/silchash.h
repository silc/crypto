/*

  silchash.h

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

#ifndef SILCHASH_H
#define SILCHASH_H

/****h* silccrypt/Hash Function Interface
 *
 * DESCRIPTION
 *
 * This is the interface for hash functions which are used to create message
 * digests.  The routines are used in various cryptographic operations.
 *
 * EXAMPLE
 *
 * SilcHash sha1hash;
 *
 * // Allocate SHA-1 hash function
 * silc_hash_alloc(SILC_HASH_SHA1, &sha1hash);
 *
 * // Hash some data
 * unsigned char digest[SILC_HASH_MAXLEN];
 *
 * silc_hash_init(sha1hash);
 * silc_hash_update(sha1hash, "foobar", 6);
 * silc_hash_final(sha1hash, digest);
 *
 * // Same can be done in one call also
 * silc_hash_make(sha1hash, "foobar", 6, digest);
 *
 * // Free hash
 * silc_hash_free(sha1hash);
 *
 ***/

/****s* silccrypt/SilcHash
 *
 * NAME
 *
 *    typedef struct SilcHashStruct *SilcHash;
 *
 * DESCRIPTION
 *
 *    This context is the actual hash function context and is allocated
 *    by silc_hash_alloc and given as argument usually to all
 *    silc_hash_* functions.  It is freed by the silc_hash_free
 *    function.
 *
 ***/
typedef struct SilcHashStruct *SilcHash;

/****d* silccrypt/Hashes
 *
 * NAME
 *
 *    Hash functions
 *
 * DESCRIPTION
 *
 *    Supported hash function names.  These names can be given as argument
 *    to silc_hash_alloc.
 *
 * SOURCE
 */
#define SILC_HASH_SHA256          "sha256"       /* SHA-256 */
#define SILC_HASH_SHA512          "sha512"       /* SHA-512 */
#define SILC_HASH_SHA1            "sha1"	 /* SHA-1 */
#define SILC_HASH_MD5             "md5"		 /* MD5 */
/***/

/****d* silccrypt/Hash-OIDs
 *
 * NAME
 *
 *    Hash functions
 *
 * DESCRIPTION
 *
 *    Supported hash function OIDs.  These names can be given as argument
 *    to silc_hash_alloc_by_oid.
 *
 * SOURCE
 */
#define SILC_HASH_OID_SHA256    "2.16.840.1.101.3.4.2.1"
#define SILC_HASH_OID_SHA512    "2.16.840.1.101.3.4.2.3"
#define SILC_HASH_OID_SHA1      "1.3.14.3.2.26"
#define SILC_HASH_OID_MD5       "1.2.840.113549.2.5"
/***/

/****d* silccrypt/SILC_HASH_MAXLEN
 *
 * NAME
 *
 *    #define SILC_HASH_MAXLEN 64
 *
 * DESCRIPTION
 *
 *    Maximum size of digest any algorithm supported by SILC Crypto Toolkit
 *    would produce.  You can use this to define static digest buffers and
 *    safely use it with any hash function.
 *
 * EXAMPLE
 *
 *   unsigned char digest[SILC_HASH_MAXLEN];
 *
 *   silc_hash_make(hash, data, data_len, digest);
 *
 ***/
#define SILC_HASH_MAXLEN 64

/* Hash implementation object */
typedef struct {
  char *name;
  char *oid;
  SilcUInt16 hash_len;
  SilcUInt16 block_len;

  void (*init)(void *);
  void (*update)(void *, const unsigned char *, SilcUInt32);
  void (*final)(void *, unsigned char *);
  void (*transform)(void *, const unsigned char *);
  SilcUInt32 (*context_len)();
} SilcHashObject;

/* Marks for all hash functions. This can be used in silc_hash_unregister
   to unregister all hash function at once. */
#define SILC_ALL_HASH_FUNCTIONS ((SilcHashObject *)1)

/* Default hash functions for silc_hash_register_default(). */
extern DLLAPI const SilcHashObject silc_default_hash[];

/* Macros */

/* Following macros are used to implement the SILC Hash API. These
   macros should be used instead of declaring functions by hand. */

/* Macros that can be used to declare SILC Hash API functions. */
#define SILC_HASH_API_INIT(hash)					\
void silc_##hash##_init(void *context)
#define SILC_HASH_API_UPDATE(hash)					\
void silc_##hash##_update(void *context, const unsigned char *data,	\
                          SilcUInt32 len)
#define SILC_HASH_API_FINAL(hash)					\
void silc_##hash##_final(void *context, unsigned char *digest)
#define SILC_HASH_API_TRANSFORM(hash)					\
void silc_##hash##_transform(void *state, const unsigned char *buffer)
#define SILC_HASH_API_CONTEXT_LEN(hash)					\
SilcUInt32 silc_##hash##_context_len()

/* Prototypes */

/****f* silccrypt/silc_hash_register
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_register(const SilcHashObject *hash);
 *
 * DESCRIPTION
 *
 *    Registers a new hash function into the SILC.  This function can be
 *    used at the initialization.  All registered hash functions should be
 *    unregistered with silc_hash_unregister.  Returns FALSE on error.
 *    Usually this function is not needed.  The default hash functions are
 *    automatically registered.  This can be used to change the order of
 *    the registered hash functions by re-registering them in desired order,
 *    or add new hash functions.
 *
 ***/
SilcBool silc_hash_register(const SilcHashObject *hash);

/****f* silccrypt/silc_hash_unregister
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_unregister(SilcHashObject *hash);
 *
 * DESCRIPTION
 *
 *    Unregister a hash function from SILC by the SilcHashObject `hash'.
 *    This should be called for all hash functions registered with
 *    silc_hash_register.  Returns FALSE on error.
 *
 ***/
SilcBool silc_hash_unregister(SilcHashObject *hash);

/****f* silccrypt/silc_hash_register_default
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_register_default(void);
 *
 * DESCRIPTION
 *
 *    Registers all default hash functions into the SILC.  Application
 *    need not call this directly.  By calling silc_crypto_init this function
 *    is called.
 *
 ***/
SilcBool silc_hash_register_default(void);

/****f* silccrypt/silc_hash_unregister_all
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_unregister_all(void);
 *
 * DESCRIPTION
 *
 *    Unregisters all registered hash functions.  Application need not
 *    call this directly.  By calling silc_crypto_uninit this function is
 *    called.
 *
 ***/
SilcBool silc_hash_unregister_all(void);

/****f* silccrypt/silc_hash_alloc
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_alloc(const char *name, SilcHash *new_hash);
 *
 * DESCRIPTION
 *
 *    Allocates a new SilcHash object of name of `name'.  The new allocated
 *    hash function is returned into `new_hash' pointer.  This function
 *    returns FALSE if such hash function does not exist.
 *
 *    See Hashes for supported hash functions.
 *
 ***/
SilcBool silc_hash_alloc(const char *name, SilcHash *new_hash);

/****f* silccrypt/silc_hash_alloc_by_oid
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_alloc_by_oid(const char *oid, SilcHash *new_hash);
 *
 * DESCRIPTION
 *
 *    Same as silc_hash_alloc but allocates the hash algorithm by the
 *    hash algorithm OID string indicated by `oid'. Returns FALSE if such
 *    hash function does not exist.
 *
 *    See Hash-OIDs for supported hash function OIDs.
 *
 ***/
SilcBool silc_hash_alloc_by_oid(const char *oid, SilcHash *new_hash);

/****f* silccrypt/silc_hash_free
 *
 * SYNOPSIS
 *
 *    void silc_hash_free(SilcHash hash);
 *
 * DESCRIPTION
 *
 *    Frees the allocated hash function context.
 *
 ***/
void silc_hash_free(SilcHash hash);

/****f* silccrypt/silc_hash_is_supported
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_is_supported(const char *name);
 *
 * DESCRIPTION
 *
 *    Returns TRUE if the hash function indicated by the `name' exists.
 *
 ***/
SilcBool silc_hash_is_supported(const char *name);

/****f* silccrypt/silc_hash_get_supported
 *
 * SYNOPSIS
 *
 *    char *silc_hash_get_supported(void);
 *
 * DESCRIPTION
 *
 *    Returns comma (`,') separated list of registered hash functions  This
 *    is used for example when sending supported hash function list during
 *    the SILC Key Exchange protocol (SKE).  The caller must free the returned
 *    pointer.
 *
 ***/
char *silc_hash_get_supported(void);

/****f* silccrypt/silc_hash_len
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_len(SilcHash hash);
 *
 * DESCRIPTION
 *
 *    Returns the length of the message digest the hash function produce.
 *
 ***/
SilcUInt32 silc_hash_len(SilcHash hash);

/****f* silccrypt/silc_hash_block_len
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_block_len(SilcHash hash);
 *
 * DESCRIPTION
 *
 *    Returns the block length of the hash function.
 *
 ***/
SilcUInt32 silc_hash_block_len(SilcHash hash);

/****f* silccrypt/silc_hash_get_name
 *
 * SYNOPSIS
 *
 *    const char *silc_hash_get_name(SilcHash hash);
 *
 * DESCRIPTION
 *
 *    Returns the name of the hash function indicated by the `hash' context.
 *
 ***/
const char *silc_hash_get_name(SilcHash hash);

/****f* silccrypt/silc_hash_get_oid
 *
 * SYNOPSIS
 *
 *    const char *silc_hash_get_name(SilcHash hash);
 *
 * DESCRIPTION
 *
 *    Returns the hash OID string.  Returns NULL if the hash doesn't have
 *    OID string.  Use strlen() to get the OID string length.
 *
 ***/
const char *silc_hash_get_oid(SilcHash hash);

/****f* silccrypt/silc_hash_make
 *
 * SYNOPSIS
 *
 *    void silc_hash_make(SilcHash hash, const unsigned char *data,
 *                        SilcUInt32 len, unsigned char *return_hash);
 *
 * DESCRIPTION
 *
 *    Computes the message digest (hash) out of the data indicated by
 *    `data' of length of `len' bytes.  Returns the message digest to the
 *    `return_hash' buffer which must be at least of the size of the
 *    message digest the `hash' produces.
 *
 ***/
void silc_hash_make(SilcHash hash, const unsigned char *data,
		    SilcUInt32 len, unsigned char *return_hash);

/****f* silccrypt/silc_hash_init
 *
 * SYNOPSIS
 *
 *    void silc_hash_init(SilcHash hash);
 *
 * DESCRIPTION
 *
 *    Sometimes calling the silc_hash_make might not be the most optimal
 *    case of computing digests.  If you have a lot of different data
 *    that you need to put together for computing a digest you may either
 *    put them into a buffer and compute the digest from the buffer by
 *    calling the silc_hash_make, or you can use the silc_hash_init,
 *    silc_hash_update and silc_hash_final to do the digest.  This function
 *    prepares the allocated hash function context for this kind of digest
 *    computation.  To add the data to be used in the digest computation
 *    call the silc_hash_update function.
 *
 ***/
void silc_hash_init(SilcHash hash);

/****f* silccrypt/silc_hash_update
 *
 * SYNOPSIS
 *
 *    void silc_hash_update(SilcHash hash, const unsigned char *data,
 *                          SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    This function may be called to add data to be used in the digest
 *    computation.  This can be called multiple times to add data from
 *    many sources before actually computing the digest.  Once you've
 *    added all the data you need you can call the silc_hash_final to
 *    actually produce the message digest value.
 *
 * EXAMPLE
 *
 *    unsigned char digest[20];
 *
 *    silc_hash_init(hash);
 *    silc_hash_update(hash, data, data_len);
 *    silc_hash_update(hash, more_data, more_data_len);
 *    silc_hash_final(hash, digest);
 *
 ***/
void silc_hash_update(SilcHash hash, const unsigned char *data,
		      SilcUInt32 data_len);

/****f* silccrypt/silc_hash_final
 *
 * SYNOPSIS
 *
 *    void silc_hash_final(SilcHash hash, unsigned char *return_hash);
 *
 * DESCRIPTION
 *
 *    This function is used to produce the final message digest from
 *    the data that has been added to the hash function context by calling
 *    the silc_hash_update function.  The digest is copied in to the
 *    `return_hash' pointer which must be at least the size that
 *    the silc_hash_len returns.
 *
 ***/
void silc_hash_final(SilcHash hash, unsigned char *return_hash);

/****f* silccrypt/silc_hash_transform
 *
 * SYNOPSIS
 *
 *    void silc_hash_transform(SilcHash hash, void *state,
 *                             const unsigned char *data);
 *
 * DESCRIPTION
 *
 *    This is special function for calling the hash function's internal
 *    digest generation function.  The size of the `state' array and the
 *    sizeof the `data' buffer is hash function specific and must be
 *    known by the caller.  Usually this function is not needed.
 *
 ***/
void silc_hash_transform(SilcHash hash, void *state,
			 const unsigned char *data);

/****f* silccrypt/silc_hash_fingerprint
 *
 * SYNOPSIS
 *
 *    char *silc_hash_fingerprint(SilcHash hash, const unsigned char *data,
 *                                SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Utility function which can be used to create a textual fingerprint
 *    out of the data indicated by `data' of length of `data_len' bytes.
 *    If `hash' is NULL then SHA1 hash function is used automatically.
 *    The caller must free the returned string.
 *
 *    Example output could be:
 *      41BF 5C2E 4149 039A 3917  831F 65C4 0A69 F98B 0A4D
 *
 ***/
char *silc_hash_fingerprint(SilcHash hash, const unsigned char *data,
			    SilcUInt32 data_len);

/****f* silccrypt/silc_hash_babbleprint
 *
 * SYNOPSIS
 *
 *    char *silc_hash_babbleprint(SilcHash hash, const unsigned char *data,
 *                                SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Utility function which can be used to create a textual babbleprint
 *    out of the data indicated by `data' of length of `data_len' bytes.
 *    If `hash' is NULL then SHA1 hash function is used automatically.
 *    The caller must free the returned string.
 *
 *    The babbleprint is same as fingerprint but encoded in a form which
 *    makes it easier to pronounce.  When verifying fingerprint for example
 *    over a phone call, the babbleprint makes it easier to read the
 *    fingerprint.
 *
 *    Example output could be:
 *      xiber-zulad-vubug-noban-puvyc-labac-zonos-gedik-novem-rudog-tyxix
 *
 ***/
char *silc_hash_babbleprint(SilcHash hash, const unsigned char *data,
			    SilcUInt32 data_len);

#endif

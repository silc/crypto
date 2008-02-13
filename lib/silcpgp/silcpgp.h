/*

  silcpgp.h

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

/****h* silcpgp/OpenPGP Interface
 *
 * DESCRIPTION
 *
 * This implementation supports OpenPGP public key versions 2, 3 and 4.
 * OpenPGP private key support exist only for version 4.  This means that
 * this API can be used verify signatures with all versions of OpenPGP public
 * keys, but signatures can only be computed with version 4 private keys.
 * This implementation also only generates version 4 private keys.
 *
 * The interface implements the RFC 2440 and rfc2440bis-22 Internet Draft
 * specifications.
 *
 ***/

#ifndef SILCPGP_H
#define SILCPGP_H

/****s* silcpgp/SilcPGPPublicKey
 *
 * NAME
 *
 *    typedef struct { ... } *SilcPGPPublicKey;
 *
 * DESCRIPTION
 *
 *    This structure defines the OpenPGP public key (certificate).  This
 *    context can be retrieved from SilcPublicKey by calling
 *    silc_pkcs_public_key_get_pkcs for the PKCS type SILC_PKCS_OPENPGP.
 *
 * SOURCE
 */
typedef struct SilcPGPPublicKeyStruct {
  SilcList packets;		   /* Packets making this public key, contains
				      main key, subkeys, signatures etc. */
  SilcDList subkeys;		   /* Subkeys, each is SilcPGPPublicKey */

  const SilcPKCSAlgorithm *pkcs;   /* PKCS Algorithm */
  void *public_key;		   /* PKCS Algorithm specific public key */

  unsigned char key_id[8];	   /* Public key ID */
  unsigned char fingerprint[20];   /* Fingerprint of the public key */

  SilcUInt32 created;		   /* Time when public key was created */
  SilcUInt16 valid;		   /* Validity period (V3 keys) */
  SilcUInt8 version;		   /* Version, 2, 3 or 4 */
  SilcUInt8 algorithm;		   /* Algorithm, SilcPGPPKCSAlgorithm */
} *SilcPGPPublicKey;
/***/

/****s* silcpgp/SilcPGPPrivateKey
 *
 * NAME
 *
 *    typedef struct { ... } *SilcPGPPrivateKey;
 *
 * DESCRIPTION
 *
 *    This structure defines the OpenPGP private key.  This context can be
 *    retrieved from SilcPublicKey by calling silc_pkcs_private_key_get_pkcs
 *    for the PKCS type SILC_PKCS_OPENPGP.
 *
 * SOURCE
 */
typedef struct SilcPGPPrivateKeyStruct {
  SilcList packets;		   /* Packets making this private key, contains
				      main key, subkeys, signatures etc. */
  SilcDList subkeys;		   /* Subkeys, each is SilcPGPPrivateKey */

  SilcPGPPublicKey public_key;	   /* Public key */
  void *private_key;		   /* Algorithm specific private key */

  SilcUInt32 s2k_count;		   /* S2K iterate octet count */
  SilcUInt8 cipher;		   /* Cipher, SilcPGPCipher */
  SilcUInt8 s2k_type;		   /* S2K type, SilcPGPS2KType */
  SilcUInt8 s2k_hash;		   /* Hash, SilcPGPHash */
} *SilcPGPPrivateKey;
/***/

/****s* silcpgp/SilcPGPPacket
 *
 * NAME
 *
 *    typedef struct SilcPGPPacketStruct *SilcPGPPacket;
 *
 * DESCRIPTION
 *
 *    OpenPGP packet context.  This context is allocated by calling
 *    silc_pgp_packet_decode.
 *
 ***/
typedef struct SilcPGPPacketStruct *SilcPGPPacket;

/****d* silcpgp/SilcPGPPacketTag
 *
 * NAME
 *
 *    typedef enum { ... } SilcPGPPacketTag;
 *
 * DESCRIPTION
 *
 *    OpenPGP packet types.
 *
 * SOURCE
 */
typedef enum {
  SILC_PGP_PACKET_PKENC_SK        = 1,   /* Public key enc session key */
  SILC_PGP_PACKET_SIGNATURE       = 2,	 /* Signature packet */
  SILC_PGP_PACKET_SENC_SK         = 3,	 /* Symmetric-key enc session key */
  SILC_PGP_PACKET_OP_SIGNATURE    = 4,	 /* One pass signature packet */
  SILC_PGP_PACKET_SECKEY          = 5,	 /* Secret key packet */
  SILC_PGP_PACKET_PUBKEY          = 6,	 /* Public key packet */
  SILC_PGP_PACKET_SECKEY_SUB      = 7,	 /* Secret subkey packet */
  SILC_PGP_PACKET_COMP_DATA       = 8,	 /* Compressed data packet */
  SILC_PGP_PACKET_SENC_DATA       = 9,	 /* Symmetrically enc data packet */
  SILC_PGP_PACKET_MARKER          = 10,	 /* Marker packet */
  SILC_PGP_PACKET_LITERAL_DATA    = 11,	 /* Literal data packet */
  SILC_PGP_PACKET_TRUST           = 12,	 /* Trust packet */
  SILC_PGP_PACKET_USER_ID         = 13,	 /* User ID packet */
  SILC_PGP_PACKET_PUBKEY_SUB      = 14,	 /* Public subkey packet */
  SILC_PGP_PACKET_USER_ATTR       = 17,	 /* User attribute packet */
  SILC_PGP_PACKET_SENC_I_DATA     = 18,	 /* Symmetric key enc/integ data */
  SILC_PGP_PACKET_MDC             = 19,	 /* Modification detection code */
} SilcPGPPacketTag;
/***/

/****d* silcpgp/SilcPGPPKCSAlgorithm
 *
 * NAME
 *
 *    typedef enum { ... } SilcPGPPKCSAlgorithm;
 *
 * DESCRIPTION
 *
 *    OpenPGP public key cryptosystem algorithms.
 *
 * SOURCE
 */
typedef enum {
  SILC_PGP_PKCS_RSA               = 1,   /* RSA */
  SILC_PGP_PKCS_RSA_ENC_ONLY      = 2,   /* RSA encryption allowed only */
  SILC_PGP_PKCS_RSA_SIG_ONLY      = 3,   /* RSA signatures allowed only */
  SILC_PGP_PKCS_ELGAMAL_ENC_ONLY  = 16,	 /* Elgamal encryption only */
  SILC_PGP_PKCS_DSA               = 17,	 /* DSA */
  SILC_PGP_PKCS_ECDSA             = 19,	 /* ECDSA */
  SILC_PGP_PKCS_ELGAMAL           = 20,	 /* Elgamal encryption/signatures */
  SILC_PGP_PKCS_DH                = 21,	 /* Diffie-Hellman */
} SilcPGPPKCSAlgorithm;
/***/

/****d* silcpgp/SilcPGPCipher
 *
 * NAME
 *
 *    typedef enum { ... } SilcPGPCipher;
 *
 * DESCRIPTION
 *
 *    OpenPGP ciphers.
 *
 * SOURCE
 */
typedef enum {
  SILC_PGP_CIPHER_NONE            = 0,   /* No cipher, plaintext */
  SILC_PGP_CIPHER_IDEA            = 1,	 /* IDEA */
  SILC_PGP_CIPHER_3DES            = 2,	 /* Triple-DES */
  SILC_PGP_CIPHER_CAST5           = 3,	 /* CAST5 (CAST-128) */
  SILC_PGP_CIPHER_BLOWFISH        = 4,	 /* Blowfish */
  SILC_PGP_CIPHER_AES128          = 7,	 /* AES 128-bit key */
  SILC_PGP_CIPHER_AES192          = 8,	 /* AES 192-bit key */
  SILC_PGP_CIPHER_AES256          = 9,	 /* AES 256-bit key */
  SILC_PGP_CIPHER_TWOFISH         = 10,	 /* Twofish 256-bit key */
} SilcPGPCipher;
/***/

/****d* silcpgp/SilcPGPHash
 *
 * NAME
 *
 *    typedef enum { ... } SilcPGPHash;
 *
 * DESCRIPTION
 *
 *    OpenPGP hash functions.
 *
 * SOURCE
 */
typedef enum {
  SILC_PGP_HASH_MD5               = 1,	 /* MD5 */
  SILC_PGP_HASH_SHA1              = 2,	 /* SHA-1 */
  SILC_PGP_HASH_RIPEMD160         = 3,	 /* RIPE-MD160 */
  SILC_PGP_HASH_SHA256            = 8,	 /* SHA-256 */
  SILC_PGP_HASH_SHA384            = 9,	 /* SHA-394 */
  SILC_PGP_HASH_SHA512            = 10,	 /* SHA-512 */
  SILC_PGP_HASH_SHA224            = 11,	 /* SHA-224 */
} SilcPGPHash;
/***/

/****d* silcpgp/SilcPGPS2KType
 *
 * NAME
 *
 *    typedef enum { ... } SilcPGPS2KType;
 *
 * DESCRIPTION
 *
 *    String-to-key (S2K) specifier types.  These define how the passphrase
 *    is converted into encryption and decryption key.
 *
 * SOURCE
 */
typedef enum {
  SILC_PGP_S2K_SIMPLE		  = 0,	 /* Simple S2K */
  SILC_PGP_S2K_SALTED             = 1,	 /* Salted S2K */
  SILC_PGP_S2K_ITERATED_SALTED    = 3,	 /* Iterated and salted S2K */
} SilcPGPS2KType;
/***/

/****d* silcpgp/SilcPGPKeyType
 *
 * NAME
 *
 *    typedef enum { ... } SilcPGPKeyType;
 *
 * DESCRIPTION
 *
 *    PGP key generation types.  These types define what kind of PGP key
 *    is created with silc_pgp_generate_key.
 *
 *    SILC_PGP_RSA
 *
 *      Generates RSA key that can be used for both signatures and encryption.
 *      This is default.  If key type is not specified, this is used as
 *      default key type.
 *
 *    SILC_PGP_DSA_SIG
 *
 *      Generates signature only DSA key.  The key cannot be used for
 *      encryption.
 *
 *    SILC_PGP_ECDSA_SIG
 *
 *      Generates signature only ECDSA key.  The key cannot be used for
 *      encryption.
 *
 *    SILC_PGP_DSA_SIG_ELGAMAL_ENC
 *
 *      Generates key with DSA for signatures and Elgamal for encryption.
 *
 *    SILC_PGP_DSA_SIG_RSA_ENC
 *
 *      Generates key with DSA for signatures and RSA for encryption.
 *
 * SOURCE
 */
typedef enum {
  SILC_PGP_RSA                     = 0,	 /* Generate RSA key */
  SILC_PGP_DSA_SIG                 = 1,	 /* Generate signature only DSA key */
  SILC_PGP_ECDSA_SIG               = 2,	 /* Generate signature only ECDSA key */
  SILC_PGP_DSA_SIG_ELGAMAL_ENC     = 3,	 /* Generate DSA and Elgamal key */
  SILC_PGP_DSA_SIG_RSA_ENC         = 4,	 /* Generate DSA and RSA key */
} SilcPGPKeyType;
/***/

typedef struct SilcPgpKeygenParamsStruct {
  SilcPGPKeyType type;
  int key_len_bits;

  int expire_days;
  int expire_weeks;
  int expire_months;
  int expire_years;
} SilcPgpKeygenParams;

/* XXX TODO */
SilcBool silc_pgp_generate_key(SilcPgpKeygenParams *params,
			       const char *user_id,
			       SilcRng rng,
			       SilcPublicKey *ret_public_key,
			       SilcPrivateKey *ret_private_key);

/****f* silcpgp/silc_pgp_packet_decode
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pgp_packet_decode(const unsigned char *data,
 *                                    SilcUInt32 data_len,
 *                                    SilcBool *success,
 *                                    SilcList *ret_list);
 *
 * DESCRIPTION
 *
 *    Decodes PGP packets from the data buffer indicated by `data' of length
 *    of `data_len' bytes.  The data buffer may include one or more packets
 *    that are decoded and returned to the `ret_list'.  The caller must free
 *    the returned packets with silc_pgp_packet_free_list.  Each entry in
 *    the `ret_list' is SilcPGPPacket.
 *
 *    Returns the number of packets decoded or 0 on error.  If the `success'
 *    is FALSE but this returns > 0 then not all packets were decoded
 *    successfully and the `ret_list' includes the packets that were decoded.
 *    When the `success' is TRUE all packets were decoded successfully.
 *
 * EXAMPLE
 *
 *    SilcList list;
 *    SilcBool success;
 *    unsigned char *data;
 *    SilcUInt32 data_len;
 *    SilcPGPPublicKey public_key;
 *
 *    // Open public key file (binary format) and parse all PGP packets
 *    data = silc_file_readfile("pubkey.bin", &data_len, NULL);
 *    silc_pgp_packet_decode(data, data_len, &success, &list);
 *
 *    // Parse public key
 *    silc_pgp_public_key_decode(&list, &public_key);
 *
 ***/
int silc_pgp_packet_decode(const unsigned char *data,
			   SilcUInt32 data_len,
			   SilcBool *success,
			   SilcList *ret_list);

/****f* silcpgp/silc_pgp_packet_get_tag
 *
 * SYNOPSIS
 *
 *    SilcPGPPacketTag silc_pgp_packet_get_tag(SilcPGPPacket packet);
 *
 * DESCRIPTION
 *
 *    Returns the OpenPGP packet tag (packet type) from `packet'.
 *
 ***/
SilcPGPPacketTag silc_pgp_packet_get_tag(SilcPGPPacket packet);

/****f* silcpgp/silc_pgp_packet_get_data
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_pgp_packet_get_data(SilcPGPPacket packet,
 *                                            SilcUInt32 *data_len);
 *
 * DESCRIPTION
 *
 *    Returns the packet data from the `packet'.  The returned pointer
 *    must not be freed by the caller.  The length of the data is returned
 *    into `data_len' pointer.
 *
 ***/
unsigned char *silc_pgp_packet_get_data(SilcPGPPacket packet,
					SilcUInt32 *data_len);

/****f* silcpgp/silc_pgp_packet_free
 *
 * SYNOPSIS
 *
 *    void silc_pgp_packet_free(SilcPGPPacket packet);
 *
 * DESCRIPTION
 *
 *    Free PGP packet.
 *
 ***/
void silc_pgp_packet_free(SilcPGPPacket packet);

/****f* silcpgp/silc_pgp_packet_free_list
 *
 * SYNOPSIS
 *
 *    void silc_pgp_packet_free_list(SilcList *list);
 *
 * DESCRIPTION
 *
 *    Free all PGP packets from the `list'.  All packets in the list will
 *    become invalid after this call.
 *
 ***/
void silc_pgp_packet_free_list(SilcList *list);

/****f* silcpgp/silc_pgp_public_key_decode
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pgp_public_key_decode(SilcList *list,
 *                                        SilcPGPPublicKey *ret_public_key);
 *
 * DESCRIPTION
 *
 *    Decodes OpenPGP public key (certificate) from decoded PGP packets list
 *    indicated by `list'.  The decoded public key is returned into the
 *    `ret_public_key' which the caller must free by calling the
 *    silc_pgp_public_key_free function.  Returns FALSE on error.
 *
 *    The `list' can be allocated by calling silc_pgp_packet_decode.
 *    If the `list' contains more that one public keys this only decodes
 *    the first one.  The public key `list' is advanced while decoding the
 *    public key.  If another public key follows the first public key, this
 *    function may be called again to decode that public key as well.
 *
 ***/
SilcBool silc_pgp_public_key_decode(SilcList *pubkey,
				    SilcPGPPublicKey *ret_public_key);

/****f* silcpgp/silc_pgp_public_key_free
 *
 * SYNOPSIS
 *
 *    void silc_pgp_public_key_free(SilcPGPPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Frees the public key.
 *
 ***/
void silc_pgp_public_key_free(SilcPGPPublicKey public_key);

/****f* silcpgp/silc_pgp_private_key_decode
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pgp_private_key_decode(SilcList *list,
 *                                         const char *passphrase,
 *                                         SilcUInt32 passphrase_len,
 *                                         SilcPGPPrivateKey *ret_private_key);
 *
 * DESCRIPTION
 *
 *    Decodes OpenPGP secret key (private key) from decoded PGP packets list
 *    indicated by `list'.  The decoded private key is returned into the
 *    `ret_private_key' which the caller must free by calling the
 *    silc_pgp_private_key_free function.  Returns FALSE on error.
 *
 *    The `passphrase' can be provided in case the private key is
 *    encrypted.  Usually all OpenPGP private keys are encrypted so the
 *    passphrase should be always provided.
 *
 *    The `list' can be allocated by calling silc_pgp_packet_decode.
 *    If the `list' contains more that one private keys this only decodes
 *    the first one.  The private key `list' is advanced while decoding the
 *    public key.  If another private key follows the first public key, this
 *    function may be called again to decode that private key as well.
 *
 ***/
SilcBool silc_pgp_private_key_decode(SilcList *list,
				     const char *passphrase,
				     SilcUInt32 passphrase_len,
				     SilcPGPPrivateKey *ret_private_key);

/****f* silcpgp/silc_pgp_private_key_free
 *
 * SYNOPSIS
 *
 *    void silc_pgp_private_key_free(SilcPGPPrivateKey private_key);
 *
 * DESCRIPTION
 *
 *    Frees the private key.
 *
 ***/
void silc_pgp_private_key_free(SilcPGPPrivateKey private_key);

/****f* silcpgp/silc_pgp_s2k
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_pgp_s2k(SilcPGPS2KType type,
 *                                SilcPGPHash hash,
 *                                const char *passphrase,
 *                                SilcUInt32 passphrase_len,
 *                                SilcUInt32 key_len,
 *                                unsigned char *salt,
 *                                SilcUInt32 iter_octet_count,
 *                                SilcRng rng);
 *
 * DESCRIPTION
 *
 *   Computes the OpenPGP string-to-key (S2K).  Converts passphrases to
 *   encryption and decryption keys.  The `passphrase' must be non-NULL.
 *
 *   The `type' specifies the S2K specifier type.  The `hash' is the
 *   hash algorithm used if the `type' is SILC_PGP_S2K_SALTED or
 *   SILC_PGP_S2K_ITERATED_SALTED.  If the `type' is
 *   SILC_PGP_S2K_ITERATED_SALTED the `iter_octet_count' is the number of
 *   bytes to iteratively hash (max value is 65536).
 *
 *   The `key_len' is the length of the key to produce in bytes.  If `salt'
 *   is NULL this will generate an encryption key.  If it is non-NULL this
 *   will use the salt to compute the decryption key.
 *
 ***/
unsigned char *silc_pgp_s2k(SilcPGPS2KType type,
			    SilcPGPHash hash,
			    const char *passphrase,
			    SilcUInt32 passphrase_len,
			    SilcUInt32 key_len,
			    unsigned char *salt,
			    SilcUInt32 iter_count,
			    SilcRng rng);

unsigned char *silc_pgp_dearmor(unsigned char *data,
				SilcUInt32 data_len,
				SilcUInt32 *ret_len);

#include "silcpgp_i.h"

#endif /* SILCPGP_H */

/*

  silcpgp_pubkey.c

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
#include "rsa.h"
#include "dsa.h"

/************************ Static utility functions **************************/

/* Computes fingerprint of the OpenPGP public key and saves it to the key.
   Saves also the key IDs to public key context. */

static SilcBool silc_pgp_compute_fingerprint(SilcBuffer keybuf,
					     SilcPGPPublicKey pubkey)
{
  SILC_LOG_DEBUG(("Computing fingerprint"));

  if (pubkey->version >= 4) {
    /* Version 4 */
    SilcHash sha1;
    unsigned char tmp[3];

    if (!silc_hash_alloc("sha1", &sha1))
      return FALSE;

    tmp[0] = 0x99;
    SILC_PUT16_MSB(silc_buffer_len(keybuf), tmp + 1);

    silc_hash_init(sha1);
    silc_hash_update(sha1, tmp, 3);
    silc_hash_update(sha1, silc_buffer_data(keybuf), silc_buffer_len(keybuf));
    silc_hash_final(sha1, pubkey->fingerprint);
    silc_hash_free(sha1);

    /* Save key ID */
    memcpy(pubkey->key_id, pubkey->fingerprint + 12, 8);
  } else {
    /* Versions 2 and 3 */
    SilcHash md5;
    unsigned char *n, *e;
    SilcUInt16 n_len, e_len;

    if (!silc_hash_alloc("md5", &md5))
      return FALSE;

    silc_buffer_format(keybuf,
		       SILC_STR_OFFSET(8),
		       SILC_STR_UI16_NSTRING(&n, &n_len),
		       SILC_STR_UI16_NSTRING(&e, &e_len),
		       SILC_STR_END);

    n_len = (n_len + 7) / 8;
    e_len = (e_len + 7) / 8;

    silc_hash_init(md5);
    silc_hash_update(md5, n, n_len);
    silc_hash_update(md5, e, e_len);
    silc_hash_final(md5, pubkey->fingerprint);
    silc_hash_free(md5);

    /* Save key ID */
    memcpy(pubkey->key_id, n + (n_len - 8), 8);
  }

  return TRUE;
}

/*************************** Public Key Routines ****************************/

/* Decode OpenPGP Public Key packet */

int silc_pgp_packet_public_key_decode(unsigned char *key, SilcUInt32 key_len,
				      SilcPGPPublicKey pubkey)
{
  SilcBufferStruct keybuf, fbuf;
  const SilcPKCSAlgorithm *pkcs;
  int ret;

  SILC_LOG_DEBUG(("Parse OpenPGP public key packet"));

  if (!key || !key_len)
    return 0;
  silc_buffer_set(&keybuf, key, key_len);

  SILC_LOG_HEXDUMP(("OpenPGP public key"), key, key_len);

  /* Decode the key */
  if (silc_buffer_unformat(&keybuf,
			   SILC_STR_ADVANCE,
			   SILC_STR_UINT8(&pubkey->version),
			   SILC_STR_UI_INT(&pubkey->created),
			   SILC_STR_END) < 0) {
    SILC_LOG_DEBUG(("Malformed public key"));
    goto err;
  }

  if (pubkey->version < 2) {
    SILC_LOG_DEBUG(("Invalid version %d", pubkey->version));
    goto err;
  }

  SILC_LOG_DEBUG(("Public key version %d", pubkey->version));

  if (pubkey->version <= 3) {
    /* Versions 2 and 3 */
    if (silc_buffer_unformat(&keybuf,
			     SILC_STR_ADVANCE,
			     SILC_STR_UINT16(&pubkey->valid),
			     SILC_STR_UINT8(&pubkey->algorithm),
			     SILC_STR_END) < 0) {
      SILC_LOG_DEBUG(("Malformed public key"));
      goto err;
    }
  } else {
    /* Version 4 */
    if (silc_buffer_unformat(&keybuf,
			     SILC_STR_ADVANCE,
			     SILC_STR_UINT8(&pubkey->algorithm),
			     SILC_STR_END) < 0) {
      SILC_LOG_DEBUG(("Malformed public key"));
      goto err;
    }
  }

  SILC_LOG_DEBUG(("Parse algorithm %d", pubkey->algorithm));

  /* Decode the public key algorithm */
  switch (pubkey->algorithm) {
  case SILC_PGP_PKCS_RSA:
  case SILC_PGP_PKCS_RSA_ENC_ONLY:
  case SILC_PGP_PKCS_RSA_SIG_ONLY:
    /* Get PKCS object */
    pkcs = silc_pkcs_find_algorithm("rsa", "openpgp");
    if (!pkcs) {
      SILC_LOG_ERROR(("Unsupported PKCS algorithm (rsa/openpgp)"));
      goto err;
    }
    break;

  case SILC_PGP_PKCS_DSA:
    /* Get PKCS object */
    pkcs = silc_pkcs_find_algorithm("dsa", "openpgp");
    if (!pkcs) {
      SILC_LOG_ERROR(("Unsupported PKCS algorithm (dsa/openpgp)"));
      goto err;
    }
    break;

  case SILC_PGP_PKCS_ELGAMAL_ENC_ONLY:
  case SILC_PGP_PKCS_ELGAMAL:
    /* Get PKCS object */
    pkcs = silc_pkcs_find_algorithm("elgamal", "openpgp");
    if (!pkcs) {
      SILC_LOG_ERROR(("Unsupported PKCS algorithm (elgamal/openpgp)"));
      goto err;
    }
    break;

  default:
    SILC_LOG_DEBUG(("Unsupported OpenPGP public key algorithm %d",
		    pubkey->algorithm));
    goto err;
  }
  pubkey->pkcs = pkcs;

  /* Import the algorithm public key */
  ret = pkcs->import_public_key(pkcs, silc_buffer_data(&keybuf),
				silc_buffer_len(&keybuf),
				&pubkey->public_key);
  if (!ret) {
    SILC_LOG_DEBUG(("Malformed public key"));
    goto err;
  }

  /* Compute and save fingerprint */
  silc_buffer_set(&fbuf, key, silc_buffer_headlen(&keybuf) + ret);
  if (!silc_pgp_compute_fingerprint(&fbuf, pubkey))
    goto err;

  return silc_buffer_headlen(&keybuf) + ret;

 err:
  return 0;
}

/* Decode public key from PGP packets */

SilcBool silc_pgp_public_key_decode(SilcList *list,
				    SilcPGPPublicKey *ret_public_key)
{
  SilcPGPPublicKey pubkey, subkey;
  unsigned char *data;
  SilcUInt32 data_len;
  SilcPGPPacket pub, packet;

  SILC_LOG_DEBUG(("Parse OpenPGP public key"));

  pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    goto err;

  /* First packet must be public key packet */
  pub = silc_list_get(*list);
  if (!pub)
    goto err;
  if (silc_pgp_packet_get_tag(pub) != SILC_PGP_PACKET_PUBKEY &&
      silc_pgp_packet_get_tag(pub) != SILC_PGP_PACKET_PUBKEY_SUB)
    goto err;

  /* Parse the public key */
  data = silc_pgp_packet_get_data(pub, &data_len);
  if (!silc_pgp_packet_public_key_decode(data, data_len, pubkey))
    goto err;

  /* Parse any and all packets until we hit end of the packets or next
     public key in the list.  We simply copy the raw data, and actual
     parsing is done later if and when the packets are needed. */
  if (silc_pgp_packet_get_tag(pub) == SILC_PGP_PACKET_PUBKEY) {
    silc_list_init(pubkey->packets, struct SilcPGPPacketStruct, next);

    /* Copy the raw public key packet */
    packet = silc_pgp_packet_copy(pub);
    if (packet)
      silc_list_add(pubkey->packets, packet);

    while ((packet = silc_list_get(*list))) {
      SILC_LOG_DEBUG(("Adding %d (%s) packet to public key",
		      silc_pgp_packet_get_tag(packet),
		      silc_pgp_packet_name(silc_pgp_packet_get_tag(packet))));

      switch (silc_pgp_packet_get_tag(packet)) {

      case SILC_PGP_PACKET_PUBKEY:
	/* Next public key, stop decoding.  Set list pointer so that the list
	   points to the next public key. */
	list->current = packet;
	break;

      case SILC_PGP_PACKET_PUBKEY_SUB:
	/* Parse subkeys recursively */
	list->current = packet;
	if (!silc_pgp_public_key_decode(list, &subkey))
	  goto err;

	if (!pubkey->subkeys) {
	  pubkey->subkeys = silc_dlist_init();
	  if (!pubkey->subkeys)
	    goto err;
	}
	silc_dlist_add(pubkey->subkeys, subkey);

      default:
	/* Copy packet to the public key */
	packet = silc_pgp_packet_copy(packet);
	if (packet)
	  silc_list_add(pubkey->packets, packet);
	break;
      }
    }
  }

  if (ret_public_key)
    *ret_public_key = pubkey;

  return TRUE;

 err:
  silc_free(pubkey);
  return FALSE;
}

/* Free public key */

void silc_pgp_public_key_free(SilcPGPPublicKey public_key)
{
  SilcPGPPublicKey p;
  SilcPGPPacket packet;

  if (public_key->pkcs)
    public_key->pkcs->public_key_free(public_key->pkcs,
				      public_key->public_key);

  if (public_key->subkeys) {
    silc_dlist_start(public_key->subkeys);
    while ((p = silc_dlist_get(public_key->subkeys)))
      silc_pgp_public_key_free(p);
    silc_dlist_uninit(public_key->subkeys);
  }

  silc_list_start(public_key->packets);
  while ((packet = silc_list_get(public_key->packets)))
    silc_pgp_packet_free(packet);

  silc_free(public_key);
}

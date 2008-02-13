/*

  silcpgp_seckey.c

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

/*************************** Private Key Routines ***************************/

/* Decode OpenPGP Secret Key packet */

int silc_pgp_packet_private_key_decode(unsigned char *key, SilcUInt32 key_len,
				       const char *passphrase,
				       SilcUInt32 passphrase_len,
				       SilcPGPPrivateKey privkey)
{
  SilcBufferStruct keybuf;
  SilcPGPPublicKey pubkey = NULL;
  unsigned char *iv, *salt = NULL, *dec = NULL;
  unsigned char *dec_key;
  SilcUInt32 iv_len = 0;
  SilcUInt16 pcksum;
  SilcUInt8 s2k_usage, s2k_count;
  SilcCipher cipher = NULL;
  int ret, ret_len;

  SILC_LOG_DEBUG(("Parsing OpenPGP private key"));

  if (!key || !key_len)
    return 0;
  silc_buffer_set(&keybuf, key, key_len);

  SILC_LOG_HEXDUMP(("OpenPGP private key"), key, key_len);

  pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey) {
    silc_free(privkey);
    return 0;
  }

  /* Parse public key from the private key */
  ret = silc_pgp_packet_public_key_decode(key, key_len, pubkey);
  if (!ret) {
    SILC_LOG_DEBUG(("Malformed private key"));
    goto err;
  }
  if (!silc_buffer_pull(&keybuf, ret))
    goto err;

  if (silc_buffer_len(&keybuf) < 12)
    goto err;

  /* Decode algorithm info */
  s2k_usage = keybuf.data[0];
  silc_buffer_pull(&keybuf, 1);
  switch (s2k_usage) {
  case 0:
    /* Plaintext private key */
    SILC_LOG_DEBUG(("Private key is not encrypted"));
    break;

  case 254:
  case 255:
    /* Encrypted, string-to-key (S2K) specifier present */
    if (silc_buffer_unformat(&keybuf,
			     SILC_STR_ADVANCE,
			     SILC_STR_UINT8(&privkey->cipher),
			     SILC_STR_UINT8(&privkey->s2k_type),
			     SILC_STR_UINT8(&privkey->s2k_hash),
			     SILC_STR_END) < 0) {
      SILC_LOG_DEBUG(("Malformed S2K specifier in private key"));
      goto err;
    }

    SILC_LOG_DEBUG(("Private key S2K type %d", privkey->s2k_type));

    switch (privkey->s2k_type) {
    case SILC_PGP_S2K_SIMPLE:
      /* Simple S2K */
      iv_len = 0;
      break;

    case SILC_PGP_S2K_SALTED:
      /* Salted S2K */
      if (silc_buffer_unformat(&keybuf,
			       SILC_STR_ADVANCE,
			       SILC_STR_DATA(&salt, 8),
			       SILC_STR_END) < 0) {
	SILC_LOG_DEBUG(("Malformed S2K specifier in private key"));
	goto err;
      }
      break;

    case SILC_PGP_S2K_ITERATED_SALTED:
      /* Iterated and salted S2K */
      if (silc_buffer_unformat(&keybuf,
			       SILC_STR_ADVANCE,
			       SILC_STR_DATA(&salt, 8),
			       SILC_STR_UINT8(&s2k_count),
			       SILC_STR_END) < 0) {
	SILC_LOG_DEBUG(("Malformed S2K specifier in private key"));
	goto err;
      }

      /* Get the iterator octet count, formula comes from the RFC */
      privkey->s2k_count = ((SilcUInt32)16 +
			    (s2k_count & 15)) << ((s2k_count >> 4) + 6);
      break;

    default:
      SILC_LOG_DEBUG(("Malformed private key"));
      goto err;
    }

    break;

  default:
    /* Encrypted with given algorithm */
    privkey->cipher = keybuf.data[0];
    silc_buffer_pull(&keybuf, 1);
    break;
  }

  ret_len = silc_buffer_headlen(&keybuf);

  /* Decrypt */
  if (privkey->cipher) {
    cipher = silc_pgp_cipher_alloc(privkey->cipher);
    if (!cipher)
      goto err;

    iv_len = silc_cipher_get_iv_len(cipher);

    /* Get IV */
    if (!silc_buffer_unformat(&keybuf,
			      SILC_STR_ADVANCE,
			      SILC_STR_DATA(&iv, iv_len),
			      SILC_STR_END)) {
      SILC_LOG_DEBUG(("Malformed private key, IV not present"));
      goto err;
    }
    ret_len += iv_len;

    SILC_LOG_HEXDUMP(("IV, iv_len %d", iv_len), iv, iv_len);

    /* Generate decryption key from passphrase */
    dec_key = silc_pgp_s2k(privkey->s2k_type, privkey->s2k_hash, passphrase,
			   passphrase_len, silc_cipher_get_key_len(cipher) / 8,
			   salt, privkey->s2k_count, NULL);
    if (!dec_key)
      goto err;

    SILC_LOG_HEXDUMP(("S2K"), dec_key, silc_cipher_get_key_len(cipher) / 8);

    /* Set decryption key */
    silc_cipher_set_key(cipher, dec_key, silc_cipher_get_key_len(cipher),
			FALSE);
    silc_cipher_set_iv(cipher, iv);

    /* Decrypt the private key */
    SILC_LOG_DEBUG(("Decrypting private key"));
    dec = silc_memdup(silc_buffer_data(&keybuf), silc_buffer_len(&keybuf));
    if (!dec)
      goto err;
    silc_buffer_set(&keybuf, dec, silc_buffer_len(&keybuf));

    if (pubkey->version >= 4) {
      silc_cipher_decrypt(cipher, keybuf.data, keybuf.data,
			  silc_buffer_len(&keybuf), NULL);
    } else {
      /* Versions 2 and 3 */
      /* Support may be added for these at some point. */
      SILC_LOG_ERROR(("Version %d encrypted private keys not supported",
		      pubkey->version));
      goto err;
    }
  }

  /* Verify checksum to see if decryption succeeded */
  if (s2k_usage == 254) {
    SilcHash sha1;
    unsigned char cksum_hash[20], pcksum_hash[20];

    if (!silc_buffer_push_tail(&keybuf, 20)) {
      SILC_LOG_DEBUG(("Malformed private key, checksum not present"));
      goto err;
    }

    memcpy(pcksum_hash, keybuf.tail, 20);

    if (!silc_hash_alloc("sha1", &sha1))
      goto err;
    silc_hash_init(sha1);
    silc_hash_update(sha1, silc_buffer_data(&keybuf),
		     silc_buffer_len(&keybuf));
    silc_hash_final(sha1, cksum_hash);
    silc_hash_free(sha1);

    /* Verify */
    if (memcmp(cksum_hash, pcksum_hash, sizeof(cksum_hash))) {
      SILC_LOG_DEBUG(("Private key checksum invalid, decryption failed"));
      goto err;
    }

    ret_len += 20;
  } else {
    SilcUInt16 cksum = 0;
    int i;

    if (silc_buffer_unformat(&keybuf,
			     SILC_STR_ADVANCE,
			     SILC_STR_UINT16(&pcksum),
			     SILC_STR_END) < 0) {
      SILC_LOG_DEBUG(("Malformed private key, checksum not present"));
      goto err;
    }

    for (i = 0; i < silc_buffer_len(&keybuf); i++)
      cksum = (cksum + keybuf.data[i]) % 0x10000;

    /* Verify */
    if (cksum != pcksum) {
      SILC_LOG_DEBUG(("Private key checksum invalid, decryption failed"));
      goto err;
    }

    ret_len += 2;
  }

  /* Import the algorithm private key */
  ret = pubkey->pkcs->import_private_key(pubkey->pkcs,
					 silc_buffer_data(&keybuf),
					 silc_buffer_len(&keybuf),
					 &privkey->private_key);
  if (!ret) {
    SILC_LOG_DEBUG(("Malformed private key"));
    goto err;
  }

  silc_free(dec);

  privkey->public_key = pubkey;

  return ret_len + ret;

 err:
  if (pubkey)
    silc_pgp_public_key_free(pubkey);
  silc_free(dec);
  return 0;
}

/* Decode private key from PGP packets */

SilcBool silc_pgp_private_key_decode(SilcList *list,
				     const char *passphrase,
				     SilcUInt32 passphrase_len,
				     SilcPGPPrivateKey *ret_private_key)
{
  SilcPGPPrivateKey privkey, subkey;
  unsigned char *data;
  SilcUInt32 data_len;
  SilcPGPPacket prv, packet;

  SILC_LOG_DEBUG(("Parse OpenPGP private key"));

  privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey)
    goto err;

  /* First packet must be private key packet */
  prv = silc_list_get(*list);
  if (!prv)
    goto err;
  if (silc_pgp_packet_get_tag(prv) != SILC_PGP_PACKET_SECKEY &&
      silc_pgp_packet_get_tag(prv) != SILC_PGP_PACKET_SECKEY_SUB)
    goto err;

  /* Parse the private key */
  data = silc_pgp_packet_get_data(prv, &data_len);
  if (!silc_pgp_packet_private_key_decode(data, data_len, passphrase,
					  passphrase_len, privkey))
    goto err;

  /* Parse any and all packets until we hit end of the packets or next
     private key in the list.  We simply copy the raw data, and actual
     parsing is done later if and when the packets are needed. */
  if (silc_pgp_packet_get_tag(prv) == SILC_PGP_PACKET_SECKEY) {
    silc_list_init(privkey->packets, struct SilcPGPPacketStruct, next);

    /* Copy the raw private key packet */
    packet = silc_pgp_packet_copy(prv);
    if (packet)
      silc_list_add(privkey->packets, packet);

    while ((packet = silc_list_get(*list))) {
      SILC_LOG_DEBUG(("Adding %d (%s) packet to private key",
		      silc_pgp_packet_get_tag(packet),
		      silc_pgp_packet_name(silc_pgp_packet_get_tag(packet))));

      switch (silc_pgp_packet_get_tag(packet)) {

      case SILC_PGP_PACKET_SECKEY:
	/* Next private key, stop decoding.  Set list pointer so that the list
	   points to the next private key. */
	list->current = packet;
	break;

      case SILC_PGP_PACKET_SECKEY_SUB:
	/* Parse subkeys recursively */
	list->current = packet;
	if (!silc_pgp_private_key_decode(list, passphrase,
					 passphrase_len, &subkey))
	  goto err;

	if (!privkey->subkeys) {
	  privkey->subkeys = silc_dlist_init();
	  if (!privkey->subkeys)
	    goto err;
	}
	silc_dlist_add(privkey->subkeys, subkey);

      default:
	/* Copy packet to the private key */
	packet = silc_pgp_packet_copy(packet);
	if (packet)
	  silc_list_add(privkey->packets, packet);
	break;
      }
    }
  }

  if (ret_private_key)
    *ret_private_key = privkey;

  return TRUE;

 err:
  silc_free(privkey);
  return FALSE;
}

/* Free private key */

void silc_pgp_private_key_free(SilcPGPPrivateKey private_key)
{
  SilcPGPPrivateKey p;
  SilcPGPPacket packet;

  if (private_key->public_key && private_key->public_key->pkcs)
    private_key->public_key->pkcs->private_key_free(private_key->
						    public_key->pkcs,
						    private_key->private_key);

  silc_pgp_public_key_free(private_key->public_key);

  if (private_key->subkeys) {
    silc_dlist_start(private_key->subkeys);
    while ((p = silc_dlist_get(private_key->subkeys)))
      silc_pgp_private_key_free(p);
    silc_dlist_uninit(private_key->subkeys);
  }

  silc_list_start(private_key->packets);
  while ((packet = silc_list_get(private_key->packets)))
    silc_pgp_packet_free(packet);

  silc_free(private_key);
}

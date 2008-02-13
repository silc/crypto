/*

  silcpgp.c

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

/************************* Static utility functions *************************/

/* Parse PGP packet */

static int
silc_pgp_packet_parse(const unsigned char *data, SilcUInt32 data_len,
		      SilcPGPPacket *ret_packet)
{
  SilcPGPPacket packet;
  SilcBufferStruct buf;
  SilcUInt8 tag;
  SilcBool partial = FALSE;
  SilcUInt32 len;

  SILC_LOG_DEBUG(("Parsing OpenPGP packet"));

  if (!data || data_len < 2)
    return 0;
  silc_buffer_set(&buf, (unsigned char *)data, data_len);

  packet = silc_calloc(1, sizeof(*packet));
  if (!packet)
    return 0;

  while (silc_buffer_len(&buf) > 0) {
    tag = buf.data[0];
    silc_buffer_pull(&buf, 1);

    if (!(tag & 0x80)) {
      SILC_LOG_DEBUG(("Invalid tag"));
      goto err;
    }

    if (tag & 0x40) {
      /* New format */

      /* Packet type */
      if (!packet->tag) {
	packet->tag = tag & 0x3f;
	SILC_LOG_DEBUG(("Packet type %d (%s)", packet->tag,
			silc_pgp_packet_name(packet->tag)));
      }

      /* Packet length */
      len = buf.data[0];
      if (len >= 192 && len <= 223) {
	/* 2 byte length */
	if (silc_buffer_len(&buf) < 2)
	  goto err;
	len = ((len - 192) << 8) + buf.data[1] + 192;
	silc_buffer_pull(&buf, 2);
      } else if (len == 255) {
	/* 5 byte length */
	if (silc_buffer_len(&buf) < 5)
	  goto err;
	silc_buffer_pull(&buf, 1);
	SILC_GET32_MSB(len, buf.data);
	silc_buffer_pull(&buf, 4);
      } else if (len >= 224 && len < 255) {
	/* Partial length */
	if (silc_buffer_len(&buf) < 1)
	  goto err;
	len = 1 << (len & 0x1f);
	silc_buffer_pull(&buf, 1);
	partial = TRUE;
      }
    } else {
      /* Old format */
      SilcUInt8 llen;

      /* Pakcet type */
      if (!packet->tag) {
	packet->tag = (tag >> 2) & 0x0f;
	SILC_LOG_DEBUG(("Packet type %d (%s)", packet->tag,
			silc_pgp_packet_name(packet->tag)));
      }

      if ((tag & 0x03) == 3) {
	/* Indeterminate length, use whole buffer */
	len = silc_buffer_len(&buf);
      } else {
	for (llen = 1 << (tag & 0x03), len = 0 ; llen; llen--) {
	  len <<= 8;
	  len |= buf.data[0];
	  if (!silc_buffer_pull(&buf, 1))
	    goto err;
	}
      }
    }

    if (silc_buffer_len(&buf) < len) {
      SILC_LOG_DEBUG(("Too short packet (%d < %d)",
		      silc_buffer_len(&buf), len));
      goto err;
    }

    /* Get data */
    if (silc_buffer_format(&packet->data,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(silc_buffer_data(&buf), len),
			   SILC_STR_END) < 0)
      goto err;

    silc_buffer_pull(&buf, len);

    if (!partial)
      break;
  }

  silc_buffer_start(&packet->data);

  SILC_LOG_HEXDUMP(("Packet, len %d", silc_buffer_len(&packet->data)),
		    silc_buffer_data(&packet->data),
		    silc_buffer_len(&packet->data));

  *ret_packet = packet;

  return silc_buffer_headlen(&buf);

 err:
  silc_buffer_purge(&packet->data);
  silc_free(packet);
  return 0;
}

/****************************** PGP Algorithms ******************************/

/* Allocates cipher */

SilcCipher silc_pgp_cipher_alloc(SilcPGPCipher cipher)
{
  SilcCipher c;

  SILC_LOG_DEBUG(("Allocate cipher %d", cipher));

  switch (cipher) {
  case SILC_PGP_CIPHER_IDEA:
    if (!silc_cipher_alloc("idea-128-cfb", &c)) {
      SILC_LOG_ERROR(("Unsupported algorithm idea-128-cfb"));
      return NULL;
    }
    break;

  case SILC_PGP_CIPHER_3DES:
    if (!silc_cipher_alloc("3des-168-cfb", &c)) {
      SILC_LOG_ERROR(("Unsupported algorithm 3des-168-cfb"));
      return NULL;
    }
    break;

  case SILC_PGP_CIPHER_CAST5:
    if (!silc_cipher_alloc("cast5-128-cfb", &c)) {
      SILC_LOG_ERROR(("Unsupported algorithm cast5-168-cfb"));
      return NULL;
    }
    break;

  case SILC_PGP_CIPHER_BLOWFISH:
    if (!silc_cipher_alloc("blowfish-128-cfb", &c)) {
      SILC_LOG_ERROR(("Unsupported algorithm blowfish-128-cfb"));
      return NULL;
    }
    break;

  case SILC_PGP_CIPHER_AES128:
    if (!silc_cipher_alloc("aes-128-cfb", &c)) {
      SILC_LOG_ERROR(("Unsupported algorithm aes-128-cfb"));
      return NULL;
    }
    break;

  case SILC_PGP_CIPHER_AES192:
    if (!silc_cipher_alloc("aes-192-cfb", &c)) {
      SILC_LOG_ERROR(("Unsupported algorithm aes-192-cfb"));
      return NULL;
    }
    break;

  case SILC_PGP_CIPHER_AES256:
    if (!silc_cipher_alloc("aes-256-cfb", &c)) {
      SILC_LOG_ERROR(("Unsupported algorithm aes-256-cfb"));
      return NULL;
    }
    break;

  case SILC_PGP_CIPHER_TWOFISH:
    if (!silc_cipher_alloc("twofish-256-cfb", &c)) {
      SILC_LOG_ERROR(("Unsupported algorithm twofish-256-cfb"));
      return NULL;
    }
    break;

  default:
    return NULL;
    break;
  }

  return c;
}

/* Allocates hash function */

SilcHash silc_pgp_hash_alloc(SilcPGPHash hash)
{
  SilcHash h;

  SILC_LOG_DEBUG(("Allocate hash %d", hash));

  switch (hash) {
  case SILC_PGP_HASH_MD5:
    if (!silc_hash_alloc("md5", &h)) {
      SILC_LOG_ERROR(("Unsupported algorithm md5"));
      return NULL;
    }
    break;

  case SILC_PGP_HASH_SHA1:
    if (!silc_hash_alloc("sha1", &h)) {
      SILC_LOG_ERROR(("Unsupported algorithm sha1"));
      return NULL;
    }
    break;

  case SILC_PGP_HASH_RIPEMD160:
    if (!silc_hash_alloc("ripemd160", &h)) {
      SILC_LOG_ERROR(("Unsupported algorithm ripemd160"));
      return NULL;
    }
    break;

  case SILC_PGP_HASH_SHA256:
    if (!silc_hash_alloc("sha256", &h)) {
      SILC_LOG_ERROR(("Unsupported algorithm sha256"));
      return NULL;
    }
    break;

  case SILC_PGP_HASH_SHA384:
    if (!silc_hash_alloc("sha384", &h)) {
      SILC_LOG_ERROR(("Unsupported algorithm sha384"));
      return NULL;
    }
    break;

  case SILC_PGP_HASH_SHA512:
    if (!silc_hash_alloc("sha512", &h)) {
      SILC_LOG_ERROR(("Unsupported algorithm sha512"));
      return NULL;
    }
    break;

  case SILC_PGP_HASH_SHA224:
    if (!silc_hash_alloc("sha244", &h)) {
      SILC_LOG_ERROR(("Unsupported algorithm sha224"));
      return NULL;
    }
    break;

  default:
    return NULL;
    break;
  }

  return h;
}

/************************* OpenPGP Packet routines **************************/

#ifdef SILC_DEBUG
/* Return packet tag as string */

const char *silc_pgp_packet_name(SilcPGPPacketTag tag)
{
  if (tag == SILC_PGP_PACKET_PKENC_SK)
    return "PKENC_SK";
  if (tag == SILC_PGP_PACKET_SIGNATURE)
    return "SIGNATURE";
  if (tag == SILC_PGP_PACKET_SENC_SK)
    return "SENC_SK";
  if (tag == SILC_PGP_PACKET_OP_SIGNATURE)
    return "OP_SIGNATUER";
  if (tag == SILC_PGP_PACKET_SECKEY)
    return "SECKEY";
  if (tag == SILC_PGP_PACKET_PUBKEY)
    return "PUBKEY";
  if (tag == SILC_PGP_PACKET_SECKEY_SUB)
    return "SECKEY_SUB";
  if (tag == SILC_PGP_PACKET_COMP_DATA)
    return "COMP_DATA";
  if (tag == SILC_PGP_PACKET_SENC_DATA)
    return "SENC_DATA";
  if (tag == SILC_PGP_PACKET_MARKER)
    return "MARKER";
  if (tag == SILC_PGP_PACKET_LITERAL_DATA)
    return "LITERAL_DATA";
  if (tag == SILC_PGP_PACKET_TRUST)
    return "TRUST";
  if (tag == SILC_PGP_PACKET_USER_ID)
    return "USER_ID";
  if (tag == SILC_PGP_PACKET_PUBKEY_SUB)
    return "PUBKEY_SUB";
  if (tag == SILC_PGP_PACKET_USER_ATTR)
    return "USER_ATTR";
  if (tag == SILC_PGP_PACKET_SENC_I_DATA)
    return "SENC_I_DATA";
  if (tag == SILC_PGP_PACKET_MDC)
    return "MDC";
  return "UNKNOWN";
}
#endif /* SILC_DEBUG */

/* Copy packet */

SilcPGPPacket silc_pgp_packet_copy(SilcPGPPacket packet)
{
  SilcPGPPacket newpacket;
  unsigned char *data;

  newpacket = silc_calloc(1, sizeof(*newpacket));
  if (!newpacket)
    return NULL;

  data = silc_memdup(packet->data.head, silc_buffer_truelen(&packet->data));
  if (!data) {
    silc_free(newpacket);
    return NULL;
  }

  silc_buffer_set(&newpacket->data, data, silc_buffer_truelen(&packet->data));
  newpacket->tag = packet->tag;

  return newpacket;
}

/* Decode all PGP packets into a list */

int silc_pgp_packet_decode(const unsigned char *data,
			   SilcUInt32 data_len,
			   SilcBool *success,
			   SilcList *ret_list)
{
  SilcBufferStruct buf;
  SilcPGPPacket packet;
  int ret;

  SILC_LOG_DEBUG(("Parsing OpenPGP packets"));

  if (success)
    *success = TRUE;

  if (!data || data_len < 2)
    return 0;

  silc_buffer_set(&buf, (unsigned char *)data, data_len);
  silc_list_init(*ret_list, struct SilcPGPPacketStruct, next);

  /* Parse one by one */
  while (silc_buffer_len(&buf) > 0) {
    ret = silc_pgp_packet_parse(silc_buffer_data(&buf),
				silc_buffer_len(&buf), &packet);
    if (!ret) {
      if (success)
	*success = FALSE;
      break;
    }

    silc_buffer_pull(&buf, ret);
    silc_list_add(*ret_list, packet);
  }

  SILC_LOG_DEBUG(("Parsed %d packets", silc_list_count(*ret_list)));

  silc_list_start(*ret_list);

  return silc_list_count(*ret_list);
}

/* Get PGP packet tag (packet type) */

SilcPGPPacketTag silc_pgp_packet_get_tag(SilcPGPPacket packet)
{
  return packet->tag;
}

/* Get PGP packet data */

unsigned char *silc_pgp_packet_get_data(SilcPGPPacket packet,
					SilcUInt32 *data_len)
{
  unsigned char *ptr = silc_buffer_data(&packet->data);
  if (data_len)
    *data_len = silc_buffer_len(&packet->data);
  return ptr;
}

/* Free PGP packet from  */

void silc_pgp_packet_free(SilcPGPPacket packet)
{
  silc_buffer_purge(&packet->data);
  silc_free(packet);
}

/* Free PGP packets from list */

void silc_pgp_packet_free_list(SilcList *list)
{
  SilcPGPPacket packet;

  silc_list_start(*list);
  while ((packet = silc_list_get(*list))) {
    silc_buffer_purge(&packet->data);
    silc_free(packet);
  }
}

/****************************** String to Key *******************************/

/* PGP String-to-key.  Converts passphrases to encryption and decryption
   keys.  This can be used to create both encryption and decryption key. */

unsigned char *silc_pgp_s2k(SilcPGPS2KType type,
			    SilcPGPHash hash,
			    const char *passphrase,
			    SilcUInt32 passphrase_len,
			    SilcUInt32 key_len,
			    unsigned char *salt,
			    SilcUInt32 iter_octet_count,
			    SilcRng rng)
{
  SilcHash h = NULL;
  unsigned char *key = NULL, digest[SILC_HASH_MAXLEN], preload[8], esalt[8];
  SilcUInt32 hash_len;
  int i, k;

  if (!passphrase)
    return NULL;

  SILC_LOG_DEBUG(("Compute S2K for %s", salt ? "decryption" : "encryption"));

  h = silc_pgp_hash_alloc(hash);
  if (!h)
    return NULL;
  hash_len = silc_hash_len(h);

  key = silc_malloc(key_len);
  if (!key)
    goto err;

  memset(preload, 0, sizeof(preload));
  silc_hash_init(h);

  /* If salt is NULL, we'll create one for encryption */
  if (!salt) {
    silc_rng_get_rn_data(rng, 8, esalt, sizeof(esalt));
    salt = esalt;
  }

  switch (type) {
  case SILC_PGP_S2K_SIMPLE:
    /* Hash passphrase */
    for (i = 0; i < key_len; i += hash_len) {
      if (i && i < sizeof(preload)) {
	silc_hash_init(h);
	silc_hash_update(h, preload, i);
      }

      silc_hash_update(h, passphrase, passphrase_len);
      silc_hash_final(h, digest);
      memcpy(key + i, digest,
	     (key_len - i) > hash_len ? hash_len : key_len - i);
    }
    break;

  case SILC_PGP_S2K_SALTED:
    /* Hash passphrase with salt */
    for (i = 0; i < key_len; i += hash_len) {
      if (i && i < sizeof(preload)) {
	silc_hash_init(h);
	silc_hash_update(h, preload, i);
      }

      silc_hash_update(h, salt, 8);
      silc_hash_update(h, passphrase, passphrase_len);
      silc_hash_final(h, digest);
      memcpy(key + i, digest,
	     (key_len - i) > hash_len ? hash_len : key_len - i);
    }
    break;

  case SILC_PGP_S2K_ITERATED_SALTED:
    /* Hash passphrase with salt iteratively.  This is very poorly defined
       in the RFC. */
    if (iter_octet_count < 8 + passphrase_len)
      iter_octet_count = 8 + passphrase_len;

    for (i = 0; i < key_len; i += hash_len) {
      if (i && i < sizeof(preload)) {
	silc_hash_init(h);
	silc_hash_update(h, preload, i);
      }

      for (k = 0; k < iter_octet_count; k += (8 + passphrase_len)) {
	if (iter_octet_count - k < 8) {
	  silc_hash_update(h, salt, iter_octet_count - k);
	} else {
	  silc_hash_update(h, salt, 8);
	  if (iter_octet_count - k - 8 < passphrase_len)
	    silc_hash_update(h, passphrase, iter_octet_count - k - 8);
	  else
	    silc_hash_update(h, passphrase, passphrase_len);
	}
      }

      silc_hash_final(h, digest);
      memcpy(key + i, digest,
	     (key_len - i) > hash_len ? hash_len : key_len - i);
    }
    break;

  default:
    goto err;
    break;
  }

  memset(digest, 0, sizeof(digest));
  memset(esalt, 0, sizeof(esalt));
  silc_hash_free(h);

  return key;

 err:
  silc_hash_free(h);
  silc_free(key);
  return NULL;
}

/****************************** ASCII armoring ******************************/

/* Adds ASCII armor */

unsigned char *silc_pgp_armor(unsigned char *data,
			      SilcUInt32 data_len)
{
  /* XXX TODO */
  return NULL;
}

/* Removes ASCII armoring */

unsigned char *silc_pgp_dearmor(unsigned char *data,
				SilcUInt32 data_len,
				SilcUInt32 *ret_len)
{
  int i, k;

  if (data_len < 28)
    return NULL;

  if (memcmp(data, "-----BEGIN PGP ", 15))
    return NULL;

  /* Get beginning of base64 encoded data */
  for (i = 0; i < data_len; i++) {
    if (i + 3 < data_len && data[i] == '\n' && data[i + 1] == '\n') {
      i += 2;
      break;
    }
    if (i + 3 < data_len &&
	data[i] == '\n' && data[i + 1] == ' ' && data[i + 2] == '\n') {
      i += 3;
      break;
    }
  }

  /* Get end of base64 encoded data, ignore OpenPGP radix64 CRC */
  for (k = i; k < data_len; k++) {
    if (k + 1 < data_len && data[k] == '=') {
      data_len -= (data_len - ++k);
      break;
    }
  }

  return silc_base64_decode(NULL, data + i, data_len, ret_len);
}

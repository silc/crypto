/*

  silcpgp_pkcs.c

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

/**************************** OpenPGP PKCS API ******************************/

/* Get algorithm context */

SILC_PKCS_GET_ALGORITHM(silc_pkcs_pgp_get_algorithm)
{
  SilcPGPPublicKey pubkey = public_key;
  return pubkey->pkcs;
}

/* Import PGP public key file */

SILC_PKCS_IMPORT_PUBLIC_KEY_FILE(silc_pkcs_pgp_import_public_key_file)
{
  SilcList list;
  SilcBool ret;
  unsigned char *data = NULL;
  SilcPGPPublicKey pubkey;

  SILC_LOG_DEBUG(("Parsing OpenPGP public key file"));

  if (!ret_public_key)
    return FALSE;

  switch (encoding) {
  case SILC_PKCS_FILE_BIN:
    break;

  case SILC_PKCS_FILE_BASE64:
    data = silc_pgp_dearmor(filedata, filedata_len, &filedata_len);
    if (!data)
      return FALSE;
    filedata = data;
    break;
  }

  /* Parse PGP packets */
  if (!silc_pgp_packet_decode(filedata, filedata_len, NULL, &list)) {
    silc_free(data);
    return FALSE;
  }
  silc_free(data);

  /* Parse the public key */
  ret = silc_pgp_public_key_decode(&list, &pubkey);
  if (ret) {
    if (ret_alg)
      *ret_alg = pubkey->pkcs;
    if (ret_public_key)
      *ret_public_key = pubkey;
  }

  silc_pgp_packet_free_list(&list);

  return ret;
}

/* Import OpenPGP public key packet (OpenPGP certificate). */

SILC_PKCS_IMPORT_PUBLIC_KEY(silc_pkcs_pgp_import_public_key)
{
  SilcPGPPublicKey pubkey;
  int ret;

  pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    return 0;

  ret = silc_pgp_packet_public_key_decode(key, key_len, pubkey);
  if (ret) {
    if (ret_alg)
      *ret_alg = pubkey->pkcs;
    if (ret_public_key)
      *ret_public_key = pubkey;
  } else {
    silc_free(pubkey);
  }

  return ret;
}

/* Export PGP public key file */

SILC_PKCS_EXPORT_PUBLIC_KEY_FILE(silc_pkcs_pgp_export_public_key_file)
{
  return 0;
}

/* Export OpenPGP public key */

SILC_PKCS_EXPORT_PUBLIC_KEY(silc_pkcs_pgp_export_public_key)
{
  return 0;
}

/* Return public key length in bits */

SILC_PKCS_PUBLIC_KEY_BITLEN(silc_pkcs_pgp_public_key_bitlen)

{
  SilcPGPPublicKey pubkey = public_key;
  return pubkey->pkcs->public_key_bitlen(pubkey->pkcs, pubkey->public_key);
}

/* Copy public key */

SILC_PKCS_PUBLIC_KEY_COPY(silc_pkcs_pgp_public_key_copy)
{
  SilcPGPPublicKey pubkey = public_key, new_pubkey, p;
  SilcPGPPacket packet;

  new_pubkey = silc_calloc(1, sizeof(*new_pubkey));
  if (!new_pubkey)
    return NULL;

  if (pubkey->subkeys) {
    new_pubkey->subkeys = silc_dlist_init();
    if (!new_pubkey->subkeys) {
      silc_free(new_pubkey);
      return NULL;
    }

    silc_dlist_start(pubkey->subkeys);
    while ((p = silc_dlist_get(pubkey->subkeys))) {
      p = silc_pkcs_pgp_public_key_copy(pkcs, p);
      if (p)
	silc_dlist_add(new_pubkey->subkeys, p);
    }
  }

  silc_list_init(new_pubkey->packets, struct SilcPGPPacketStruct, next);
  silc_list_start(pubkey->packets);
  while ((packet = silc_list_get(pubkey->packets))) {
    packet = silc_pgp_packet_copy(packet);
    if (packet) {
      silc_free(new_pubkey);
      return NULL;
    }
    silc_list_add(new_pubkey->packets, packet);
  }

  memcpy(new_pubkey->key_id, pubkey->key_id, sizeof(pubkey->key_id));
  memcpy(new_pubkey->fingerprint, pubkey->fingerprint,
	 sizeof(pubkey->fingerprint));
  new_pubkey->created = pubkey->created;
  new_pubkey->valid = pubkey->valid;
  new_pubkey->version = pubkey->version;
  new_pubkey->algorithm = pubkey->algorithm;

  new_pubkey->public_key = pubkey->pkcs->public_key_copy(pubkey->pkcs,
							 pubkey->public_key);
  if (!new_pubkey->public_key) {
    silc_free(new_pubkey);
    return NULL;
  }

  return new_pubkey;
}

/* Compares public keys */

SILC_PKCS_PUBLIC_KEY_COMPARE(silc_pkcs_pgp_public_key_compare)
{
  SilcPGPPublicKey k1 = key1, k2 = key2;

  if (k1->version != k2->version)
    return FALSE;
  if (k1->created != k2->created)
    return FALSE;
  if (k1->valid != k2->valid)
    return FALSE;
  if (k1->algorithm != k2->algorithm)
    return FALSE;
  if (memcmp(k1->key_id, k2->key_id, sizeof(k1->key_id)))
    return FALSE;
  if (memcmp(k1->fingerprint, k2->fingerprint, sizeof(k1->fingerprint)))
    return FALSE;

  return k1->pkcs->public_key_compare(k1->pkcs,
				      k1->public_key, k2->public_key);
}

/* Free public key */

SILC_PKCS_PUBLIC_KEY_FREE(silc_pkcs_pgp_public_key_free)
{
  silc_pgp_public_key_free(public_key);
}

/* Import PGP private key file */

SILC_PKCS_IMPORT_PRIVATE_KEY_FILE(silc_pkcs_pgp_import_private_key_file)
{
  SilcList list;
  SilcBool ret;
  unsigned char *data = NULL;
  SilcPGPPrivateKey privkey;

  SILC_LOG_DEBUG(("Parsing OpenPGP private key file"));

  if (!ret_private_key)
    return FALSE;

  switch (encoding) {
  case SILC_PKCS_FILE_BIN:
    break;

  case SILC_PKCS_FILE_BASE64:
    data = silc_pgp_dearmor(filedata, filedata_len, &filedata_len);
    if (!data)
      return FALSE;
    filedata = data;
    break;
  }

  /* Parse PGP packets */
  if (!silc_pgp_packet_decode(filedata, filedata_len, NULL, &list)) {
    silc_free(data);
    return FALSE;
  }
  silc_free(data);

  /* Parse the private key */
  ret = silc_pgp_private_key_decode(&list, passphrase, passphrase_len,
				    &privkey);
  if (ret) {
    if (ret_alg)
      *ret_alg = privkey->public_key->pkcs;
    if (ret_private_key)
      *ret_private_key = privkey;
  }

  silc_pgp_packet_free_list(&list);

  return ret;
}

/* Import OpenPGP private key */

SILC_PKCS_IMPORT_PRIVATE_KEY(silc_pkcs_pgp_import_private_key)
{
  SilcPGPPrivateKey privkey;
  int ret;

  privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey)
    return 0;

  ret = silc_pgp_packet_private_key_decode(key, key_len, passphrase,
					   passphrase_len, privkey);
  if (ret) {
    if (ret_alg)
      *ret_alg = privkey->public_key->pkcs;
    if (ret_private_key)
      *ret_private_key = privkey;
  } else {
    silc_free(privkey);
  }

  return ret;
}

/* Export PGP private key file */

SILC_PKCS_EXPORT_PRIVATE_KEY_FILE(silc_pkcs_pgp_export_private_key_file)
{
  return 0;
}

/* Export OpenPGP private key */

SILC_PKCS_EXPORT_PRIVATE_KEY(silc_pkcs_pgp_export_private_key)
{
  return 0;
}

/* Returns key length in bits */

SILC_PKCS_PRIVATE_KEY_BITLEN(silc_pkcs_pgp_private_key_bitlen)
{
  SilcPGPPrivateKey privkey = private_key;
  return silc_pkcs_pgp_public_key_bitlen(pkcs, privkey->public_key);
}

/* Free private key */

SILC_PKCS_PRIVATE_KEY_FREE(silc_pkcs_pgp_private_key_free)
{
  SilcPGPPrivateKey privkey = private_key;
  silc_pgp_private_key_free(privkey);
}

/* Encrypt */

SILC_PKCS_ENCRYPT(silc_pkcs_pgp_encrypt)
{
  return 0;
}

/* Decrypt */

SILC_PKCS_DECRYPT(silc_pkcs_pgp_decrypt)
{
  return 0;
}

/* Sign */

SILC_PKCS_SIGN(silc_pkcs_pgp_sign)
{
  return 0;
}

/* Verify */

SILC_PKCS_VERIFY(silc_pkcs_pgp_verify)
{
  return 0;
}

/************************** OpenPGP RSA PKCS API ****************************/

/* Import OpenPGP compliant RSA public key */

SILC_PKCS_ALG_IMPORT_PUBLIC_KEY(silc_pgp_rsa_import_public_key)
{
  SilcBufferStruct alg_key;
  RsaPublicKey *pubkey;
  unsigned char *n, *e;
  SilcUInt16 n_len, e_len;

  if (!ret_public_key)
    return 0;

  /* Allocate RSA public key */
  *ret_public_key = pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    return FALSE;

  /* Parse OpenPGP RSA public key */
  silc_buffer_set(&alg_key, key, key_len);
  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_UINT16(&n_len),
			   SILC_STR_END) < 0)
    goto err;

  n_len = (n_len + 7) / 8;
  if (!n_len)
    goto err;

  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(&n, n_len),
			   SILC_STR_UINT16(&e_len),
			   SILC_STR_END) < 0)
    goto err;

  e_len = (e_len + 7) / 8;
  if (!e_len)
    goto err;

  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(&e, e_len),
			   SILC_STR_END) < 0)
    goto err;

  /* Get MP integers */
  silc_mp_init(&pubkey->n);
  silc_mp_init(&pubkey->e);
  silc_mp_bin2mp(n, n_len, &pubkey->n);
  silc_mp_bin2mp(e, e_len, &pubkey->e);

  /* Set key length */
  pubkey->bits = silc_mp_sizeinbase(&pubkey->n, 2);

  return silc_buffer_headlen(&alg_key);

 err:
  silc_free(pubkey);
  return 0;
}

/* Export OpenPGP compliant RSA public key */

SILC_PKCS_ALG_EXPORT_PUBLIC_KEY(silc_pgp_rsa_export_public_key)
{
  RsaPublicKey *pubkey = public_key;
  SilcBufferStruct alg_key;
  unsigned char *n = NULL, *e = NULL, *ret;
  SilcUInt16 n_len, e_len;

  n_len = silc_mp_sizeinbase(&pubkey->n, 2);
  e_len = silc_mp_sizeinbase(&pubkey->e, 2);

  /* Encode MP integers */
  n = silc_mp_mp2bin(&pubkey->n, 0, NULL);
  if (!n)
    goto err;
  e = silc_mp_mp2bin(&pubkey->e, 0, NULL);
  if (!e)
    goto err;

  memset(&alg_key, 0, sizeof(alg_key));
  if (silc_buffer_format(&alg_key,
			 SILC_STR_UINT16(n_len),
			 SILC_STR_DATA(n, n_len),
			 SILC_STR_UINT16(e_len),
			 SILC_STR_DATA(e, e_len),
			 SILC_STR_END) < 0)
    goto err;

  silc_free(n);
  silc_free(e);

  ret = silc_buffer_steal(&alg_key, ret_len);
  return ret;

 err:
  silc_free(n);
  silc_free(e);
  return NULL;
}

/* Import OpenPGP compliant RSA private key */

SILC_PKCS_ALG_IMPORT_PRIVATE_KEY(silc_pgp_rsa_import_private_key)
{
  SilcBufferStruct alg_key;
  RsaPrivateKey *privkey;
  unsigned char *d, *p, *q, *u;
  SilcUInt16 d_len, p_len, q_len, u_len;
  SilcMPInt pm1, qm1;

  if (!ret_private_key)
    return 0;

  /* Allocate RSA private key */
  *ret_private_key = privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey)
    goto err;

  /* Parse OpenPGP RSA private key.  In OpenPGP the u is p^-1 mod q, but
     our RSA implementation expects q^-1 mod p (PKCS#1 compliant), thus
     we reverse p and q to make it work. */
  silc_buffer_set(&alg_key, key, key_len);
  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_UINT16(&d_len),
			   SILC_STR_END) < 0)
    goto err;

  d_len = (d_len + 7) / 8;
  if (!d_len)
    goto err;

  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(&d, d_len),
			   SILC_STR_UINT16(&q_len),
			   SILC_STR_END) < 0)
    goto err;

  q_len = (q_len + 7) / 8;
  if (!q_len)
    goto err;

  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(&q, q_len),
			   SILC_STR_UINT16(&p_len),
			   SILC_STR_END) < 0)
    goto err;

  p_len = (p_len + 7) / 8;
  if (!p_len)
    goto err;

  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(&p, p_len),
			   SILC_STR_UINT16(&u_len),
			   SILC_STR_END) < 0)
    goto err;

  u_len = (u_len + 7) / 8;
  if (!u_len)
    goto err;

  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(&u, u_len),
			   SILC_STR_END) < 0)
    goto err;

  /* Get MP integers */
  silc_mp_init(&privkey->d);
  silc_mp_init(&privkey->p);
  silc_mp_init(&privkey->q);
  silc_mp_init(&privkey->qP);
  silc_mp_bin2mp(d, d_len, &privkey->d);
  silc_mp_bin2mp(p, p_len, &privkey->p);
  silc_mp_bin2mp(q, q_len, &privkey->q);
  silc_mp_bin2mp(u, u_len, &privkey->qP);

  /* Fill in missing integers and pre-compute */
  silc_mp_init(&pm1);
  silc_mp_init(&qm1);
  silc_mp_init(&privkey->n);
  silc_mp_init(&privkey->e);
  silc_mp_init(&privkey->dP);
  silc_mp_init(&privkey->dQ);
  silc_mp_mul(&privkey->n, &privkey->p, &privkey->q);
  silc_mp_sub_ui(&pm1, &privkey->p, 1);
  silc_mp_sub_ui(&qm1, &privkey->q, 1);
  silc_mp_mod(&privkey->dP, &privkey->d, &pm1);
  silc_mp_mod(&privkey->dQ, &privkey->d, &qm1);
  silc_mp_uninit(&pm1);
  silc_mp_uninit(&qm1);

  /* Set key length */
  privkey->bits = silc_mp_sizeinbase(&privkey->n, 2);

  return silc_buffer_headlen(&alg_key);

 err:
  silc_free(privkey);
  return 0;
}

/* Export OpenPGP compliant RSA private key */

SILC_PKCS_ALG_EXPORT_PRIVATE_KEY(silc_pgp_rsa_export_private_key)
{
  RsaPrivateKey *privkey = private_key;
  SilcBufferStruct alg_key;
  unsigned char *d = NULL, *p = NULL, *q = NULL, *u = NULL, *ret;
  SilcUInt16 d_len, p_len, q_len, u_len;

  /* In OpenPGP the u is p^-1 mod q, but our RSA implementation uses
     q^-1 mod p (PKCS#1 compliant), thus we reverse p and q to make the
     key correct. */
  d_len = silc_mp_sizeinbase(&privkey->d, 2);
  p_len = silc_mp_sizeinbase(&privkey->q, 2);
  q_len = silc_mp_sizeinbase(&privkey->p, 2);
  u_len = silc_mp_sizeinbase(&privkey->qP, 2);

  /* Encode MP integers */
  d = silc_mp_mp2bin(&privkey->d, 0, NULL);
  if (!d)
    goto err;
  p = silc_mp_mp2bin(&privkey->q, 0, NULL);
  if (!p)
    goto err;
  q = silc_mp_mp2bin(&privkey->p, 0, NULL);
  if (!q)
    goto err;
  u = silc_mp_mp2bin(&privkey->qP, 0, NULL);
  if (!u)
    goto err;

  memset(&alg_key, 0, sizeof(alg_key));
  if (silc_buffer_format(&alg_key,
			 SILC_STR_UINT16(d_len),
			 SILC_STR_DATA(d, d_len),
			 SILC_STR_UINT16(p_len),
			 SILC_STR_DATA(p, p_len),
			 SILC_STR_UINT16(q_len),
			 SILC_STR_DATA(q, q_len),
			 SILC_STR_UINT16(u_len),
			 SILC_STR_DATA(u, u_len),
			 SILC_STR_END) < 0)
    goto err;

  silc_free(d);
  silc_free(p);
  silc_free(q);
  silc_free(u);

  ret = silc_buffer_steal(&alg_key, ret_len);
  return ret;

 err:
  silc_free(d);
  silc_free(p);
  silc_free(q);
  silc_free(u);
  return NULL;
}

/************************** OpenPGP DSA PKCS API ****************************/

/* Import OpenPGP compliant DSA public key */

SILC_PKCS_ALG_IMPORT_PUBLIC_KEY(silc_pgp_dsa_import_public_key)
{
  SilcBufferStruct alg_key;
  DsaPublicKey *pubkey;
  unsigned char *p, *q, *g, *y;
  SilcUInt16 p_len, q_len, g_len, y_len;

  if (!ret_public_key)
    return 0;

  /* Allocate DSA public key */
  *ret_public_key = pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    return FALSE;

  /* Parse OpenPGP DSA public key */
  silc_buffer_set(&alg_key, key, key_len);
  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_UINT16(&p_len),
			   SILC_STR_END) < 0)
    goto err;

  p_len = (p_len + 7) / 8;
  if (!p_len)
    goto err;

  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(&p, p_len),
			   SILC_STR_UINT16(&q_len),
			   SILC_STR_END) < 0)
    goto err;

  q_len = (q_len + 7) / 8;
  if (!q_len)
    goto err;

  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(&q, q_len),
			   SILC_STR_UINT16(&g_len),
			   SILC_STR_END) < 0)
    goto err;

  g_len = (g_len + 7) / 8;
  if (!g_len)
    goto err;

  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(&g, g_len),
			   SILC_STR_UINT16(&y_len),
			   SILC_STR_END) < 0)
    goto err;

  y_len = (y_len + 7) / 8;
  if (!y_len)
    goto err;

  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(&y, y_len),
			   SILC_STR_END) < 0)
    goto err;

  /* Get MP integers */
  silc_mp_init(&pubkey->p);
  silc_mp_init(&pubkey->q);
  silc_mp_init(&pubkey->g);
  silc_mp_init(&pubkey->y);
  silc_mp_bin2mp(p, p_len, &pubkey->p);
  silc_mp_bin2mp(q, q_len, &pubkey->q);
  silc_mp_bin2mp(g, g_len, &pubkey->g);
  silc_mp_bin2mp(y, y_len, &pubkey->y);

  /* Set key length */
  pubkey->bits = silc_mp_sizeinbase(&pubkey->p, 2);

  return silc_buffer_headlen(&alg_key);

 err:
  silc_free(pubkey);
  return 0;
}

/* Export OpenPGP compliant DSA public key */

SILC_PKCS_ALG_EXPORT_PUBLIC_KEY(silc_pgp_dsa_export_public_key)
{
  return 0;
}

/* Import OpenPGP compliant DSA private key */

SILC_PKCS_ALG_IMPORT_PRIVATE_KEY(silc_pgp_dsa_import_private_key)
{
  SilcBufferStruct alg_key;
  DsaPrivateKey *privkey;
  unsigned char *x;
  SilcUInt16 x_len;

  if (!ret_private_key)
    return 0;

  /* Allocate DSA private key */
  *ret_private_key = privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey)
    goto err;

  /* Parse OpenPGP DSA private key. */
  silc_buffer_set(&alg_key, key, key_len);
  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_UINT16(&x_len),
			   SILC_STR_END) < 0)
    goto err;

  x_len = (x_len + 7) / 8;
  if (!x_len)
    goto err;

  if (silc_buffer_unformat(&alg_key,
			   SILC_STR_ADVANCE,
			   SILC_STR_DATA(&x, x_len),
			   SILC_STR_END) < 0)
    goto err;

  /* Get MP integers */
  silc_mp_init(&privkey->x);
  silc_mp_bin2mp(x, x_len, &privkey->x);

  return silc_buffer_headlen(&alg_key);

 err:
  silc_free(privkey);
  return 0;
}

/* Export OpenPGP compliant DSA private key */

SILC_PKCS_ALG_EXPORT_PRIVATE_KEY(silc_pgp_dsa_export_private_key)
{
  return 0;
}

/*

  test_softacc_cipher2.c

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

/* Test that the software accelerated cipher encrypts and decrypts
   correctly. */

#include "silccrypto.h"
#include "softacc.h"

#define ENC_LEN 799		/* enc data len */
#define ENC_ROUND 10000		/* enc rounds */

SilcCipher enc_cipher, enc_acc_cipher;
SilcCipher dec_cipher, dec_acc_cipher;

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  unsigned char *data, iv[SILC_CIPHER_MAX_IV_SIZE];
  SilcUInt32 i, k;

  silc_runtime_init();
  silc_crypto_init(NULL);

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*acc*,*cipher*,*twofish*");
  }

  if (!silc_acc_init(SILC_SOFTACC, (void *)0x01, "min_threads", 2,
		     "max_threads", 8, NULL))
    exit(1);

  data = malloc(ENC_LEN * sizeof(*data));
  if (!data)
    exit(1);

  /* Plaintext */
  for (i = 0; i < ENC_LEN; i++)
    data[i] = i % 255;
  SILC_LOG_HEXDUMP(("data"), data, ENC_LEN);

  /* IV */
  for (i = 0; i < SILC_CIPHER_MAX_IV_SIZE; i++)
    iv[i] = i % 255;

  SILC_LOG_HEXDUMP(("IV"), iv, SILC_CIPHER_MAX_IV_SIZE);

  for (i = 0; silc_default_ciphers[i].name; i++) {
    if (!silc_cipher_alloc(silc_default_ciphers[i].name, &enc_cipher)) {
      fprintf(stderr, "Error allocating %s\n", silc_default_ciphers[i].name);
      exit(1);
    }
    if (!silc_cipher_alloc(silc_default_ciphers[i].name, &dec_cipher)) {
      fprintf(stderr, "Error allocating %s\n", silc_default_ciphers[i].name);
      exit(1);
    }

    enc_acc_cipher = silc_acc_cipher(SILC_SOFTACC, enc_cipher);
    if (!enc_acc_cipher)
      continue;
    dec_acc_cipher = silc_acc_cipher(SILC_SOFTACC, dec_cipher);
    if (!dec_acc_cipher)
      continue;

    SILC_LOG_DEBUG(("Allocated cipher %s", silc_default_ciphers[i].name));

    SILC_LOG_DEBUG(("Set key"));
    silc_cipher_set_key(enc_acc_cipher, data,
			silc_cipher_get_key_len(enc_cipher),
			TRUE);
    silc_cipher_set_key(dec_acc_cipher, data,
			silc_cipher_get_key_len(dec_cipher),
			FALSE);


    SILC_LOG_DEBUG(("Set IV"));
    silc_cipher_set_iv(enc_acc_cipher, iv);

    SILC_LOG_DEBUG(("Encrypt with accelerated cipher"));
    for (k = 0; k < ENC_ROUND; k++)
      silc_cipher_encrypt(enc_acc_cipher, data, data, ENC_LEN, NULL);
    SILC_LOG_HEXDUMP(("data"), data, ENC_LEN);

    SILC_LOG_DEBUG(("Set IV"));
    silc_cipher_set_iv(dec_cipher, iv);

    SILC_LOG_DEBUG(("Decrypt with associated cipher"));
    for (k = 0; k < ENC_ROUND; k++)
      silc_cipher_decrypt(dec_cipher, data, data, ENC_LEN, NULL);
    SILC_LOG_HEXDUMP(("data"), data, ENC_LEN);

    /* Verify */
    SILC_LOG_DEBUG(("Verify"));
    for (k = 0; k < ENC_LEN; k++)
      if (data[k] != k % 255)
	goto err;
    SILC_LOG_DEBUG(("Ok"));


    SILC_LOG_DEBUG(("Set IV"));
    silc_cipher_set_iv(enc_cipher, iv);

    SILC_LOG_DEBUG(("Encrypt with associated cipher"));
    for (k = 0; k < ENC_ROUND; k++)
      silc_cipher_encrypt(enc_cipher, data, data, ENC_LEN, NULL);
    SILC_LOG_HEXDUMP(("data"), data, ENC_LEN);

    SILC_LOG_DEBUG(("Set IV"));
    silc_cipher_set_iv(dec_acc_cipher, iv);

    SILC_LOG_DEBUG(("Decrypt with accelerated cipher"));
    for (k = 0; k < ENC_ROUND; k++)
      silc_cipher_decrypt(dec_acc_cipher, data, data, ENC_LEN, NULL);
    SILC_LOG_HEXDUMP(("data"), data, ENC_LEN);

    /* Verify */
    SILC_LOG_DEBUG(("Verify"));
    for (k = 0; k < ENC_LEN; k++)
      if (data[k] != k % 255)
	goto err;
    SILC_LOG_DEBUG(("Ok"));


    SILC_LOG_DEBUG(("Set IV"));
    silc_cipher_set_iv(enc_acc_cipher, iv);

    SILC_LOG_DEBUG(("Encrypt with accelerated cipher"));
    for (k = 0; k < ENC_ROUND; k++)
      silc_cipher_encrypt(enc_acc_cipher, data, data, ENC_LEN, NULL);
    SILC_LOG_HEXDUMP(("data"), data, ENC_LEN);

    SILC_LOG_DEBUG(("Set IV"));
    silc_cipher_set_iv(dec_acc_cipher, iv);

    SILC_LOG_DEBUG(("Decrypt with accelerated cipher"));
    for (k = 0; k < ENC_ROUND; k++)
      silc_cipher_decrypt(dec_acc_cipher, data, data, ENC_LEN, NULL);
    SILC_LOG_HEXDUMP(("data"), data, ENC_LEN);

    /* Verify */
    SILC_LOG_DEBUG(("Verify"));
    for (k = 0; k < ENC_LEN; k++)
      if (data[k] != k % 255)
	goto err;
    SILC_LOG_DEBUG(("Ok"));


    SILC_LOG_DEBUG(("Set IV"));
    silc_cipher_set_iv(enc_cipher, iv);

    SILC_LOG_DEBUG(("Encrypt with associated cipher"));
    for (k = 0; k < ENC_ROUND; k++)
      silc_cipher_encrypt(enc_cipher, data, data, ENC_LEN, NULL);
    SILC_LOG_HEXDUMP(("data"), data, ENC_LEN);

    SILC_LOG_DEBUG(("Set IV"));
    silc_cipher_set_iv(dec_cipher, iv);

    SILC_LOG_DEBUG(("Decrypt with associated cipher"));
    for (k = 0; k < ENC_ROUND; k++)
      silc_cipher_decrypt(dec_cipher, data, data, ENC_LEN, NULL);
    SILC_LOG_HEXDUMP(("data"), data, ENC_LEN);

    /* Verify */
    SILC_LOG_DEBUG(("Verify"));
    for (k = 0; k < ENC_LEN; k++)
      if (data[k] != k % 255)
	goto err;
    SILC_LOG_DEBUG(("Ok"));


    silc_cipher_free(enc_acc_cipher);
    silc_cipher_free(enc_cipher);
    silc_cipher_free(dec_acc_cipher);
    silc_cipher_free(dec_cipher);
  }

  silc_acc_uninit(SILC_SOFTACC);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  silc_crypto_uninit();
  silc_runtime_uninit();

  return !success;
}

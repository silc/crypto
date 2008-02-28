/*

  test_softacc_cipher.c

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

#include "silccrypto.h"
#include "softacc.h"

#define ENC_LEN 0x00100000	/* enc data len (at least) */
#define ENC_ROUND 512		/* enc rounds (at least) */
#define ENC_MIN_TIME 15.0        /* seconds to run the test (at least) */

SilcTimerStruct timer;
SilcCipher cipher, acc_cipher;

int main(int argc, char **argv)
{
  SilcUInt64 sec;
  SilcUInt32 usec;
  double totsec;
  unsigned char *data;
  SilcUInt32 rounds;
  SilcUInt32 i, k;

  silc_runtime_init();
  silc_crypto_init(NULL);

#if 0
  silc_log_debug(TRUE);
  silc_log_quick(TRUE);
  silc_log_debug_hexdump(TRUE);
  silc_log_set_debug_string("*acc*,*thread*");
#endif

  if (!silc_acc_init(SILC_SOFTACC, (void *)0x01, "min_threads", 2,
		     "max_threads", 8, NULL))
    exit(1);

  data = malloc(ENC_LEN * sizeof(*data));
  if (!data)
    exit(1);

  for (i = 0; i < ENC_LEN; i++)
    data[i] = i % 255;

  silc_timer_synchronize(&timer);

  for (i = 0; silc_default_ciphers[i].name; i++) {
    if (!silc_cipher_alloc(silc_default_ciphers[i].name, &cipher)) {
      fprintf(stderr, "Error allocating %s\n", silc_default_ciphers[i].name);
      exit(1);
    }

    acc_cipher = silc_acc_cipher(SILC_SOFTACC, cipher);
    if (!acc_cipher)
      continue;

    silc_cipher_set_iv(acc_cipher, data);
    silc_cipher_set_key(acc_cipher, data, silc_cipher_get_key_len(cipher),
			TRUE);
    sleep(1);

    rounds = ENC_ROUND;

  retry:
    silc_timer_start(&timer);
    for (k = 0; k < rounds; k++)
      silc_cipher_encrypt(acc_cipher, data, data, ENC_LEN, NULL);
    silc_timer_stop(&timer);

    silc_timer_value(&timer, &sec, &usec);
    totsec = (double)sec;
    totsec += ((double)usec / (double)((double)1000 * (double)1000));
    if (totsec < ENC_MIN_TIME) {
      rounds += rounds;
      goto retry;
    }

    silc_cipher_free(acc_cipher);
    silc_cipher_free(cipher);

    sleep(1);
    printf("%s:\t%.2f KB (%.2f MB, %.2f Mbit) / sec (total %.3f secs)\n",
	   silc_default_ciphers[i].name,
	   (((double)((double)ENC_LEN * (double)rounds) / 1024.0) / totsec),
	   (((double)((double)ENC_LEN * (double)rounds) / (1024.0 *
							   1024.0)) / totsec),
	   ((((double)((double)ENC_LEN * (double)rounds) / 1024.0)
	     / 128.0) / totsec),
	   totsec);
  }

  silc_acc_uninit(SILC_SOFTACC);

  silc_crypto_uninit();
  silc_runtime_uninit();

  return 0;
}

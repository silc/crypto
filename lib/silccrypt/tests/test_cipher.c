/*

  test_cipher.c

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

#define ENC_LEN 0x00100000	/* enc data len (at least) */
#define ENC_ROUND 512		/* enc rounds (at least) */
#define ENC_MIN_TIME 8.0        /* seconds to run the test (at least) */

SilcTimerStruct timer;
SilcCipher cipher;

int main(int argc, char **argv)
{
  SilcUInt64 sec;
  SilcUInt32 usec;
  double totsec;
  unsigned char *data;
  SilcUInt32 rounds;
  SilcUInt32 i, k;

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

    silc_cipher_set_key(cipher, data, silc_cipher_get_key_len(cipher), TRUE);
    silc_cipher_set_iv(cipher, data);

    rounds = ENC_ROUND;

  retry:
    silc_timer_start(&timer);
    for (k = 0; k < rounds; k++)
      silc_cipher_encrypt(cipher, data, data, ENC_LEN, NULL);
    silc_timer_stop(&timer);

    silc_timer_value(&timer, &sec, &usec);
    totsec = (double)sec;
    totsec += ((double)usec / (double)(1000 * 1000));
    if (totsec < ENC_MIN_TIME) {
      rounds += rounds;
      goto retry;
    }

    printf("%s:\t%.2f KB (%.2f MB) / sec (total test time %.2f secs)\n",
	   silc_default_ciphers[i].name,
	   (((double)(ENC_LEN * rounds) / 1024.0) / totsec),
	   (((double)(ENC_LEN * rounds) / (1024.0 * 1024.0)) / totsec),
	   totsec);

    silc_cipher_free(cipher);
  }

  return 0;
}

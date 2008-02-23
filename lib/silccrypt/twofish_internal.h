/*

  twofish_internal.h

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

#ifndef TWOFISH_INTERNAL_H
#define TWOFISH_INTERNAL_H

#include "ciphers_def.h"

/* Cipher's context */
typedef struct {
  SilcUInt32 S[4][256];
  SilcUInt32 K[40];
  SilcUInt32 padlen;
} twofish_key;

/* Prototypes */
int twofish_setup(const unsigned char *key, int keylen, int num_rounds,
		  twofish_key *skey);
int twofish_encrypt(const SilcUInt32 pt[4], SilcUInt32 ct[4],
		    twofish_key *skey);
int twofish_decrypt(const SilcUInt32 ct[4], SilcUInt32 pt[4],
		    twofish_key *skey);

#endif /* TWOFISH_INTERNAL_H */

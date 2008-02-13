/*

  silcpgp_i.h

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

#ifndef SILCPGP_I_H
#define SILCPGP_I_H

#ifndef SILCPGP_H
#error "Do not include this header directly"
#endif

/* OpenPGP packet.  Contains the raw data and packet tag. */
struct SilcPGPPacketStruct {
  struct SilcPGPPacketStruct *next;
  SilcBufferStruct data;
  SilcUInt8 tag;
};

/* Armoring headers */
#define SILC_PGP_ARMOR_MESSAGE   "BEGIN PGP MESSAGE"
#define SILC_PGP_ARMOR_PUBKEY    "BEGIN PGP PUBLIC KEY BLOCK"
#define SILC_PGP_ARMOR_PRIVKEY   "BEGIN PGP PRIVATE KEY BLOCK"
#define SILC_PGP_ARMOR_SIGNATURE "BEGIN PGP SIGNATURE"

SilcPGPPacket silc_pgp_packet_copy(SilcPGPPacket packet);
SilcCipher silc_pgp_cipher_alloc(SilcPGPCipher cipher);
int silc_pgp_packet_public_key_decode(unsigned char *key, SilcUInt32 key_len,
				      SilcPGPPublicKey pubkey);
int silc_pgp_packet_private_key_decode(unsigned char *key, SilcUInt32 key_len,
				       const char *passphrase,
				       SilcUInt32 passphrase_len,
				       SilcPGPPrivateKey privkey);
#ifdef SILC_DEBUG
const char *silc_pgp_packet_name(SilcPGPPacketTag tag);
#endif /* SILC_DEBUG */

#endif /* SILCPGP_I_H */

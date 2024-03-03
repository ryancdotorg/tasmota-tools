/* SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR MIT-0 */
/* Copyright (c) 2024 Ryan Castellucci, No Rights Reserved */

const tasmota_tls_fingerprint = (_=>{
  // golfed SHA1, reuses variables for size; the data has to be already padded
  // based on https://github.com/jbt/tiny-hashes/blob/04cfef0/sha1/sha1.js
  const raw_sha1 = (u, j) => {
    var
      i,
      W = [],
      words = [],
      A, B, C, D,
      n = --j >> 2,
      H = [A = 0x67452301, B = 0xEFCDAB89, ~A, ~B, 0xC3D2E1F0];

    for (; ~j;) { // j !== -1
      words[j >> 2] |= u[j] << 8 * ~j--;
    }

    for (i = j = 0; i < n; i += 16) {
      A = H;

      for (; j < 80;
        A = [
          (
            A[4] +
            (
              W[j] =
                (j < 16)
                  ? words[i + j]
                  : u * 2 | u < 0 // u << 1 | s >>> 31
            ) +
            1518500249 +
            [
              (B & C | ~B & D),
              u = (B ^ C ^ D) + 341275144,
              (B & C | B & D | C & D) + 882459459,
              u + 1535694389
            ][j++ / 5 >> 2] +
            ((u = A[0]) << 5 | u >>> 27)
          ),
          u,
          B << 30 | B >>> 2,
          C,
          D
        ]
      ) {
        u = W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16];
        B = A[1];
        C = A[2];
        D = A[3];
      }

      for (j = 5; j;) {
        H[--j] += A[j];
      }
    }

    // hex encode with a space between each byte
    for (u = ''; j < 40;) {
      u += (j && !(j&1) ? ' ' : '') +
           (H[j >> 3] >> (7 - j++) * 4 & 15).toString(16);
    }

    return u.toUpperCase();
  };

  // base64 decode to Uint8Array
  const b64d = str => Uint8Array.from(atob(str), c => c.charCodeAt());

  // strip e.g. -----BEGIN PUBLIC KEY--- and base64 decode
  const pemToDer = str => b64d(str.replace(/(^-.+)?\n/gm, ''));

  // crude ASN.1 tag-length-value decoder
  const getAsn1TLV = (u8, off) => {
    let tmp, len;

    // first two bits are class, next is form, last five are number
    //let class_ = u8[off] >> 6;
    let form = u8[off] & 32;
    let type = u8[off++] & 31;

    // values larger than 30 are encoded in additional bytes
    if (type == 31) {
      type = 0;
      do {
        tmp = u8[off++];
        // the high bit is a "more bytes follow" flag
        type = type * 128 + (tmp & 127);
      } while (tmp >> 7);
    }

    // lengths longer than 127 set the high bit, then use the lower 7 bits to
    // indicate how many bytes were used to store the actual length
    len = tmp = u8[off++];
    if (tmp >> 7) {
      len = 0;
      // set tmp to end offset
      for (tmp = (tmp & 127) + off; off < tmp;) {
        len = len * 256 + u8[off++];
        /*if (len >= Number.MAX_SAFE_INTEGER) {
          throw new Error("Excessive ASN.1 length!");
        }*/
      }
    }

    // new_offset, form, type, length, value
    return [off, form, type, len, u8.slice(off, off+len)];
  };

  return data => {
    const pubKeyData = [b64d('c3NoLXJzYQ==')]; // "ssh-rsa"
    const resultU8 = new Uint8Array(2048);
    const resultDV = new DataView(resultU8.buffer);
    let der = pemToDer(data);
    let n, i, offset = 0, toSave_blockEnd;

    // crudely parse the ASN.1 data
    while (offset < der.length) {
      const [
        new_offset, form, type, len, value
      ] = /*@__INLINE__*/getAsn1TLV(der, offset);
      //console.log(der.length, offset, new_offset, toSave_blockEnd, form, type, len, value.toString());

      // we discard everyting until we find an rsa public key oui
      if (len && !form && type != 3) {
        if (!toSave_blockEnd) {
          toSave_blockEnd =
            len == 9 && // OID of rsaEncryption
            !b64d('KoZIhvcNAQEB').some((v, i) => v ^ value[i]) * 2;
        } else {
          // save the rsa public key data... if there's a leading zero, it
          // needs to be removed for compatibility with Tasmota and BearSSL
          pubKeyData[toSave_blockEnd] = value.slice(!value[0]); // (value[0] ? 0 : 1);
          // we're done once we have the key
          if (!(--toSave_blockEnd)) { break; }
        }
      }

      // skip over the data unles the form bit is set
      offset = new_offset + !form * len; // (form ? 0 : len);
      // type 3 is "BIT STRING" and should contain the key as ASN.1 data
      if (type == 3) {
        // need to skip the first byte, not sure why
        offset = 1;
        // deeper!
        der = value;
      }
    }

    // serialize the public key in tasmota's "new" format
    for (offset = i = 0; i < 3;) {
      // 4 byte big endian length
      resultDV.setUint32(offset, n = pubKeyData[i].length);
      // actual data
      resultU8.set(pubKeyData[i++], offset += 4);
      offset += n;
    }

    // add SHA1 padding
    resultU8[offset] = 0x80;
    toSave_blockEnd = offset + 72 & ~63;
    resultDV.setUint32(toSave_blockEnd-4, offset * 8);

    // hash
    return raw_sha1(resultU8, toSave_blockEnd);
  };
})();

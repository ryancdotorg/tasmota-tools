/*! SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR MIT-0 */
/*! Copyright (c) 2024 Ryan Castellucci, No Rights Reserved */

const tasmota_tls_fingerprint = (_=>{
  // golfed SHA1, reuses variables for size; the data has to be already padded
  // based on an old version of https://github.com/jbt/tiny-hashes
  const raw_sha1 = u8 => {
    for (var blockstart=0,
        i = 0,
        W = [],
        A, B, C, D, F, G,
        H = [A = 0x67452301, B = 0xEFCDAB89, ~A, ~B, 0xC3D2E1F0],
        words = [],
        n = u8.length;
      i<n;){
      words[i>>2] |= (u8[i])<<(8*(3-i++%4));
    }

    n /= 4;

    for (; blockstart < n; blockstart += 16) {
      A = H, i = 0;

      for (; i < 80;
        A = [[
          (G = ((u8=A[0])<<5|u8>>>27) + A[4] + (W[i] = (i<16) ? ~~words[blockstart + i] : G*2|G<0) + 1518500249) + ((B=A[1]) & (C=A[2]) | ~B & (D=A[3])),
          F = G + (B ^ C ^ D) + 341275144,
          G + (B & C | B & D | C & D) + 882459459,
          F + 1535694389
        ][i++/5>>2] | 0, u8, B<<30|B>>>2, C, D]
      ) {
        G = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
      }

      for (i = 5; i;) {
        H[--i] += A[i];
      }
    }

    // hex encode with a space between each byte
    for (u8 = ''; i < 40;) {
      u8 += (i && !(i&1) ? ' ' : '') +
            (H[i >> 3] >> (7 - i++) * 4 & 15).toString(16);
    }

    return u8.toUpperCase();
  };

  // base64 decode to Uint8Array
  const b64d = str => {
    // atob returns the byte values in a string... :-(
    str = atob(str);

    for (var n = str.length, u8 = new Uint8Array(n); n;) {
      u8[--n] = str.charCodeAt(n);
    }

    return u8;
  };

  // the OID for rsaEncryption
  const rsaEncryption = b64d('KoZIhvcNAQEB');

  // check whether two Uint8Arrays are equal
  // XXX not constant time
  const u8Equal = (a, b) => {
    let n = a.length, ret = n ^ b.length;
    while (!ret && n--) { ret = a[n] ^ b[n]; }
    return !ret;
  };

  // strip e.g. -----BEGIN PUBLIC KEY--- and base64 decode
  const pemToDer = str => b64d(str.replace(/(?:-+[^-]+-+|\n)/gm, ''));

  // crude ASN.1 tag-length-value decoder
  const getAsn1TLV = (u8, off) => {
    let tmp, len;

    // first two bits are class, next is form, last five are number
    //let class_ = u8[off] >> 6;
    let form = (u8[off] >> 5) & 1;
    let type = u8[off++] & 31;

    // values larger than 30 are encoded in additional bytes
    if (type === 31) {
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
    let offset = 0, toSave = 0;

    // crudely parse the ASN.1 data
    while (offset < der.length) {
      const [new_offset, form, type, len, value] = getAsn1TLV(der, offset);
      console.log(der.length, offset, new_offset, toSave, form, type, len, value.toString());

      // we discard everyting until we find an rsa public key oui
      if (len && !form && type != 3) {
        if (toSave < 1) {
          toSave = u8Equal(value, rsaEncryption) && 2;
        } else {
          // save the rsa public key data... if there's a leading zero, it
          // needs to be removed for compatibility with Tasmota and BearSSL
          pubKeyData[toSave] = value.slice(value[0] ? 0 : 1);
          // we're done once we have the key
          if (!(--toSave)) { break; }
        }
      }

      // skip over the data unles the form bit is set
      offset = new_offset + (form ? 0 : len);
      // type 3 is "BIT STRING" and should contain the key as ASN.1 data
      if (type == 3) {
        // need to skip the first byte, not sure why
        offset = 1;
        // deeper!
        der = value;
      }
    }

    // serialize the public key in tasmota's "new" format
    offset = 0;
    for (let n, i = 0; i < 3; ++i) {
      // 4 byte big endian length
      resultDV.setUint32(offset, n = pubKeyData[i].length, false);
      offset += 4;
      // actual data
      resultU8.set(pubKeyData[i], offset);
      offset += n;
    }

    // add SHA1 padding
    resultU8[offset] = 0x80;
    let blockEnd = offset + 72 & ~63;
    resultDV.setUint32(blockEnd-4, offset * 8, false);

    // truncate and hash
    return raw_sha1(resultU8.slice(0, blockEnd));
  };
})();
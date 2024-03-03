#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR MIT-0
# Copyright (c) 2024 Ryan Castellucci, No Rights Reserved

import sys
import ssl

from hashlib import sha1

def _cryptography_rsa_pub_params(pem):
    cert = x509.load_pem_x509_certificate(pem)
    rsa = cert.public_key().public_numbers()
    return (rsa.e, rsa.n)

def _cryptodome_rsa_pub_params(pem):
    rsa = RSA.importKey(pem)
    return (rsa.e, rsa.n)

def _subprocess_rsa_pub_params(pem):
    e, n = None, None

    result = subprocess.run(
        ['openssl', 'x509', '-noout', '-text'],
        input=pem, capture_output=True
    )

    data = re.sub(r':\n\s+', ':', result.stdout.decode())

    for line in data.split('\n'):
        m = re.match(r'\s*(Modulus|Exponent):\s*(\S+)', line)
        if m is not None:
            label, value = m.groups()

            if ':' in value:
                value = int(value.replace(':',''), 16)
            else:
                value = int(value)

            if label == 'Modulus':
                n = value
            elif label == 'Exponent':
                e = value

    return (e, n)

try:
    # prefer the cryptography module
    from cryptography import x509
    rsa_pub_params = _cryptography_rsa_pub_params
except ModuleNotFoundError:
    try:
        # fallback to pycryptodome module
        from Cryptodome.PublicKey import RSA
        rsa_pub_params = _cryptodome_rsa_pub_params
    except ModuleNotFoundError:
        try:
            # pycryptodome could be installed as `Crypto`
            from Crypto.PublicKey import RSA
            rsa_pub_params = _cryptodome_rsa_pub_params
        except ModuleNotFoundError:
            # fine, whatever, we can just run `openssl`
            import subprocess, re
            rsa_pub_params = _subprocess_rsa_pub_params

def get_server_certificate(hostname, port=8883):
    import ssl, socket

    # we need non-default tls client configuration
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # hostname checking has to be disabled before setting verify_mode = CERT_NONE
    ctx.check_hostname = False
    # this tool is expected to often be used with self-signed certificates
    ctx.verify_mode = ssl.CERT_NONE
    # we specifically want the RSA certificate
    ctx.set_ciphers('-ALL:aRSA')
    # turn off TLSv1.3 since it won't honor the cipher settings
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    # set application protocol preferences
    ctx.set_alpn_protocols(['mqtt', 'h2', 'http/1.1'])

    # try to connect
    with socket.create_connection((hostname, port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(True)
            return ssl.DER_cert_to_PEM_cert(der).encode()

def to_bytes(n, length=None):
    if length is None:
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')

def fmt_fingerprint(hexdigest):
    h = hexdigest.upper()
    return ' '.join(h[i:i+2] for i in range(0, len(h), 2))

if __name__ == '__main__':
    source = sys.argv[1]

    if ':' in source:
        parts = source.split(':')
        hostname = parts[0]
        port = int(parts[1])
        pem = get_server_certificate(hostname, port)
    else:
        with open(source, 'rb') as cert:
            pem = cert.read()

    e, n = rsa_pub_params(pem)
    e_bytes = to_bytes(e)
    e_len = to_bytes(len(e_bytes), 4)
    n_bytes = to_bytes(n)
    n_len = to_bytes(len(n_bytes), 4)

    bytes_new = b'\0\0\0\7ssh-rsa'+e_len+e_bytes+n_len+n_bytes
    fp_new = sha1(bytes_new).hexdigest()

    print(f'{fmt_fingerprint(fp_new)} (Tasmota v8.4.0+)')

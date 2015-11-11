##
# Copyright (C) 2012 by Konstantin Ryabitsev and contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#

import os
import base64
import hashlib
import hmac
import logging

import string
import struct

import totpcgi

logger = logging.getLogger('totpcgi')

from Crypto.Cipher import AES
from passlib.utils.pbkdf2 import pbkdf2

AES_BLOCK_SIZE = 16
KDF_ITER = 2000
SALT_SIZE = 32
KEY_SIZE = 32


def hash_pincode(pincode, algo='bcrypt'):
    if algo not in ('bcrypt', 'sha256', 'sha512', 'md5'):
        raise ValueError('Unsupported algorithm: %s' % algo)

    import passlib.hash

    # we stick to 5000 rounds for uniform compatibility
    # if you want higher computational cost, just use bcrypt
    if algo == 'sha256':
        return passlib.hash.sha256_crypt.encrypt(pincode, rounds=5000)

    if algo == 'sha512':
        return passlib.hash.sha512_crypt.encrypt(pincode, rounds=5000)

    if algo == 'md5':
        # really? Okay.
        return passlib.hash.md5_crypt.encrypt(pincode)

    return passlib.hash.bcrypt.encrypt(pincode)


def generate_secret(rate_limit=(3, 30), window_size=3, scratch_tokens=5, bs=80, max_age=-1):
    # os.urandom expects bytes, so we divide by 8
    secret = base64.b32encode(os.urandom(bs/8))

    gaus = totpcgi.GAUserSecret(secret)

    gaus.rate_limit = rate_limit
    gaus.window_size = window_size
    gaus.max_age = max_age

    for i in xrange(scratch_tokens):
        token = string.zfill(struct.unpack('I', os.urandom(4))[0], 8)[-8:]
        gaus.scratch_tokens.append(token)

    return gaus


def encrypt_secret(data, pincode):
    salt = os.urandom(SALT_SIZE)

    # derive a twice-long key from pincode
    key = pbkdf2(pincode, salt, KDF_ITER, KEY_SIZE*2, prf='hmac-sha256')

    # split the key in two, one used for AES, another for HMAC
    aes_key = key[:KEY_SIZE]
    hmac_key = key[KEY_SIZE:]

    pad = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
    data += pad * chr(pad)
    iv_bytes = os.urandom(AES_BLOCK_SIZE)
    cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
    data = iv_bytes + cypher.encrypt(data)
    sig = hmac.new(hmac_key, data, hashlib.sha256).digest()

    # jab it all together in a base64-encrypted format
    b64str = ('aes256+hmac256$' 
              + base64.b64encode(salt).replace('\n', '') + '$'
              + base64.b64encode(data+sig).replace('\n', ''))

    logger.debug('Encrypted secret: %s' % b64str)

    return b64str


def decrypt_secret(b64str, pincode):
    # split the secret into components
    try:
        (scheme, salt, ciphertext) = b64str.split('$')

        salt = base64.b64decode(salt)
        ciphertext = base64.b64decode(ciphertext)

    except (ValueError, TypeError):
        raise totpcgi.UserSecretError('Failed to parse encrypted secret')

    key = pbkdf2(pincode, salt, KDF_ITER, KEY_SIZE*2, prf='hmac-sha256')

    aes_key = key[:KEY_SIZE]
    hmac_key = key[KEY_SIZE:]

    sig_size = hashlib.sha256().digest_size
    sig = ciphertext[-sig_size:]
    data = ciphertext[:-sig_size]

    # verify hmac sig first
    if hmac.new(hmac_key, data, hashlib.sha256).digest() != sig:
        raise totpcgi.UserSecretError('Failed to verify hmac!')

    iv_bytes = data[:AES_BLOCK_SIZE]
    data = data[AES_BLOCK_SIZE:]

    cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
    data = cypher.decrypt(data)
    secret = data[:-ord(data[-1])]

    logger.debug('Decryption successful')

    return secret

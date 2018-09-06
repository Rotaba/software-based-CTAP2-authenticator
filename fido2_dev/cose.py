# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, unicode_literals

from .utils import bytes2int, int2bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding


class CoseKey(dict):
    def verify(self, message, signature):
        raise NotImplementedError('Signature verification not supported.')

    @classmethod
    def from_cryptography_key(cls, public_key):
        raise NotImplementedError('Creation from cryptography not supported.')

    @staticmethod
    def for_alg(alg):
        for cls in CoseKey.__subclasses__():
            if getattr(cls, 'ALGORITHM', None) == alg:
                return cls
        return UnsupportedKey

    @staticmethod
    def parse(cose):
        return CoseKey.for_alg(cose[3])(cose)


class UnsupportedKey(CoseKey):
    pass


class ES256(CoseKey):
    ALGORITHM = -7

    def verify(self, message, signature):
        print("ec.verfiy printouts START")
        from binascii import b2a_hex, a2b_hex
        print(b2a_hex(message))
        print(b2a_hex(signature))
        print("ec.verfiy printouts END")
        ec.EllipticCurvePublicNumbers(
            bytes2int(self[-2]), bytes2int(self[-3]), ec.SECP256R1()
        ).public_key(default_backend()).verify(
            signature, message, ec.ECDSA(hashes.SHA256())
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        pn = public_key.public_numbers()
        return cls({
            1: 2,
            3: cls.ALGORITHM,
            -1: 1,
            -2: int2bytes(pn.x, 32),
            -3: int2bytes(pn.y, 32)
        })

    @classmethod
    def from_ctap1(cls, data):
        return cls({
            1: 2,
            3: cls.ALGORITHM,
            -2: data[1:33],
            -3: data[33:65]
        })


class RS256(CoseKey):
    ALGORITHM = -257

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(
            bytes2int(self[-2]), bytes2int(self[-1])
        ).public_key(default_backend()).verify(
            signature, message, padding.PKCS1v15(), hashes.SHA256()
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        pn = public_key.public_numbers()
        return cls({
            1: 3,
            3: cls.ALGORITHM,
            -1: int2bytes(pn.n),
            -2: int2bytes(pn.e)
        })


class PS256(CoseKey):
    ALGORITHM = -37

    def verify(self, message, signature):
        rsa.RSAPublicNumbers(
            bytes2int(self[-2]), bytes2int(self[-1])
        ).public_key(default_backend()).verify(
            signature, message, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ), hashes.SHA256()
        )

    @classmethod
    def from_cryptography_key(cls, public_key):
        pn = public_key.public_numbers()
        return cls({
            1: 3,
            3: cls.ALGORITHM,
            -1: int2bytes(pn.n),
            -2: int2bytes(pn.e)
        })

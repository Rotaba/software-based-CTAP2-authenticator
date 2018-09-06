from binascii import hexlify, a2b_hex, b2a_hex
from fido2 import cbor

def cbor2hex(data):
    return b2a_hex(cbor.dumps(data)).decode()


_AAGUID = a2b_hex('F8A011F38C0A4D15800617111F9EDC7D')
_INFO = a2b_hex(
    'a60182665532465f5632684649444f5f325f3002826375766d6b686d61632d7365637265740350f8a011f38c0a4d15800617111f9edc7d04a462726bf5627570f564706c6174f469636c69656e7450696ef4051904b0068101')  # noqa
ret1 = "ret1: " + b'\0' + _INFO + " END"
print (ret1)
info_data = {
    'versions': ['U2F_V2', 'FIDO_2_0'],
    'extensions': ['uvm', 'hmac-secret'],
    'aaguid': _AAGUID,
    'options': {
        'clientPin': False,
        'plat': False,
        'rk': True,
        'up': True
    },
    'max_msg_size': 1200,
    'pin_protocols': [1]
}
# print(cbor.dumps(info_data))
ret2 = "ret2: " +b'\0' + cbor.dumps(info_data) + " END"
# ret = b'\0' + _INFO
print (ret2)
# # Serialize an object as a bytestring
# data = dumps(['hello', 'world'])
# #
# # Deserialize a bytestring
# obj = loads(data)
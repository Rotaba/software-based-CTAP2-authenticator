
"""
Connects to the first FIDO device found, creates a new credential for it,
and authenticates the credential. This works with both FIDO 2.0 devices as well
as with U2F devices.
"""
from __future__ import print_function, absolute_import, unicode_literals

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from getpass import getpass
import sys
import fido2.ctap2

import struct
import cbor
from binascii import hexlify, a2b_hex, b2a_hex
import json

# Locate a device
dev = next(CtapHidDevice.list_devices(), None)
if not dev:
    print('No FIDO device found')
    sys.exit(1)

# Set up a FIDO 2 client using the origin https://example.com
client = Fido2Client(dev, 'https://example.com')

# Prepare parameters for makeCredential
rp = {'id': 'example.com', 'name': 'Example RP'}
user = {'id': b'user_id', 'name': 'A. User'}
challenge = 'Y2hhbGxlbmdl'


#from yubieco Test CTAP
# ~ rp = {'id': 'example.com', 'name': 'Example RP'}
# ~ user = {'id': b'user_id', 'name': 'A. User'}
# ~ challenge = 'Y2hhbGxlbmdl'
# ~ client_param = a2b_hex(b'4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb')  # noqa
# ~ app_param = a2b_hex(b'f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4')  # noqa

# Create a credential
print('\nTouch your authenticator device now...\n')
try:
    # ~ attestation_object, client_data = client.make_credential(
        # ~ rp, user, challenge)
    attestation_object, client_data = client.make_credential(
        rp, user, challenge)
except ValueError:
    attestation_object, client_data = client.make_credential(
        rp, user, challenge,
        pin=getpass('Please enter PIN:'))

#pretty print a dict
def pretty_AS(d, indent=0):
    for key, value in d.items():
        print('\t' * indent + '"' +str(key)+'":')
        if isinstance(value, dict):
            #pretty_AS(value)
            print(value)
        else:
            #print()
            print('\t' * (indent+1) + str(value))
            #print('\t' * (indent + 1) + str('A'))
    print()

#hex print a dict
def dict_values(d, indent=0):
    for key, value in d.items():
        print((value), indent+1)


#pretty print the Auth_data obejct and its elements
def pretty_CD(d):
    return ('"AttestedCredentialData"(\n\t\t"aaguid": %s, \n\t\t"credential_id": %s, '
            '\n\t\t"public_key": %s') % (hexstr(d.aaguid),
                                 hexstr(d.credential_id),
                                 d.public_key)

# ~ parsed = json.loads(client_data)
# ~ print (json.dumps(parsed, indent=4, sort_keys=True))

def hexstr(bs):
    return "h'%s'" % b2a_hex(bs).decode()

def pretty_AD(d):
    r = '"AuthenticatorData"(\n\t"rp_id_hash": %s, \n\t"flags": 0x%02x, \n\t"counter": %d' %\
        (hexstr(d.rp_id_hash), d.flags, d.counter)
    if d.credential_data:
        r += ', \n\t"credential_data": %s' % pretty_CD(d.credential_data)
    if d.extensions:
        r += ', \n\t"extensions": %s' % d.extensions
    return r + ')'

print('hexlify(attestation_object):\n',hexlify(attestation_object))
print('0****************************************************')
print()
print('1)attestation_object.fmt:',attestation_object.fmt)
print('+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=')
print()
print('2) print attestation_object.auth_data:')
print('2.1) unpack dictornary and print RAW auth_data:')
print(hexlify(attestation_object.auth_data))
print('2.2) print pretty auth_data:')
print(pretty_AD(attestation_object.auth_data))

# auth_data breakdown
# ~ data1 = attestation_object.auth_data;
# ~ print ('rp_id_hash =', hexlify(data1[:32]))
# ~ flags, counter = struct.unpack('>BI', data1[32:32+5]) # >BI = big-Endian unsigned char/int
# ~ print ('flags =', flags) 
# ~ print ('counter =', counter) 
# ~ print ('credential_data and extensions if avail. =', hexlify(data1[37:]))


# credential_data breakdown
# ~ data = attestation_object.auth_data.credential_data;
# ~ print ('aaguid =', hexlify(data[:16] ) )s
# ~ c_len = struct.unpack('>H', data[16:18])[0]
# ~ print ('cred_id =', hexlify(data[18:18+c_len] ))
# ~ print ('pub_key, rest =', cbor.loads(data[18+c_len:]) )

print('+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=')
print()
print ('3)attestation_object.att_statement:')
# ~ print('3.1) print RAW att_statement:')
# ~ print(dict_values(attestation_object.att_statement))
print('3.2) print pretty att_statement:')
print(pretty_AS(attestation_object.att_statement))
print('****************************************************')
print()

# ~ if ((attestation_object.fmt) == ("fido-u2f")):
    # ~ print('runnig additonal u2f cbor unpack')
    # ~ def _parse_cbor(data):
        # ~ resp, rest = cbor.loads(data)
        # ~ if rest:
            # ~ raise ValueError('Extraneous data')
        # ~ return resp

    # ~ print 
    # ~ data = a2b_hex(hexlify((attestation_object)) )   
    # ~ data = dict((AttestationObject.KEY.for_key(k), v) for (k, v) in _parse_cbor(data).items())
    # ~ fmt = data[1]
    # ~ auth_data = AuthenticatorData(data[2])
    # ~ data[2] = self.auth_data
    # ~ att_statement = data[3]


# ~ print('attestation_object.att_statement:\n',attestation_object.att_statement)
# ~ print('CLIENT DATA:')
# ~ parsed = json.loads(client_data)
# ~ print (json.dumps(parsed, indent=4, sort_keys=True))
# ~ print(client_data)
# ~ print()
# ~ print('ATTESTATION OBJECT: as is')
# ~ print(attestation_object)
# ~ print()
# ~ print(cbor.dumps(attestation_object))
# ~ print('ATTESTATION OBJECT: as cbor hex?')
# ~ rec = cbor.loads(attestation_object)
# ~ print(b2a_hex(cbor.dumps(rec)).decode())

# ~ print('AUTH_DATA: ', cbor.loads(attestation_object.3L))
# ~ print (json.dumps(rec, indent=4, sort_keys=True))
# ~ print('fmt: ' + str((attestation_object.fmt)).replace(', ', ',\n') )
# ~ print('auth_data: ' + str(attestation_object.auth_data).replace(', ', ',\n') )
# ~ print('att_statement: ' + str(attestation_object.att_statement).replace(', ', ',\n') )
# ~ print()
# ~ print('CREDENTIAL DATA:')
# ~ print(str(attestation_object.auth_data.credential_data).replace(', ', ',\n'))
# ~ print('______________________________________')
# Verify signature
attestation_object.verify(client_data.hash)
print('Attestation signature verified!')

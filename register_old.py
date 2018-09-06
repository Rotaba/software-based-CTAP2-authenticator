
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


print('A_O: ',hexlify(attestation_object))
print('New credential created!')
print()
print('CLIENT DATA:')
# ~ parsed = json.loads(client_data)
# ~ print (json.dumps(parsed, indent=4, sort_keys=True))
print(client_data)
print()
print('ATTESTATION OBJECT: as is')
print(attestation_object)
print()
print(cbor.dumps(attestation_object))
print('ATTESTATION OBJECT: as cbor hex?')
rec = cbor.loads(attestation_object)
print(b2a_hex(cbor.dumps(rec)).decode())

# ~ print('AUTH_DATA: ', cbor.loads(attestation_object.3L))
# ~ print (json.dumps(rec, indent=4, sort_keys=True))
# ~ print('fmt: ' + str((attestation_object.fmt)).replace(', ', ',\n') )
# ~ print('auth_data: ' + str(attestation_object.auth_data).replace(', ', ',\n') )
# ~ print('att_statement: ' + str(attestation_object.att_statement).replace(', ', ',\n') )
print()
print('CREDENTIAL DATA:')
print(str(attestation_object.auth_data.credential_data).replace(', ', ',\n'))
print('______________________________________')
# Verify signature
attestation_object.verify(client_data.hash)
print('Attestation signature verified!')

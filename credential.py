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
import time

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

# Create a credential
print('\nTouch your authenticator device now...\n')
try:
    attestation_object, client_data = client.make_credential(
        rp, user, challenge)
except ValueError:
    attestation_object, client_data = client.make_credential(
        rp, user, challenge,
        pin=getpass('Please enter PIN:'))


print('New credential created!')
print()
print('CLIENT DATA:', client_data)
print()
print('ATTESTATION OBJECT:', attestation_object)
print()
print('CREDENTIAL DATA:', attestation_object.auth_data.credential_data)

# Verify signature
attestation_object.verify(client_data.hash)
print()
print('Attestation signature verified!')
print()
print('**********************************Attestation phase FINISHED***************************************')
time.sleep(1)
print("prepare for second stage; Assertion")
time.sleep(1)
print("...")
time.sleep(1)


credential = attestation_object.auth_data.credential_data

# Prepare parameters for getAssertion
challenge = 'Q0hBTExFTkdF'  # Use a new challenge for each call.
allow_list = [{
    'type': 'public-key',
    'id': credential.credential_id
}]

# Authenticate the credential
print('\nTouch your authenticator device now...\n')

try:
    assertions, client_data = client.get_assertion(
        rp['id'], challenge, allow_list)
except ValueError:
    assertions, client_data = client.get_assertion(
        rp['id'], challenge, allow_list,
        pin=getpass('Please enter PIN:'))

print('Credential authenticated!')

assertion = assertions[0]  # Only one cred in allowList, only one response.

print('CLIENT DATA:', client_data)
print()
print('ASSERTION DATA:', assertion)

# Verify signature
assertion.verify(client_data.hash, credential.public_key)
print()
print('Assertion signature verified!')
print()
print('**********************************Assertion phase FINISHED***************************************')

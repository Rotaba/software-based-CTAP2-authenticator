The code was tested with Python 3.5+ using Debain 9/Ubuntu 16 desktop environment.
It uses the Yubiekey FIDO2 python libs https://github.com/Yubico/python-fido2
I've added the lib locally to be able to peek under it's hood; but you can also use the official one through pip3 install fido2

# v2f.py is a virtual FIDO2 device

Clone this source code repository

```bash
git clone https://projects.cispa.saarland/roman.tabachnikov/FIDO2_Token_emulator/
```
You have to tweak the permissions of some files before running v2f, which needs uhid and
hidraw.  An easy way to do that is just making `/dev/uhid` and `/dev/hidraw*`
device nodes universally read-writable - there's a simple .sh to help you

```bash
sudo bash hack-linux-for-v2f
```
Run v2f (default: store everything under ~/.v2f directory)

```bash
python3 v2f.py
```

Run v2f with a specified device information directory

```bash
python3 v2f.py ~/.my-v2f-info-dir
```
You can use the Yubieko files to test the program, mainly credentails.py to run a full CTAP cycle of attest-assert

```bash
get_info.py.py
credentails.py
multi_device.py 
```

This implementation was build upon an already existing U2F (FIDO1) token with an unerlaying UHID API.
Because of this, some functions are deprecated while other were heavily altered to fit the new CTAP2 format.
Nonetheless this implementation follows the same general structre;

```bash
u2fhid.py
u2fraw.py 
v2f.py 
```
The v2f file starts the app and is generally left unchanged; while the u2fhid file takes care of the UHID communication including formatting and seriailizing; 
finally the u2fraw is in charge of the CTAP data-exchange - 

```bash
initialize - create key and cert and init constants
process_u2fraw_request - get raw request; check first bytes for command and reroute accordingly to;
generate_get_version_response_message
generate_get_info_response_message
generate_registration_response_message
generate_authentication_response_message
all those have also a U2F versions which are left in the code for back compatability reasons - not tested yet
```
On a get_info request we answer with a static info_data response 
On gen_reg we parse the msg - generate and form a CBOR attestation object to be send back through the UHID
On gen_auth we do the same for a CBOR auth object
All throughout u2fraw I've used the same terms as specified in FIDO2-CTAP2 doc as part of the W3C Webauthn standard
https://www.w3.org/TR/webauthn
https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-client-to-authenticator-protocol-v2.0-ps-20170927.html

please note that the AAGUID and CRED_ID used in the files are static and correspond to yubico's testing suit 


 
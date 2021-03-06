# touch the future - without paying 20$ for a Yubiekey 

The code was tested with Python 3.5+ using Debain 9/Ubuntu 16 desktop environment. 
It uses the Yubiekey FIDO2 python libs - I've added the lib locally to be able to peek under the hood; but you can also use the official one through
https://github.com/Yubico/python-fido2 

```bash
pip3 install fido2 
```
After you clone the repo, you'll have to tweak the permissions of some files before running v2f, which needs uhid and hidraw access.  An easy way to do that is just making `/dev/uhid` and `/dev/hidraw*` device nodes universally read-writable - there's a simple .sh to help you - TAKE NOTE; I HIGHLY RECOMMEND RUNNING THIS ON A VM TO AVOID SABOTAGING YOUR SYSTEM

```bash
sudo bash hack-linux-for-v2f
```
Run v2f (as default: it stores everything under ~/.v2f directory)

```bash
python3 v2f.py
```

Run v2f with a specified device information directory

```bash
python3 v2f.py ~/.my-v2f-info-dir
```
You can use the Yubieko testing lib to try-out the program, mainly credentials.py; to run a full CTAP cycle of attest-assert

```bash
get_info.py.py
credentials.py
multi_device.py 
```

This implementation was build upon an already existing U2F (FIDO1) token app with an underlying UHID API as an interface.
Because of this, some functions are deprecated while other were heavily altered to fit the new CTAP2 format.
Nonetheless this implementation follows the same general structure;

```bash
u2fhid.py
u2fraw.py 
v2f.py 
```
The v2f file starts the app and is generally left unchanged; while the u2fhid file takes care of the UHID communication including formatting and seriailizing; 
finally the u2fraw is in charge of the CTAP data-exchange - 

```bash
initialize - create key and cert and init constants
process_u2fraw_request - get raw request; check first bytes for command and reroute accordingly;
    generate_get_version_response_message - answer with a static version response
    generate_get_info_response_message - answer with a static info_data response
    generate_registration_response_message - generate and form a CBOR attestation object
    generate_authentication_response_message - generate and form a CBOR assertion object
parsing the msg, generating a response and sending it back to the UHID through u2fhid.py
all those have also a U2F versions which are left in the code for back compatability reasons - not tested yet
```

All throughout the u2fraw I've used the same terms as specified in FIDO2-CTAP2 doc as part of the W3C Webauthn standard
https://www.w3.org/TR/webauthn
https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-client-to-authenticator-protocol-v2.0-ps-20170927.html

please note that the AAGUID and CRED_ID used in the files are static and correspond to yubico's testing suit 


 
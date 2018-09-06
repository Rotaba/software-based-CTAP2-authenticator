import collections
import os
import select
import sys
import time

#SCARY CRYPTO STUFF
from fido2.attestation import Attestation
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
# from fido2.cose import ES256
import hashlib
import u2fcrypto
from fido2.ctap2 import Info
from fido2 import cbor
from binascii import hexlify, a2b_hex, b2a_hex
from fido2.cose import CoseKey, ES256, RS256, UnsupportedKey

#for x509 cert
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from cryptography.hazmat.primitives import serialization


KGEN_KEY = None
HMAC_KEY = None
INCR_CNT = None
V2F_DIR = None

U2F_REGISTER        = 0x01
U2F_AUTHENTICATE    = 0x02
U2F_VERSION         = 0x03
U2F_GETINFO         = 0x04

SW_NO_ERROR                 = 0x9000
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_WRONG_DATA               = 0x6984
SW_INS_NOT_SUPPORTED        = 0x6d00



ApduCmd = collections.namedtuple('ApduCmd', 'cla ins p1 p2 len data')


def initialize(device_master_secret_key, update_counter, v2f_dir):
    global KGEN_KEY
    global HMAC_KEY
    global INCR_CNT
    global V2F_DIR

    global ROMAN_KEY
    global ROMAN_CERT

    assert len(device_master_secret_key) == 64
    KGEN_KEY = device_master_secret_key[:32]
    HMAC_KEY = device_master_secret_key[32:]
    INCR_CNT = update_counter
    V2F_DIR = v2f_dir

    ## ROMAN GLOBAL SIG AND KEY
    # create a new private key
    ROMAN_KEY = ec.generate_private_key(ec.SECP256R1(), default_backend())

    ##SELF SIGNED CERT
    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Comp"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Authenticator Attestation"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ROMAN_KEY.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        # x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        x509.BasicConstraints(ca=False, path_length=None),
        critical=False,
        # Sign our certificate with our private key
    ).sign(ROMAN_KEY, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    # with open("path/to/certificate.pem", "wb") as f:
    #     f.write(cert.public_bytes(serialization.Encoding.DER))
    # print(cert.public_bytes(serialization.Encoding.DER))
    ROMAN_CERT = cert


def process_u2fraw_request(raw_request):
    print('process_u2fraw_request - raw_request: ', raw_request)
    try:
        apducmd = decode_apdu_commandROMAN(raw_request)
        print('apducmd = decode_apdu_command(raw_request) passed and apducmd.ins is ' + str(apducmd.ins) + " with apducmd.cla "  + str(apducmd.cla) )
        if (apducmd.cla == U2F_REGISTER):
            print("ROMAN apducmd.CLA or .INS == FIDO2_REGISTER")
            print(b2a_hex(apducmd.data))
            cbor_data = cbor.loads(apducmd.data)
            print((cbor_data))
            #print("apducmd.data: " + cbor.loads(apducmd.data.decode()))
            #assert len(apducmd.data) == 64
            # application_parameter = apducmd.data[32:] # parse reg
            # challenge_parameter = apducmd.data[:32]
            #sw, resp = generate_registration_response_message(application_parameter, challenge_parameter) #create response
            sw, resp = generate_registration_response_message(cbor_data)
        elif (apducmd.ins == U2F_REGISTER):
            print("ROMAN_U2F apducmd.INS == U2F_REGISTER")
            print(b2a_hex(apducmd.data))
            # cbor_data = cbor.loads(apducmd.data)
            # print((cbor_data))
            #print("apducmd.data: " + cbor.loads(apducmd.data.decode()))
            #assert len(apducmd.data) == 64
            # application_parameter = apducmd.data[32:] # parse reg
            # challenge_parameter = apducmd.data[:32]
            #sw, resp = generate_registration_response_message(application_parameter, challenge_parameter) #create response
            sw, resp = generate_registration_u2f_response_message(apducmd.data)
        elif apducmd.cla == U2F_AUTHENTICATE: # and apducmd.p1 == 0x07:
            print("ROMAN apducmd.INS == FIDO2_AUTHENTICATE")
            cbor_data = cbor.loads(apducmd.data)
            print(cbor_data)
            # assert len(apducmd.data) >= 65
            # assert len(apducmd.data[65:]) == apducmd.data[64]
            # print("*************666*************")
            #There are two Auth mode; for check OR full auth;
            # sw, resp = generate_key_handle_checking_response(apducmd.data[32:64], apducmd.data[65:])
            sw, resp = generate_authentication_response_message(cbor_data)
        elif apducmd.cla == U2F_VERSION:
            print("ROMAN apducmd.CLA == FIDO2_CANCEL")
            # assert len(apducmd.data) == 0
            sw, resp = generate_get_version_response_message()
            #sw, resp = SW_INS_NOT_SUPPORTED, b''
        elif apducmd.ins == U2F_VERSION:
            print("apducmd.ins == U2F_VERSION")
            assert len(apducmd.data) == 0
            sw, resp = generate_get_version_response_message()
        elif apducmd.ins == U2F_REGISTER:
            print("apducmd.ins == U2F_REGISTER")
            assert len(apducmd.data) == 64
            application_parameter = apducmd.data[32:] # parse reg
            challenge_parameter = apducmd.data[:32]
            sw, resp = generate_registration_response_message(application_parameter, challenge_parameter) #create response to reg
        elif apducmd.ins == U2F_AUTHENTICATE and apducmd.p1 == 0x07:
            print("apducmd.ins == U2F_AUTHENTICATE")
            assert len(apducmd.data) >= 65
            assert len(apducmd.data[65:]) == apducmd.data[64]
            sw, resp = generate_key_handle_checking_response(apducmd.data[32:64], apducmd.data[65:])
        elif apducmd.ins == U2F_AUTHENTICATE and apducmd.p1 == 0x03:
            print("apducmd.ins == U2F_AUTHENTICATE")
            assert len(apducmd.data) >= 65
            assert len(apducmd.data[65:]) == apducmd.data[64]
            sw, resp = generate_authentication_response_message(apducmd.data[32:64], apducmd.data[0:32], apducmd.data[65:])
        elif apducmd.ins == U2F_GETINFO:
            print("apducmd.ins == U2F_GETINFO")
            #assert len(apducmd.data) == 0
            sw, resp = generate_get_info_response_message()
        else:
            print("apducmd.ins == ELSE")
            sw, resp = SW_INS_NOT_SUPPORTED, b''

    except AssertionError:
        sw, resp = SW_WRONG_DATA, b''
    # ~ print('***Response from process_u2fraw_request + sw.to_bytes(2, \'big\')***: ', resp + sw.to_bytes(2, 'big') )
    return resp #+ sw.to_bytes(2, 'big')


def _is_good_key_handle(application_parameter, key_handle):
    try:
        assert len(key_handle) is 64
        kg_nonce = key_handle[:32]
        checksum = key_handle[32:]
        assert u2fcrypto.hmacsha256(HMAC_KEY, application_parameter + kg_nonce) == checksum
        return True
    except AssertionError:
        return False


def _get_key_pair(application_parameter, key_handle):
    kg_nonce = key_handle[:32]
    print("seed")
    print(b2a_hex(application_parameter + kg_nonce))
    print()
    privatekey, publickey = u2fcrypto.generate_p256ecdsa_keypair(
            application_parameter + kg_nonce)
    return privatekey, publickey


def _generate_new_key_handle(application_parameter):
    kg_nonce = os.urandom(32)
    checksum = u2fcrypto.hmacsha256(HMAC_KEY, application_parameter + kg_nonce)
    key_handle = kg_nonce + checksum
    return key_handle


def cbor2hex(data):
    return b2a_hex(cbor.dumps(data)).decode()

def hex2cbor(data):
    return cbor.loads(a2b_hex(data))

def generate_get_version_response_message():
    return SW_NO_ERROR, b'U2F_V2'

def generate_get_info_response_message():
    _AAGUID = a2b_hex('F8A011F38C0A4D15800617111F9EDC7D')
    # f8a011f38c0a4d15800617111f9edc7d
    _INFO = a2b_hex(
        'a60182665532465f5632684649444f5f325f3002826375766d6b686d61632d7365637265740350f8a011f38c0a4d15800617111f9edc7d04a462726bf5627570f564706c6174f469636c69656e7450696ef4051904b0068101')  # noqa
    # VERSIONS = 1
    # EXTENSIONS = 2
    # AAGUID = 3
    # OPTIONS = 4
    # MAX_MSG_SIZE = 5
    # PIN_PROTOCOLS = 6
    info_data = {
        1: ['U2F_V2', 'FIDO_2_0'],
        2: ['uvm', 'hmac-secret'],
        3: _AAGUID,
        4: {
            'clientPin': False,
            'plat': False,
            'rk': True,
            'up': True
        },
        5: 1200,
        6: [1]
    }

    ret = b'\0' + cbor.dumps(info_data)
    #ret = b'\0' + _INFO
    return SW_NO_ERROR, ret

def generate_registration_u2f_response_message(apducmd_data):
    print('''
%s %s

Got an event from some relying party!

A website is asking you to register the authenticator,
and it is claiming itself to be APPID with SHA256(APPID) =
%s''' % (sys.argv[0], V2F_DIR, apducmd_data))
    if not user_says_yes('Enter yes to register'):
        return SW_CONDITIONS_NOT_SATISFIED, b''

    print()
    print('Please return to the web page in 3 seconds to avoid timeout!')
    print()
    time.sleep(3)

    #ATTESTED CRED. DATA
    #token id
    _AAGUID = b'f8a011f38c0a4d15800617111f9edc7d'
    #id of publicKey source - i.e. manufacturer
    _CRED_ID = b'fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783'  # noqa

    private_key = ROMAN_KEY #initated on start
    public_key = private_key.public_key()

    #transfer into COSE format
    cose_public_key = ES256.from_cryptography_key(public_key)
    cose_public_key_hex = b2a_hex(cbor.dumps(cose_public_key))
    # cose_public_key.verify(data2, signature)

    attest_cred_data = b''.join([
        _AAGUID,
        #b'F8A011F38C0A4D15800617111F9EDC7D', #AAGUID
        b'0040',  # CRED_ID length
        _CRED_ID,
        #b'fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783',
        cose_public_key_hex,
        #cbor2hex(pk_cose).encode(), #Credentail PubK CBORtoHEX and encoded to bytes
        # b'a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290'
        ])

    ## AUTH_DATA

    #Data got from Client to be used in signature
    RP_ID = apducmd_data[32:] # used in RP ID hash
    RP_ID_hash = private_key.sign(RP_ID, ec.ECDSA(hashes.SHA256()))

    auth_data = b''.join([
        b2a_hex(RP_ID_hash),
        #b2a_hex(cbor_data[0].get(1)), #RP ID HASH
        #b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12',  # RP ID HASH
        b'41',  # FLAG
        b'00000003',  # counter
        attest_cred_data
        #b'f8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290'
    ])

    ## ATT_STMT
    # SIGNATURE

    #find clientDataHash from request
    challenge_parameter = apducmd_data[:32]
    clientDataHash = challenge_parameter
    data_to_sign = a2b_hex(auth_data) + clientDataHash
    attStmt_signature_ = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

    attest_statement = {
        'alg': -7,
        # 'sig': a2b_hex(b'304502200D15DAF337D727AB4719B4027114A2AC43CD565D394CED62C3D9D1D90825F0B3022100989615E7394C87F4AD91F8FDAE86F7A3326DF332B3633DB088AAC76BFFB9A46B'),
        'sig': attStmt_signature_,
        'x5c': [ROMAN_CERT.public_bytes(serialization.Encoding.DER)]
        # 'x5c': [a2b_hex(
        #     b'308202B73082019FA00302010202041D31330D300D06092A864886F70D01010B0500302A3128302606035504030C1F59756269636F2050726576696577204649444F204174746573746174696F6E301E170D3138303332383036333932345A170D3139303332383036333932345A306E310B300906035504061302534531123010060355040A0C0959756269636F20414231223020060355040B0C1941757468656E74696361746F72204174746573746174696F6E3127302506035504030C1E59756269636F205532462045452053657269616C203438393736333539373059301306072A8648CE3D020106082A8648CE3D030107034200047D71E8367CAFD0EA6CF0D61E4C6A416BA5BB6D8FAD52DB2389AD07969F0F463BFDDDDDC29D39D3199163EE49575A3336C04B3309D607F6160C81E023373E0197A36C306A302206092B0601040182C40A020415312E332E362E312E342E312E34313438322E312E323013060B2B0601040182E51C0201010404030204303021060B2B0601040182E51C01010404120410F8A011F38C0A4D15800617111F9EDC7D300C0603551D130101FF04023000300D06092A864886F70D01010B050003820101009B904CEADBE1F1985486FEAD02BAEAA77E5AB4E6E52B7E6A2666A4DC06E241578169193B63DADEC5B2B78605A128B2E03F7FE2A98EAEB4219F52220995F400CE15D630CF0598BA662D7162459F1AD1FC623067376D4E4091BE65AC1A33D8561B9996C0529EC1816D1710786384D5E8783AA1F7474CB99FE8F5A63A79FF454380361C299D67CB5CC7C79F0D8C09F8849B0500F6D625408C77CBBC26DDEE11CB581BEB7947137AD4F05AAF38BD98DA10042DDCAC277604A395A5B3EAA88A5C8BB27AB59C8127D59D6BBBA5F11506BF7B75FDA7561A0837C46F025FD54DCF1014FC8D17C859507AC57D4B1DEA99485DF0BA8F34D00103C3EEF2EF3BBFEC7A6613DE')]
        # # noqa
    }

    attest_obj = {
        1: 'fido-u2f', #its the backward compatible u2f mode - not packed
        2: a2b_hex(auth_data),
        3: attest_statement
    }

    att_obj = cbor2hex(attest_obj)

    return SW_NO_ERROR, b'\0' + a2b_hex(att_obj)

def generate_registration_response_message(cbor_data):
    print('''
%s %s

Got an event from some relying party!

A website is asking you to register the authenticator,
and it is claiming itself to be APPID with SHA256(APPID) =
%s''' % (sys.argv[0], V2F_DIR, cbor_data))
    if not user_says_yes('Enter yes to register'):
        return SW_CONDITIONS_NOT_SATISFIED, b''

    print()
    print('Please return to the web page in 3 seconds to avoid timeout!')
    print()
    time.sleep(3)

    _AAGUID = b'f8a011f38c0a4d15800617111f9edc7d'
    _CRED_ID = b'fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783'  # noqa

    # private_key = ROMAN_KEY
    public_key = ROMAN_KEY.public_key()

    # print(signature)
    # public_key.verify(signature, data2, ec.ECDSA(hashes.SHA256()))

    cose_public_key = ES256.from_cryptography_key(public_key)
    cose_public_key_hex = b2a_hex(cbor.dumps(cose_public_key))
    # cose_public_key.verify(data2, signature)

    attest_cred_data = b''.join([
        _AAGUID,
        #b'F8A011F38C0A4D15800617111F9EDC7D', #AAGUID
        b'0040',  # CRED_ID length
        _CRED_ID,
        #b'fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783',
        cose_public_key_hex,
        #cbor2hex(pk_cose).encode(), #Credentail PubK CBORtoHEX and encoded to bytes
        # b'a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290'
        ])
    # print(cbor_data[0].get(2))
    RP_ID = cbor_data[0].get(2).get('id')

    RP_ID_hash = hashlib.sha256(str.encode(RP_ID)).digest()
    # print(b2a_hex(RP_ID_hash))

    auth_data = b''.join([
        b2a_hex(RP_ID_hash), #RP ID HASH
        #b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12'  # RP ID HASH
        b'41',  # FLAG
        b'00000003',  # counter
        attest_cred_data
        #b'f8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290'
    ])

    #ATT_STMT

    #SIGNATURE
    #find clientDataHash from request
    clientDataHash = cbor_data[0].get(1)

    # data_to_sign = auth_data + client_data_hash
    # data_to_sign = b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12010000002C' + b'7B89F12A9088B0F5EE0EF8F6718BCCC374249C31AEEBAEB79BD0450132CD536C'
    data_to_sign = a2b_hex(auth_data) + clientDataHash
    attStmt_signature_ = ROMAN_KEY.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))
    # print("***678***")
    # print(b2a_hex(signature))
    # print(b2a_hex(data_to_sign))

    #CERTIFICATE x509
    #created on init and saved in global var - see above

    attStmt_certificate = ROMAN_CERT

    statement2 = {
        'alg': -7,
        # 'sig': a2b_hex(b'304502200D15DAF337D727AB4719B4027114A2AC43CD565D394CED62C3D9D1D90825F0B3022100989615E7394C87F4AD91F8FDAE86F7A3326DF332B3633DB088AAC76BFFB9A46B'),
        'sig': attStmt_signature_,
        'x5c': [attStmt_certificate.public_bytes(serialization.Encoding.DER)]
        # 'x5c': [a2b_hex(
        #     b'308202B73082019FA00302010202041D31330D300D06092A864886F70D01010B0500302A3128302606035504030C1F59756269636F2050726576696577204649444F204174746573746174696F6E301E170D3138303332383036333932345A170D3139303332383036333932345A306E310B300906035504061302534531123010060355040A0C0959756269636F20414231223020060355040B0C1941757468656E74696361746F72204174746573746174696F6E3127302506035504030C1E59756269636F205532462045452053657269616C203438393736333539373059301306072A8648CE3D020106082A8648CE3D030107034200047D71E8367CAFD0EA6CF0D61E4C6A416BA5BB6D8FAD52DB2389AD07969F0F463BFDDDDDC29D39D3199163EE49575A3336C04B3309D607F6160C81E023373E0197A36C306A302206092B0601040182C40A020415312E332E362E312E342E312E34313438322E312E323013060B2B0601040182E51C0201010404030204303021060B2B0601040182E51C01010404120410F8A011F38C0A4D15800617111F9EDC7D300C0603551D130101FF04023000300D06092A864886F70D01010B050003820101009B904CEADBE1F1985486FEAD02BAEAA77E5AB4E6E52B7E6A2666A4DC06E241578169193B63DADEC5B2B78605A128B2E03F7FE2A98EAEB4219F52220995F400CE15D630CF0598BA662D7162459F1AD1FC623067376D4E4091BE65AC1A33D8561B9996C0529EC1816D1710786384D5E8783AA1F7474CB99FE8F5A63A79FF454380361C299D67CB5CC7C79F0D8C09F8849B0500F6D625408C77CBBC26DDEE11CB581BEB7947137AD4F05AAF38BD98DA10042DDCAC277604A395A5B3EAA88A5C8BB27AB59C8127D59D6BBBA5F11506BF7B75FDA7561A0837C46F025FD54DCF1014FC8D17C859507AC57D4B1DEA99485DF0BA8F34D00103C3EEF2EF3BBFEC7A6613DE')]
        # # noqa
    }

    attest_obj = {
        1: 'packed',
        2: a2b_hex(auth_data),
        3: statement2
    }

    att_obj = cbor2hex(attest_obj)

    return SW_NO_ERROR, b'\0' + a2b_hex(att_obj)


def generate_key_handle_checking_response(application_parameter, key_handle):
    if _is_good_key_handle(application_parameter, key_handle):
        return SW_CONDITIONS_NOT_SATISFIED, b''
    else:
        return SW_WRONG_DATA, b''


def generate_authentication_response_message(cbor_data):
    # if not _is_good_key_handle(application_parameter, key_handle):
    #     print("FAILED THE CHECK")
    #     return SW_WRONG_DATA, b''

    print('''
%s %s

Got an event from some relying party!

A website is asking you to login with the authenticator,
and it is claiming itself to be APPID with SHA256(APPID) =
%s''' % (sys.argv[0], V2F_DIR, cbor_data))
    if not user_says_yes('Enter yes to login'):
        return SW_CONDITIONS_NOT_SATISFIED, b''
    print()

    #CBOR AUTH REQUEST EXAMPLE:
    # ({1: 'example.com',
    #   2: b'\xfd,/\xce\xb8\xf3\xf9\xf7]\xdf\xf8\x87\x9c\xb2\xe9\xe7\x15\xb8\xfc\x9f\x8ec\x1c;9\x02\xb1\xf7/^\xf6`',
    #   3: [{'type': 'public-key',
    #          'id': b'\xfe:\xac\x03m\x14\xc1\xe1\xc6U\x18\xb6\x98\xdd\x1d\xa8\xf5\x96\xbc3\xe1\x10r\x814f\xc6\xbf8Ei\x15\t\xb8\x0f\xb7mY0\x9b\x8d9\xe0\xa94Rh\x8fl\xa3\xa3\x9av\xf3\xfcRtO\xb79H\xb1W\x83'}]},
    #  b'')


    userEntity = cbor_data[0].get(3)

    # AuthenticatorData = {
    #     'rp_id_hash': b'0021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12',
    #     'flags': 0x01,
    #     'counter': 29
    # }
    # print("rp_id_hash")
    # print(b2a_hex(cbor_data[0].get(2)))

    RP_ID = cbor_data[0].get(1)
    # print(b2a_hex(RP_ID_hash))

    RP_ID_hash = hashlib.sha256(str.encode(RP_ID)).digest()


    auth_data = b''.join([
        b2a_hex(RP_ID_hash),  # RP ID HASH
        #b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12'  # RP ID HASH
        b'01',  # FLAG
        b'00000001',  # counter
        #attest_cred_data
        #b'f8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290'
    ])

    clientDataHash = cbor_data[0].get(2)
    # data_to_sign = auth_data + client_data_hash
    # data_to_sign = b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12010000002C' + b'7B89F12A9088B0F5EE0EF8F6718BCCC374249C31AEEBAEB79BD0450132CD536C'
    data_to_sign = a2b_hex(auth_data) + clientDataHash
    attStmt_signature_ = ROMAN_KEY.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

    assert_cbor2 = {
          # 1: {
          #     'id': b'\xfe:\xac\x03m\x14\xc1\xe1\xc6U\x18\xb6\x98\xdd\x1d\xa8\xf5\x96\xbc3\xe1\x10r\x814f\xc6\xbf8Ei\x15\t\xb8\x0f\xb7mY0\x9b\x8d9\xe0\xa94Rh\x8fl\xa3\xa3\x9av\xf3\xfcRtO\xb79H\xb1W\x83',
          #   'type': 'public-key'
          # },
        1: userEntity,
        #Auth_data
        # 2: b'\x00!\xf5\xfc\x0b\x85\xcd"\xe6\x06#\xbc\xd7\xd1\xcaH\x94\x89\t$\x9bGv\xebQQT\xe5{f\xae\x12\x01\x00\x00\x00\x1d',
        2: a2b_hex(auth_data),
        #Sig
        3: attStmt_signature_,
        # 3: b"0D\x02 ge\xcb\xf6\xe8q\xd3\xaf\x7f\x01\xae\x96\xf0k\x13\xc9\x0f&\xf5K\x90\\Qf\xa2\xc7\x91'O\xc29q\x02 \x0b\x148\x93Xl\xc7\x99\xfb\xa4\xda\x83\xb1\x19\xea\xea\x1b\xd8\n\xc3\xce\x88\xfc\xed\xb3\xef\xbdYj\x1fOc"
    }

    assert_obj2 = cbor2hex(assert_cbor2)
    # print(a2b_hex(asser_obj2))
    # _GA_RESP = b'a301a26269645840fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b1578364747970656a7075626c69632d6b6579025900250021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12010000001d035846304402206765cbf6e871d3af7f01ae96f06b13c90f26f54b905c5166a2c791274fc2397102200b143893586cc799fba4da83b119eaea1bd80ac3ce88fcedb3efbd596a1f4f63'
    # # print(a2b_hex(_GA_RESP))
    # _YU_RESP = b'a301a262696458400ca932ae6a47ec9fa8c8156a6559b00b9d6815930c951116ac66e39faa9632c634d9e932db7644ace66f1143163c22fe0c8c2df272d42d9e3db3bba572e96dd764747970656a7075626c69632d6b6579025825a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce194701000001b70358473045022100ee7def8a5c5bd170f0cdfdb9e6c278fd660c1f97a0045c298ca106dfd33cef3202202f42c9d55bf945550a74bdb21c0e43b9c8bf8d4899f5f7f6a2e8cb4d967fd983'
    return SW_NO_ERROR, b'\0' + a2b_hex(assert_obj2)
    # return SW_NO_ERROR, b'\0' + a2b_hex(_GA_RESP)


def decode_apdu_command(x):
    #print('decode_apdu_command(x)')
    if len(x) >= 7:
        # print('decode_apdu_command(x) len(x) >= 7:')
        #assert len(x) >= 7
        cmd_data_len = (x[4]<<16)|(x[5]<<8)|x[6]
        # print("cmd_data_len: " +  str(cmd_data_len))
        data_and_tail = x[7:]
        # print("data_and_tail: " + str(x[7:]))
        #assert len(data_and_tail) >= cmd_data_len
        # print('decode_apdu_command(x) assert len(data_and_tail) >= cmd_data_len == ' + str(len(data_and_tail) >= cmd_data_len))
        return ApduCmd(cla=x[0], ins=x[1], p1=x[2], p2=x[3], len=cmd_data_len, data=data_and_tail[:cmd_data_len])
    else:
        print('decode_apdu_command(x) GET_INFO')
        return ApduCmd(0, 0x04, 0, 0, 0, 0)

def decode_apdu_commandROMAN(x):
    # print('decode_apdu_command(x)ROMAN')
    if len(x) >= 7:
        #print('decode_apdu_command(x) len(x) >= 7:')
        #assert len(x) >= 7
        cmd_data_len = (x[4]<<16)|(x[5]<<8)|x[6]
        #print("cmd_data_len: " +  str(cmd_data_len))
        data_and_tail = x[7:]
        #print("data_and_tail: " + b2a_hex(x[1:]))
        #assert len(data_and_tail) >= cmd_data_len
        # print('decode_apdu_command(x) assert len(data_and_tail) >= cmd_data_len == ' + str(len(data_and_tail) >= cmd_data_len))
        return ApduCmd(cla=x[0], ins=x[1], p1=x[2], p2=x[3], len=cmd_data_len, data=x[1:])
    else:
        # print('decode_apdu_command(x) GET_INFO')
        return ApduCmd(0, 0x04, 0, 0, 0, 0)

def user_says_yes(prompt, timeout=10):
    print('\n' + prompt + ': ', end='', flush=True)
    return ([] != select.select([sys.stdin], [], [], timeout)[0]) and sys.stdin.readline() == 'yes\n'

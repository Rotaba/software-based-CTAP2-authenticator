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

import u2fcrypto
from fido2.ctap2 import Info
from fido2 import cbor
from binascii import hexlify, a2b_hex, b2a_hex
from fido2.cose import CoseKey, ES256, RS256, UnsupportedKey

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
    global ROMAN_SIG

    assert len(device_master_secret_key) == 64
    KGEN_KEY = device_master_secret_key[:32]
    HMAC_KEY = device_master_secret_key[32:]
    INCR_CNT = update_counter
    V2F_DIR = v2f_dir
    # ROMAN GLOBAL SIG AND KEY
    # ROMAN_SIG = b''
    ROMAN_KEY = ec.generate_private_key(ec.SECP256R1(), default_backend())


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

    #ATT_STMT
    #sig_new = u2fcrypto.generate_sha256_p256ecdsa_signature( a2b_hex(auth_data3) + cbor_data[0].get(1), sk) #RP ID HASH

    # statement = {
    #     'alg': -7,
    #     'sig': a2b_hex(
    #         b'304502200D15DAF337D727AB4719B4027114A2AC43CD565D394CED62C3D9D1D90825F0B3022100989615E7394C87F4AD91F8FDAE86F7A3326DF332B3633DB088AAC76BFFB9A46B'),
    #     # noqa
    #     'x5c': [a2b_hex(
    #         b'308202B73082019FA00302010202041D31330D300D06092A864886F70D01010B0500302A3128302606035504030C1F59756269636F2050726576696577204649444F204174746573746174696F6E301E170D3138303332383036333932345A170D3139303332383036333932345A306E310B300906035504061302534531123010060355040A0C0959756269636F20414231223020060355040B0C1941757468656E74696361746F72204174746573746174696F6E3127302506035504030C1E59756269636F205532462045452053657269616C203438393736333539373059301306072A8648CE3D020106082A8648CE3D030107034200047D71E8367CAFD0EA6CF0D61E4C6A416BA5BB6D8FAD52DB2389AD07969F0F463BFDDDDDC29D39D3199163EE49575A3336C04B3309D607F6160C81E023373E0197A36C306A302206092B0601040182C40A020415312E332E362E312E342E312E34313438322E312E323013060B2B0601040182E51C0201010404030204303021060B2B0601040182E51C01010404120410F8A011F38C0A4D15800617111F9EDC7D300C0603551D130101FF04023000300D06092A864886F70D01010B050003820101009B904CEADBE1F1985486FEAD02BAEAA77E5AB4E6E52B7E6A2666A4DC06E241578169193B63DADEC5B2B78605A128B2E03F7FE2A98EAEB4219F52220995F400CE15D630CF0598BA662D7162459F1AD1FC623067376D4E4091BE65AC1A33D8561B9996C0529EC1816D1710786384D5E8783AA1F7474CB99FE8F5A63A79FF454380361C299D67CB5CC7C79F0D8C09F8849B0500F6D625408C77CBBC26DDEE11CB581BEB7947137AD4F05AAF38BD98DA10042DDCAC277604A395A5B3EAA88A5C8BB27AB59C8127D59D6BBBA5F11506BF7B75FDA7561A0837C46F025FD54DCF1014FC8D17C859507AC57D4B1DEA99485DF0BA8F34D00103C3EEF2EF3BBFEC7A6613DE')]
    #     # noqa
    #   # 'x5c': [a2b_hex(
    #     # 4D494943476A434341634367417749424167494A414D5564567A72302F5855624D416F4743437147534D343942414D434D476778437A414A42674E56424159540A416B52464D517377435159445651514944414A455254454C4D416B47413155454277774352455578437A414A42674E5642416F4D416B52464D517377435159440A5651514C44414A455254454C4D416B474131554541777743524555784744415742676B71686B69473977304243514557435552465145526C4C6D4E76625441650A467730784F4441344D6A45784E4451334D444A61467730784F4441354D6A41784E4451334D444A614D476778437A414A42674E5642415954416B52464D5173770A435159445651514944414A455254454C4D416B47413155454277774352455578437A414A42674E5642416F4D416B52464D517377435159445651514C44414A450A5254454C4D416B474131554541777743524555784744415742676B71686B69473977304243514557435552465145526C4C6D4E766254425A4D424D47427971470A534D34394167454743437147534D34394177454841304941424F61426934453448646D4C72346C6C62515844456838635545394C526B644378674C4938314A320A59466F44646B70335345303364614F76695378416C69594B2F5A57393178475037513742315546714331647345772B6A557A42524D42304741315564446751570A424253784B37446E3652354737446B4B506565373478306D784C4473477A416642674E5648534D4547444157674253784B37446E3652354737446B4B506565370A3478306D784C4473477A415042674E5648524D4241663845425441444151482F4D416F4743437147534D343942414D43413067414D455543495143476D6130470A4F6C642B4B306769526365312F375458537144367A4963502B6E5A4C4B4B316E6849316B354149674857705669584130426D6C7454566442394D357136496D620A33425A7A4752612F637370555A4D51426171733D)]
    # }

    # print("sig")
    # print(a2b_hex(auth_data3))
    # print(cbor_data[0].get(1))
    # #print(sig_new)
    # print("AND")
    # print(a2b_hex(
    #         b'304502200D15DAF337D727AB4719B4027114A2AC43CD565D394CED62C3D9D1D90825F0B3022100989615E7394C87F4AD91F8FDAE86F7A3326DF332B3633DB088AAC76BFFB9A46B'),
    #     )

    #pub_key.verify(auth_data + client_data_hash, statement['sig'])
    # key.verify(
    #     a2b_hex(b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12010000002C' +  # noqa
    #             b'7B89F12A9088B0F5EE0EF8F6718BCCC374249C31AEEBAEB79BD0450132CD536C'),  # noqa
    #     a2b_hex(
    #         b'304402202B3933FE954A2D29DE691901EB732535393D4859AAA80D58B08741598109516D0220236FBE6B52326C0A6B1CFDC6BF0A35BDA92A6C2E41E40C3A1643428D820941E0')
    #     # noqa
    # )

    # msg1 = a2b_hex(b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12010000002C' + b'7B89F12A9088B0F5EE0EF8F6718BCCC374249C31AEEBAEB79BD0450132CD536C')
    # sig1 = a2b_hex(b'304402202B3933FE954A2D29DE691901EB732535393D4859AAA80D58B08741598109516D0220236FBE6B52326C0A6B1CFDC6BF0A35BDA92A6C2E41E40C3A1643428D820941E0')
    # print("*XXXX*")
    # print(pubkey.verify(msg1, sig1))

    # msg2 = b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12010000002C' + b'7B89F12A9088B0F5EE0EF8F6718BCCC374249C31AEEBAEB79BD0450132CD536C'

    #Data got from Client to be used in signature
    RP_ID = apducmd_data[32:] # used in RP ID hash
    challenge_parameter = apducmd_data[:32]

    #FOR SIGNATURE
    RP_ID_hash = private_key.sign(RP_ID, ec.ECDSA(hashes.SHA256()))
    clientDataHash= challenge_parameter
    # print()
    # print(challenge_parameter)

    auth_data = b''.join([
        b2a_hex(RP_ID_hash),
        #b2a_hex(cbor_data[0].get(1)), #RP ID HASH
        #b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12',  # RP ID HASH
        b'41',  # FLAG
        b'00000003',  # counter
        attest_cred_data
        #b'f8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290'
    ])

    #SIGNATURE
    #find clientDataHash from request
    #clientDataHash = cbor_data[0].get(1)

    # data_to_sign = auth_data + client_data_hash
    # data_to_sign = b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12010000002C' + b'7B89F12A9088B0F5EE0EF8F6718BCCC374249C31AEEBAEB79BD0450132CD536C'
    data_to_sign = a2b_hex(auth_data) + clientDataHash
    attStmt_signature_ = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))
    # print("***678***")
    # print(b2a_hex(signature))
    # print(b2a_hex(data_to_sign))

    #CERTIFICATE x509
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime
    from cryptography.hazmat.primitives import serialization
    # from cryptography.hazmat.primitives import hashes
    # from cryptography.hazmat.backends import default_backend
    #
    #
    # one_day = datetime.timedelta(1, 0, 0)
    # builder = x509.CertificateBuilder()
    # builder = builder.subject_name(x509.Name([
    #     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
    # ]))
    # builder = builder.issuer_name(x509.Name([
    #     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
    # ]))
    # builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    # builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    # builder = builder.serial_number(x509.random_serial_number())
    # builder = builder.public_key(public_key)
    # builder = builder.add_extension(
    #     x509.SubjectAlternativeName(
    #         [x509.DNSName(u'cryptography.io')]
    #     ),
    #     critical=False
    # )
    # builder = builder.add_extension(
    #     x509.BasicConstraints(ca=False, path_length=None), critical=True,
    # )
    # attStmt_certificate = builder.sign(
    #     private_key=private_key, algorithm=hashes.SHA256(),
    #     backend=default_backend()
    # )
    # # isinstance(certificate, x509.Certificate)
    #
    #
    # # print(b2a_hex(attStmt_certificate.public_bytes(serialization.Encoding.DER)))

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
        private_key.public_key()
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
    ).sign(private_key, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    # with open("path/to/certificate.pem", "wb") as f:
    #     f.write(cert.public_bytes(serialization.Encoding.PEM))
    # print(cert.public_bytes(serialization.Encoding.DER))
    attStmt_certificate = cert


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
        1: 'fido-u2f',
        2: a2b_hex(auth_data),
        3: statement2
    }

    att_obj = cbor2hex(attest_obj)

    client_param = a2b_hex(b'985B6187D042FB1258892ED637CEC88617DDF5F6632351A545617AA2B75261BF')  # noqa

    yubiekey_intercept = b'a301667061636b65640258c4a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947410000017ff8a011f38c0a4d15800617111f9edc7d0040594be3e4870939502dac19942b4add26889b33270fd69808214e50c094f8a85688b6011fbe6688a18b1f4d069e539ceff70db365284144f939e06123dacb69cca50102032620012158208c4c417e6d5d4e3c6a9bf9bf4d558e3cfae38d4ac3240a277495cf7e10f5af6f22582088ba61b3002ddd4fbeac0e72ee5aaf50f1c5f42c62275900cf863262565a8c5903a363616c67266373696758473045022100f2c9ffa93449a09682cdde75a42a7d3f186392e03076b0d1c10efa4197f8a2ad022059f4e54600738dc5107f6dd06bc427accc4cad8be9ac6feb35fd129ac82bea9c63783563815902c2308202be308201a6a00302010202047486fdc2300d06092a864886f70d01010b0500302e312c302a0603550403132359756269636f2055324620526f6f742043412053657269616c203435373230303633313020170d3134303830313030303030305a180f32303530303930343030303030305a306f310b300906035504061302534531123010060355040a0c0959756269636f20414231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3128302606035504030c1f59756269636f205532462045452053657269616c20313935353030333834323059301306072a8648ce3d020106082a8648ce3d03010703420004955df3adf7247d3175effd9cc4f31a4e878ebae18109566150fb388b2e5f6527bf57409aa581a50d0ac52f18445c0a13548a1353c8a4e59a704e523bc04debeda36c306a302206092b0601040182c40a020415312e332e362e312e342e312e34313438322e312e313013060b2b0601040182e51c0201010404030205203021060b2b0601040182e51c01010404120410f8a011f38c0a4d15800617111f9edc7d300c0603551d130101ff04023000300d06092a864886f70d01010b05000382010100315c4880e69a527e386689bd69fd0aa86f49eb9e4e854541556faad00b3a008a1ddc01f96c76f668361a91e232c810a79c63074c9b6e7a46eb1db5d85c44489f868a7643d22a5c862ec03f03e5848be3807d7acd55f8e1ae1ee213ac73ab4b20e3fbd5268cb07b8780271d1f4be0e5ddac734d3a5897bd4d73ba7f357ea208c99d8a4d2902e6097a005c4dc904dc0a18120e0af7d00cfc969a2886e5b1b161f3edcbc677a678d7fb53039ccda186be34ba53319523439d7fd94a70f230621b93c4ce4268d3174d943bc6ae3fc937c2de43d6b44e21153df850925f9590622ebc46e0eb18c641f0fe7e6f2a09a9b2907719f62e6135a19032a213c098b7283cee'
    ATT_OBJ = b'a301667061636b65640258c40021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae124100000003f8a011f38c0a4d15800617111f9edc7d004060a386206a3aacecbdbb22d601853d955fdc5d11adfbd1aa6a950d966b348c7663d40173714a9f987df6461beadfb9cd6419ffdfe4d4cf2eec1aa605a4f59bdaa50102032620012158200edb27580389494d74d2373b8f8c2e8b76fa135946d4f30d0e187e120b423349225820e03400d189e85a55de9ab0f538ed60736eb750f5f0306a80060fe1b13010560d03a363616c6726637369675847304502200d15daf337d727ab4719b4027114a2ac43cd565d394ced62c3d9d1d90825f0b3022100989615e7394c87f4ad91f8fdae86f7a3326df332b3633db088aac76bffb9a46b63783563815902bb308202b73082019fa00302010202041d31330d300d06092a864886f70d01010b0500302a3128302606035504030c1f59756269636f2050726576696577204649444f204174746573746174696f6e301e170d3138303332383036333932345a170d3139303332383036333932345a306e310b300906035504061302534531123010060355040a0c0959756269636f20414231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3127302506035504030c1e59756269636f205532462045452053657269616c203438393736333539373059301306072a8648ce3d020106082a8648ce3d030107034200047d71e8367cafd0ea6cf0d61e4c6a416ba5bb6d8fad52db2389ad07969f0f463bfdddddc29d39d3199163ee49575a3336c04b3309d607f6160c81e023373e0197a36c306a302206092b0601040182c40a020415312e332e362e312e342e312e34313438322e312e323013060b2b0601040182e51c0201010404030204303021060b2b0601040182e51c01010404120410f8a011f38c0a4d15800617111f9edc7d300c0603551d130101ff04023000300d06092a864886f70d01010b050003820101009b904ceadbe1f1985486fead02baeaa77e5ab4e6e52b7e6a2666a4dc06e241578169193b63dadec5b2b78605a128b2e03f7fe2a98eaeb4219f52220995f400ce15d630cf0598ba662d7162459f1ad1fc623067376d4e4091be65ac1a33d8561b9996c0529ec1816d1710786384d5e8783aa1f7474cb99fe8f5a63a79ff454380361c299d67cb5cc7c79f0d8c09f8849b0500f6d625408c77cbbc26ddee11cb581beb7947137ad4f05aaf38bd98da10042ddcac277604a395a5b3eaa88a5c8bb27ab59c8127d59d6bbba5f11506bf7b75fda7561a0837c46f025fd54dcf1014fc8d17c859507ac57d4b1dea99485df0ba8f34d00103c3eef2ef3bbfec7a6613de'  # noqa

    #return SW_NO_ERROR, b'\0' + a2b_hex(yubiekey)
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
    #fix a_p after input changed to CBOR
    # application_parameter = cbor_data[0].get(1)
    # challenge_parameter = cbor_data[0].get(1)


    # print("*****321***")
    # print(b2a_hex(clientDataHash))

    #oldU2F code
    # kh = _generate_new_key_handle(application_parameter)
    # sk, pk = _get_key_pair(application_parameter, kh)

    #covert to COSE
    # pk_cose = CoseKey.for_alg(-7).from_ctap1(pk)
    # sk_cose = CoseKey.for_alg(-7).from_ctap1(sk)
    # print("pk_Cose")
    # print(pk_Cose)

    # data_to_sign = b''.join([
    #     b'\x00',
    #     application_parameter,
    #     challenge_parameter,
    #     kh,
    #     pk,
    # ])

    # print('pk =', pk.hex())
    # print('data_to_sign =', data_to_sign.hex())
    # print('signature =', signature.hex())

    # result = b''.join([
    #     b'\x05',
    #     pk,
    #     b'\x40',
    #     kh,
    #     u2fcrypto.x509encode_p256ecdsa_publickey(pk),
    #     signature,
    # # ])
    # print("U2F CODE")
    # # print(u2fcrypto.x509encode_p256ecdsa_publickey(pk))
    # # print(signature)
    # print("U2F CODE")
    #END oldU2Fcode

    #request example:
    # (
    #  {1: b'\x11C\x93\xae\xfb8\xc4\x1c$\xa9~\xf9\xf622\xfcde\xc2y}\x05Rb\x87v\x9b7\x9f\x96\xb2\xe1',
    #   2: {'name': 'Example RP', 'id': 'example.com'},
    #   3: {'name': 'A. User', 'id': b'user_id'},
    #   4: [{'alg': -7, 'type': 'public-key'}]
    #  },
    #  b'')

    #create Att_Data
    # auth_data = a2b_hex(
    #     b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE124100000003F8A011F38C0A4D15800617111F9EDC7D004060A386206A3AACECBDBB22D601853D955FDC5D11ADFBD1AA6A950D966B348C7663D40173714A9F987DF6461BEADFB9CD6419FFDFE4D4CF2EEC1AA605A4F59BDAA50102032620012158200EDB27580389494D74D2373B8F8C2E8B76FA135946D4F30D0E187E120B423349225820E03400D189E85A55DE9AB0F538ED60736EB750F5F0306A80060FE1B13010560D')  # noqa
    #
    # auth_data2 = b''.join([
    #     b2a_hex(cbor_data[0].get(1)), #RP ID HASH
    #     #b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12'  # param
    #     b'41',  # FLAG
    #     b'00000003',  # counter
    #     b'f8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290'
    # ])
       #b'F8A011F38C0A4D15800617111F9EDC7D004060A386206A3AACECBDBB22D601853D955FDC5D11ADFBD1AA6A950D966B348C7663D40173714A9F987DF6461BEADFB9CD6419FFDFE4D4CF2EEC1AA605A4F59BDAA50102032620012158200EDB27580389494D74D2373B8F8C2E8B76FA135946D4F30D0E187E120B423349225820E03400D189E85A55DE9AB0F538ED60736EB750F5F0306A80060FE1B13010560D'

    #Attested Cred. data
    # _ATT_CRED_DATA = a2b_hex(
    #     'f8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290')  # noqa

    _AAGUID = b'f8a011f38c0a4d15800617111f9edc7d'
    _CRED_ID = b'fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783'  # noqa
    # _PUB_KEY = {1: 2, #EC2 key type
    #             3: -7, #ES256 signature algorithm
    #             -1: 1, #P-256 curve
    #             -2: a2b_hex('643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf'), #x-coordinate as byte string 32 bytes in length
    #             -3: a2b_hex('171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290')}  # noqa #y-coordinate as byte string 32 bytes in length
    #
    #
    # _ES256_KEY = a2b_hex(
    #     b'A5010203262001215820A5FD5CE1B1C458C530A54FA61B31BF6B04BE8B97AFDE54DD8CBB69275A8A1BE1225820FA3A3231DD9DEED9D1897BE5A6228C59501E4BCD12975D3DFF730F01278EA61C')  # noqa
    #
    # pubkey = CoseKey.parse(cbor.loads(_ES256_KEY)[0])
    #
    # # ])
    # print("U2F CODE")
    # print(pk_cose)
    # print(pubkey)
    # print("U2F CODE")

    #SCARY CRYPTO STUFF
    # private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    # ROMAN_KEY = private_key
    # private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    private_key = ROMAN_KEY
    public_key = private_key.public_key()

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
    print(cbor_data[0].get(2))
    RP_ID = cbor_data[0].get(2).get('id')
    print()
    print(RP_ID)
    print()
    RP_ID_hash = private_key.sign(str.encode(RP_ID), ec.ECDSA(hashes.SHA256()))
    print(b2a_hex(RP_ID_hash))

    import hashlib
    RP_ID_hash = hashlib.sha256(str.encode(RP_ID)).digest()
    print(b2a_hex(RP_ID_hash))

    auth_data = b''.join([
        b2a_hex(RP_ID_hash), #RP ID HASH
        #b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12'  # RP ID HASH
        b'41',  # FLAG
        b'00000003',  # counter
        attest_cred_data
        #b'f8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290'
    ])

    #ATT_STMT
    #sig_new = u2fcrypto.generate_sha256_p256ecdsa_signature( a2b_hex(auth_data3) + cbor_data[0].get(1), sk) #RP ID HASH

    # statement = {
    #     'alg': -7,
    #     'sig': a2b_hex(
    #         b'304502200D15DAF337D727AB4719B4027114A2AC43CD565D394CED62C3D9D1D90825F0B3022100989615E7394C87F4AD91F8FDAE86F7A3326DF332B3633DB088AAC76BFFB9A46B'),
    #     # noqa
    #     'x5c': [a2b_hex(
    #         b'308202B73082019FA00302010202041D31330D300D06092A864886F70D01010B0500302A3128302606035504030C1F59756269636F2050726576696577204649444F204174746573746174696F6E301E170D3138303332383036333932345A170D3139303332383036333932345A306E310B300906035504061302534531123010060355040A0C0959756269636F20414231223020060355040B0C1941757468656E74696361746F72204174746573746174696F6E3127302506035504030C1E59756269636F205532462045452053657269616C203438393736333539373059301306072A8648CE3D020106082A8648CE3D030107034200047D71E8367CAFD0EA6CF0D61E4C6A416BA5BB6D8FAD52DB2389AD07969F0F463BFDDDDDC29D39D3199163EE49575A3336C04B3309D607F6160C81E023373E0197A36C306A302206092B0601040182C40A020415312E332E362E312E342E312E34313438322E312E323013060B2B0601040182E51C0201010404030204303021060B2B0601040182E51C01010404120410F8A011F38C0A4D15800617111F9EDC7D300C0603551D130101FF04023000300D06092A864886F70D01010B050003820101009B904CEADBE1F1985486FEAD02BAEAA77E5AB4E6E52B7E6A2666A4DC06E241578169193B63DADEC5B2B78605A128B2E03F7FE2A98EAEB4219F52220995F400CE15D630CF0598BA662D7162459F1AD1FC623067376D4E4091BE65AC1A33D8561B9996C0529EC1816D1710786384D5E8783AA1F7474CB99FE8F5A63A79FF454380361C299D67CB5CC7C79F0D8C09F8849B0500F6D625408C77CBBC26DDEE11CB581BEB7947137AD4F05AAF38BD98DA10042DDCAC277604A395A5B3EAA88A5C8BB27AB59C8127D59D6BBBA5F11506BF7B75FDA7561A0837C46F025FD54DCF1014FC8D17C859507AC57D4B1DEA99485DF0BA8F34D00103C3EEF2EF3BBFEC7A6613DE')]
    #     # noqa
    #   # 'x5c': [a2b_hex(
    #     # 4D494943476A434341634367417749424167494A414D5564567A72302F5855624D416F4743437147534D343942414D434D476778437A414A42674E56424159540A416B52464D517377435159445651514944414A455254454C4D416B47413155454277774352455578437A414A42674E5642416F4D416B52464D517377435159440A5651514C44414A455254454C4D416B474131554541777743524555784744415742676B71686B69473977304243514557435552465145526C4C6D4E76625441650A467730784F4441344D6A45784E4451334D444A61467730784F4441354D6A41784E4451334D444A614D476778437A414A42674E5642415954416B52464D5173770A435159445651514944414A455254454C4D416B47413155454277774352455578437A414A42674E5642416F4D416B52464D517377435159445651514C44414A450A5254454C4D416B474131554541777743524555784744415742676B71686B69473977304243514557435552465145526C4C6D4E766254425A4D424D47427971470A534D34394167454743437147534D34394177454841304941424F61426934453448646D4C72346C6C62515844456838635545394C526B644378674C4938314A320A59466F44646B70335345303364614F76695378416C69594B2F5A57393178475037513742315546714331647345772B6A557A42524D42304741315564446751570A424253784B37446E3652354737446B4B506565373478306D784C4473477A416642674E5648534D4547444157674253784B37446E3652354737446B4B506565370A3478306D784C4473477A415042674E5648524D4241663845425441444151482F4D416F4743437147534D343942414D43413067414D455543495143476D6130470A4F6C642B4B306769526365312F375458537144367A4963502B6E5A4C4B4B316E6849316B354149674857705669584130426D6C7454566442394D357136496D620A33425A7A4752612F637370555A4D51426171733D)]
    # }

    # print("sig")
    # print(a2b_hex(auth_data3))
    # print(cbor_data[0].get(1))
    # #print(sig_new)
    # print("AND")
    # print(a2b_hex(
    #         b'304502200D15DAF337D727AB4719B4027114A2AC43CD565D394CED62C3D9D1D90825F0B3022100989615E7394C87F4AD91F8FDAE86F7A3326DF332B3633DB088AAC76BFFB9A46B'),
    #     )

    #pub_key.verify(auth_data + client_data_hash, statement['sig'])
    # key.verify(
    #     a2b_hex(b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12010000002C' +  # noqa
    #             b'7B89F12A9088B0F5EE0EF8F6718BCCC374249C31AEEBAEB79BD0450132CD536C'),  # noqa
    #     a2b_hex(
    #         b'304402202B3933FE954A2D29DE691901EB732535393D4859AAA80D58B08741598109516D0220236FBE6B52326C0A6B1CFDC6BF0A35BDA92A6C2E41E40C3A1643428D820941E0')
    #     # noqa
    # )

    # msg1 = a2b_hex(b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12010000002C' + b'7B89F12A9088B0F5EE0EF8F6718BCCC374249C31AEEBAEB79BD0450132CD536C')
    # sig1 = a2b_hex(b'304402202B3933FE954A2D29DE691901EB732535393D4859AAA80D58B08741598109516D0220236FBE6B52326C0A6B1CFDC6BF0A35BDA92A6C2E41E40C3A1643428D820941E0')
    # print("*XXXX*")
    # print(pubkey.verify(msg1, sig1))

    # msg2 = b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12010000002C' + b'7B89F12A9088B0F5EE0EF8F6718BCCC374249C31AEEBAEB79BD0450132CD536C'

    # signature = u2fcrypto.generate_sha256_p256ecdsa_signature(sk, msg2)
    # x509cert = u2fcrypto.x509encode_p256ecdsa_publickey(pk)


    #SIGNATURE
    #find clientDataHash from request
    clientDataHash = cbor_data[0].get(1)

    # data_to_sign = auth_data + client_data_hash
    # data_to_sign = b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12010000002C' + b'7B89F12A9088B0F5EE0EF8F6718BCCC374249C31AEEBAEB79BD0450132CD536C'
    data_to_sign = a2b_hex(auth_data) + clientDataHash
    attStmt_signature_ = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))
    # print("***678***")
    # print(b2a_hex(signature))
    # print(b2a_hex(data_to_sign))

    #CERTIFICATE x509
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime
    from cryptography.hazmat.primitives import serialization
    # from cryptography.hazmat.primitives import hashes
    # from cryptography.hazmat.backends import default_backend
    #
    #
    # one_day = datetime.timedelta(1, 0, 0)
    # builder = x509.CertificateBuilder()
    # builder = builder.subject_name(x509.Name([
    #     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
    # ]))
    # builder = builder.issuer_name(x509.Name([
    #     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
    # ]))
    # builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    # builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    # builder = builder.serial_number(x509.random_serial_number())
    # builder = builder.public_key(public_key)
    # builder = builder.add_extension(
    #     x509.SubjectAlternativeName(
    #         [x509.DNSName(u'cryptography.io')]
    #     ),
    #     critical=False
    # )
    # builder = builder.add_extension(
    #     x509.BasicConstraints(ca=False, path_length=None), critical=True,
    # )
    # attStmt_certificate = builder.sign(
    #     private_key=private_key, algorithm=hashes.SHA256(),
    #     backend=default_backend()
    # )
    # # isinstance(certificate, x509.Certificate)
    #
    #
    # # print(b2a_hex(attStmt_certificate.public_bytes(serialization.Encoding.DER)))

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
        private_key.public_key()
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
    ).sign(private_key, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    # with open("path/to/certificate.pem", "wb") as f:
    #     f.write(cert.public_bytes(serialization.Encoding.PEM))
    # print(cert.public_bytes(serialization.Encoding.DER))
    attStmt_certificate = cert


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

    client_param = a2b_hex(b'985B6187D042FB1258892ED637CEC88617DDF5F6632351A545617AA2B75261BF')  # noqa

    yubiekey_intercept = b'a301667061636b65640258c4a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947410000017ff8a011f38c0a4d15800617111f9edc7d0040594be3e4870939502dac19942b4add26889b33270fd69808214e50c094f8a85688b6011fbe6688a18b1f4d069e539ceff70db365284144f939e06123dacb69cca50102032620012158208c4c417e6d5d4e3c6a9bf9bf4d558e3cfae38d4ac3240a277495cf7e10f5af6f22582088ba61b3002ddd4fbeac0e72ee5aaf50f1c5f42c62275900cf863262565a8c5903a363616c67266373696758473045022100f2c9ffa93449a09682cdde75a42a7d3f186392e03076b0d1c10efa4197f8a2ad022059f4e54600738dc5107f6dd06bc427accc4cad8be9ac6feb35fd129ac82bea9c63783563815902c2308202be308201a6a00302010202047486fdc2300d06092a864886f70d01010b0500302e312c302a0603550403132359756269636f2055324620526f6f742043412053657269616c203435373230303633313020170d3134303830313030303030305a180f32303530303930343030303030305a306f310b300906035504061302534531123010060355040a0c0959756269636f20414231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3128302606035504030c1f59756269636f205532462045452053657269616c20313935353030333834323059301306072a8648ce3d020106082a8648ce3d03010703420004955df3adf7247d3175effd9cc4f31a4e878ebae18109566150fb388b2e5f6527bf57409aa581a50d0ac52f18445c0a13548a1353c8a4e59a704e523bc04debeda36c306a302206092b0601040182c40a020415312e332e362e312e342e312e34313438322e312e313013060b2b0601040182e51c0201010404030205203021060b2b0601040182e51c01010404120410f8a011f38c0a4d15800617111f9edc7d300c0603551d130101ff04023000300d06092a864886f70d01010b05000382010100315c4880e69a527e386689bd69fd0aa86f49eb9e4e854541556faad00b3a008a1ddc01f96c76f668361a91e232c810a79c63074c9b6e7a46eb1db5d85c44489f868a7643d22a5c862ec03f03e5848be3807d7acd55f8e1ae1ee213ac73ab4b20e3fbd5268cb07b8780271d1f4be0e5ddac734d3a5897bd4d73ba7f357ea208c99d8a4d2902e6097a005c4dc904dc0a18120e0af7d00cfc969a2886e5b1b161f3edcbc677a678d7fb53039ccda186be34ba53319523439d7fd94a70f230621b93c4ce4268d3174d943bc6ae3fc937c2de43d6b44e21153df850925f9590622ebc46e0eb18c641f0fe7e6f2a09a9b2907719f62e6135a19032a213c098b7283cee'
    ATT_OBJ = b'a301667061636b65640258c40021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae124100000003f8a011f38c0a4d15800617111f9edc7d004060a386206a3aacecbdbb22d601853d955fdc5d11adfbd1aa6a950d966b348c7663d40173714a9f987df6461beadfb9cd6419ffdfe4d4cf2eec1aa605a4f59bdaa50102032620012158200edb27580389494d74d2373b8f8c2e8b76fa135946d4f30d0e187e120b423349225820e03400d189e85a55de9ab0f538ed60736eb750f5f0306a80060fe1b13010560d03a363616c6726637369675847304502200d15daf337d727ab4719b4027114a2ac43cd565d394ced62c3d9d1d90825f0b3022100989615e7394c87f4ad91f8fdae86f7a3326df332b3633db088aac76bffb9a46b63783563815902bb308202b73082019fa00302010202041d31330d300d06092a864886f70d01010b0500302a3128302606035504030c1f59756269636f2050726576696577204649444f204174746573746174696f6e301e170d3138303332383036333932345a170d3139303332383036333932345a306e310b300906035504061302534531123010060355040a0c0959756269636f20414231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3127302506035504030c1e59756269636f205532462045452053657269616c203438393736333539373059301306072a8648ce3d020106082a8648ce3d030107034200047d71e8367cafd0ea6cf0d61e4c6a416ba5bb6d8fad52db2389ad07969f0f463bfdddddc29d39d3199163ee49575a3336c04b3309d607f6160c81e023373e0197a36c306a302206092b0601040182c40a020415312e332e362e312e342e312e34313438322e312e323013060b2b0601040182e51c0201010404030204303021060b2b0601040182e51c01010404120410f8a011f38c0a4d15800617111f9edc7d300c0603551d130101ff04023000300d06092a864886f70d01010b050003820101009b904ceadbe1f1985486fead02baeaa77e5ab4e6e52b7e6a2666a4dc06e241578169193b63dadec5b2b78605a128b2e03f7fe2a98eaeb4219f52220995f400ce15d630cf0598ba662d7162459f1ad1fc623067376d4e4091be65ac1a33d8561b9996c0529ec1816d1710786384d5e8783aa1f7474cb99fe8f5a63a79ff454380361c299d67cb5cc7c79f0d8c09f8849b0500f6d625408c77cbbc26ddee11cb581beb7947137ad4f05aaf38bd98da10042ddcac277604a395a5b3eaa88a5c8bb27ab59c8127d59d6bbba5f11506bf7b75fda7561a0837c46f025fd54dcf1014fc8d17c859507ac57d4b1dea99485df0ba8f34d00103c3eef2ef3bbfec7a6613de'  # noqa

    #return SW_NO_ERROR, b'\0' + a2b_hex(yubiekey)
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

    #OLD U2F CODE
    # sk, pk = _get_key_pair(application_parameter, key_handle)
    # counter = INCR_CNT().to_bytes(4, 'big')
    # data_to_sign = b''.join([
    #     application_parameter,
    #     b'\x01',
    #     counter,
    #     challenge_parameter,
    # ])
    # signature = u2fcrypto.generate_sha256_p256ecdsa_signature(sk, data_to_sign)
    # result = b''.join([
    #     b'\x01',
    #     counter,
    #     signature
    # ])

    #ROMAN
    #REQUEST EXAMPLE:
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

    auth_data = b''.join([
        b2a_hex(cbor_data[0].get(2)), #RP ID HASH
        #b'0021F5FC0B85CD22E60623BCD7D1CA48948909249B4776EB515154E57B66AE12'  # RP ID HASH
        b'01',  # FLAG
        b'00000001',  # counter
        #attest_cred_data
        #b'f8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a5290'
    ])

    # credential =  {
    #     'id': b'\xfe:\xac\x03m\x14\xc1\xe1\xc6U\x18\xb6\x98\xdd\x1d\xa8\xf5\x96\xbc3\xe1\x10r\x814f\xc6\xbf8Ei\x15\t\xb8\x0f\xb7mY0\x9b\x8d9\xe0\xa94Rh\x8fl\xa3\xa3\x9av\xf3\xfcRtO\xb79H\xb1W\x83',
    #     'type': 'public-key'
    # }

    # assert_cbor = {
    #     'credential': userEntity,
    #     'auth_data': a2b_hex(auth_data),
    #     'signature': b'304402206765cbf6e871d3af7f01ae96f06b13c90f26f54b905c5166a2c791274fc2397102200b143893586cc799fba4da83b119eaea1bd80ac3ce88fcedb3efbd596a1f4f63'
    # }
    # print("****ROMAN_KEY**")
    # print(ROMAN_KEY)

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

    asser_obj2 = cbor2hex(assert_cbor2)
    # print(a2b_hex(asser_obj2))
    _GA_RESP = b'a301a26269645840fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b1578364747970656a7075626c69632d6b6579025900250021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12010000001d035846304402206765cbf6e871d3af7f01ae96f06b13c90f26f54b905c5166a2c791274fc2397102200b143893586cc799fba4da83b119eaea1bd80ac3ce88fcedb3efbd596a1f4f63'
    # print(a2b_hex(_GA_RESP))
    _YU_RESP = b'a301a262696458400ca932ae6a47ec9fa8c8156a6559b00b9d6815930c951116ac66e39faa9632c634d9e932db7644ace66f1143163c22fe0c8c2df272d42d9e3db3bba572e96dd764747970656a7075626c69632d6b6579025825a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce194701000001b70358473045022100ee7def8a5c5bd170f0cdfdb9e6c278fd660c1f97a0045c298ca106dfd33cef3202202f42c9d55bf945550a74bdb21c0e43b9c8bf8d4899f5f7f6a2e8cb4d967fd983'
    return SW_NO_ERROR, b'\0' + a2b_hex(asser_obj2)
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

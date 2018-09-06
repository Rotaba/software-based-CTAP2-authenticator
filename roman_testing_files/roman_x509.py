from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

one_day = datetime.timedelta(1, 0, 0)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from fido2.cose import CoseKey, ES256, RS256, UnsupportedKey
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend() )
public_key = private_key.public_key()

# private_key = rsa.generate_private_key(
#      public_exponent=65537,
#      key_size=2048,
#      backend=default_backend()
#  )
# public_key = private_key.public_key()
builder = x509.CertificateBuilder()
builder = builder.subject_name(x509.Name([
     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
 ]))
builder = builder.issuer_name(x509.Name([
     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
 ]))
builder = builder.not_valid_before(datetime.datetime.today() - one_day)
builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
builder = builder.serial_number(x509.random_serial_number())
builder = builder.public_key(public_key)
builder = builder.add_extension(
     x509.SubjectAlternativeName(
         [x509.DNSName(u'cryptography.io')]
     ),
     critical=False
 )
builder = builder.add_extension(
     x509.BasicConstraints(ca=False, path_length=None), critical=True,
 )
certificate = builder.sign(
     private_key=private_key, algorithm=hashes.SHA256(),
     backend=default_backend()
 )
isinstance(certificate, x509.Certificate)
from binascii import b2a_hex, a2b_hex
from cryptography.hazmat.primitives import serialization
print( b2a_hex (certificate.public_bytes(serialization.Encoding.DER)) )
# example_x5c =  [a2b_hex(
#     b'308202B73082019FA00302010202041D31330D300D06092A864886F70D01010B0500302A3128302606035504030C1F59756269636F2050726576696577204649444F204174746573746174696F6E301E170D3138303332383036333932345A170D3139303332383036333932345A306E310B300906035504061302534531123010060355040A0C0959756269636F20414231223020060355040B0C1941757468656E74696361746F72204174746573746174696F6E3127302506035504030C1E59756269636F205532462045452053657269616C203438393736333539373059301306072A8648CE3D020106082A8648CE3D030107034200047D71E8367CAFD0EA6CF0D61E4C6A416BA5BB6D8FAD52DB2389AD07969F0F463BFDDDDDC29D39D3199163EE49575A3336C04B3309D607F6160C81E023373E0197A36C306A302206092B0601040182C40A020415312E332E362E312E342E312E34313438322E312E323013060B2B0601040182E51C0201010404030204303021060B2B0601040182E51C01010404120410F8A011F38C0A4D15800617111F9EDC7D300C0603551D130101FF04023000300D06092A864886F70D01010B050003820101009B904CEADBE1F1985486FEAD02BAEAA77E5AB4E6E52B7E6A2666A4DC06E241578169193B63DADEC5B2B78605A128B2E03F7FE2A98EAEB4219F52220995F400CE15D630CF0598BA662D7162459F1AD1FC623067376D4E4091BE65AC1A33D8561B9996C0529EC1816D1710786384D5E8783AA1F7474CB99FE8F5A63A79FF454380361C299D67CB5CC7C79F0D8C09F8849B0500F6D625408C77CBBC26DDEE11CB581BEB7947137AD4F05AAF38BD98DA10042DDCAC277604A395A5B3EAA88A5C8BB27AB59C8127D59D6BBBA5F11506BF7B75FDA7561A0837C46F025FD54DCF1014FC8D17C859507AC57D4B1DEA99485DF0BA8F34D00103C3EEF2EF3BBFEC7A6613DE')]

#SELF SIGNED CERT
# Various details about who we are. For a self-signed certificate the
# subject and issuer are always the same.
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
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
    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    critical=False,
# Sign our certificate with our private key
).sign(private_key, hashes.SHA256(), default_backend())
# Write our certificate out to disk.
# with open("path/to/certificate.pem", "wb") as f:
#     f.write(cert.public_bytes(serialization.Encoding.PEM))
print(cert.public_bytes(serialization.Encoding.DER))
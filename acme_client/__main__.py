from http.server import HTTPServer
from threading import Thread
import cryptography.x509
from cryptography.x509.oid import NameOID
from dnslib.server import DNSServer

from acme_client.http01_handler import HTTP01Handler
from acme_client.dns01_handler import DNS01Handler

import json
import base64
import argparse
import requests
from cryptography.hazmat.primitives import hashes
import ssl

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

import math
import hashlib
import time

private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
private_csr_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
public_key = private_key.public_key()
e = public_key.public_numbers().e
n = public_key.public_numbers().n
e_b = e.to_bytes(math.ceil(e.bit_length() /8))
n_b = n.to_bytes(math.ceil(n.bit_length() /8))
e_64 = base64.urlsafe_b64encode(e_b).decode().rstrip("=")
n_64 = base64.urlsafe_b64encode(n_b).decode().rstrip("=")

file = open('acme_client/key.pem','wb')
file.write(private_csr_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format = serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()))
file.close()
def jws(payload,header):
    p_b64 = ""
    if(payload != ""):
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode().rstrip("=")
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).decode().rstrip("=")
    signature = h_b64+"."+p_b64
    b_sig= signature.encode("utf-8")
    signed = private_key.sign(
        b_sig,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    rs256 = base64.urlsafe_b64encode(signed).decode().rstrip("=")

    final_msg = {"protected":h_b64,"payload":p_b64,"signature":rs256}
    return json.dumps(final_msg).encode()

certifacte_path = './project/pebble.minica.pem'


def get_nonce(url):
    head = requests.head(url,verify= certifacte_path)
    if head.status_code == 200:
        header = head.headers
        nonce = header["Replay-Nonce"]
    else:
        print("dis wallah")
    return nonce

def create_header(jwk,nonce,url,kid = 0):
    if jwk:
        jwk = {"kty":"RSA","n":n_64,"e":e_64}
        header = {"alg":"RS256","jwk":jwk,"nonce":nonce,"url":url}
        return header
    else:
        header = {"alg":"RS256","kid":kid,"nonce":nonce,"url":url}
        return header

def get_new_account(url,nonce):
    payload = {"termsOfServiceAgreed":True}
    new_account_response = requests.post(url,
                                         headers={"Content-Type": "application/jose+json"},
                                         data= jws(payload,create_header(True,nonce,url)),
                                         verify= certifacte_path)
    if(new_account_response.status_code != 200 and new_account_response.status_code != 201):
        print(new_account_response.status_code)
    account = new_account_response.headers["location"]
    nonce = new_account_response.headers["Replay-Nonce"]
    return account, nonce

def get_chals(url,nonce,chal_type,kid):
    response = requests.post(url,
                             headers={"Content-Type": "application/jose+json"},
                             data = jws("",create_header(False,nonce,url,kid)),
                             verify = certifacte_path)
    nonce = response.headers["Replay-Nonce"]
    challenges = json.loads(response.text)["challenges"]
    if chal_type == "http01":
        chal_type = "http-01"
    else:
        chal_type = "dns-01"
    chal = next((challenge for challenge in challenges if challenge["type"] == chal_type),None)
    return chal,nonce

def dns_key_auth(domain_name,jwk,token,dns):
    compacted = json.dumps(jwk,separators=(',', ':'))
    thumbprint = hashlib.sha256(compacted.encode()).digest()
    thumbprint_b64 = base64.urlsafe_b64encode(thumbprint).decode().rstrip('=')
    key_authorization = f"{token}.{thumbprint_b64}"
    key_authorization = hashlib.sha256(key_authorization.encode()).digest()
    key_authorization = base64.urlsafe_b64encode(key_authorization).decode().rstrip('=')
    record = f"_acme-challenge.{domain_name}. 300 IN TXT \"{key_authorization}\""
    dns.records[f"_acme-challenge.{domain_name}."] = record
    return

def dns_chal(url, domain_name, nonce, token,jwk,kid,auth,dns):
    compacted = json.dumps(jwk,separators=(',', ':'))
    thumbprint = hashlib.sha256(compacted.encode()).digest()
    thumbprint_b64 = base64.urlsafe_b64encode(thumbprint).decode().rstrip('=')
    key_authorization = f"{token}.{thumbprint_b64}"
    key_authorization = hashlib.sha256(key_authorization.encode()).digest()
    key_authorization = base64.urlsafe_b64encode(key_authorization).decode().rstrip('=')
    record = f"300 IN TXT \"{key_authorization}\""
    dns.records["TXT"] = record
    dns_chal_response = requests.post(url,
                             headers={"Content-Type": "application/jose+json"},
                             data = jws({},create_header(False,nonce,url,kid)),
                             verify = certifacte_path)
    nonce = dns_chal_response.headers["Replay-Nonce"]
    status = "pending"
    while(status == "pending"):
        time.sleep(5)
        response = requests.post(auth,
                            headers={"Content-Type": "application/jose+json"},
                            data = jws("",create_header(False,nonce,auth,kid)),
                            verify = certifacte_path)
        status = json.loads(response.text)["status"]
        nonce = response.headers["Replay-Nonce"]
    dns.records.pop("TXT")
    return nonce 

def http_chal(url,nonce, token,jwk,kid,auth,http):
    compacted = json.dumps(jwk,separators=(',', ':'))
    thumbprint = hashlib.sha256(compacted.encode()).digest()
    thumbprint_b64 = base64.urlsafe_b64encode(thumbprint).decode().rstrip('=')
    key_authorization = f"{token}.{thumbprint_b64}"
    http.token = token
    http.key_auth = key_authorization
    http_chal_response = requests.post(url,
                             headers={"Content-Type": "application/jose+json"},
                             data = jws({},create_header(False,nonce,url,kid)),
                             verify = certifacte_path)
    nonce = http_chal_response.headers["Replay-Nonce"]
    status = "pending"
    while(status == "pending"):
        time.sleep(5)
        response = requests.post(auth,
                            headers={"Content-Type": "application/jose+json"},
                            data = jws("",create_header(False,nonce,auth,kid)),
                            verify = certifacte_path)
        status = json.loads(response.text)["status"]
        nonce = response.headers["Replay-Nonce"]
    return nonce

if __name__ == "__main__":
    # Hint: You may want to start by parsing command line arguments and
    # perform some sanity checks first. The built-in `argparse` library will suffice.
    parser = argparse.ArgumentParser()
    parser.add_argument("challenge",choices=["dns01", "http01"])
    parser.add_argument("--dir", required= True)
    parser.add_argument("--record", required= True)
    parser.add_argument("--domain", required=True, action='append')
    parser.add_argument("--revoke", required= False, action='store_true')
    args = parser.parse_args()

    http_handler = HTTP01Handler
    http01_server = HTTPServer((args.record, 5002), http_handler)
    dns_handler = DNS01Handler({"A": args.record})
    dns01_server = DNSServer(dns_handler, port=10053, address=args.record)
    # Hint: You will need more HTTP servers

    http01_thread = Thread(target = http01_server.serve_forever)
    dns01_thread = Thread(target = dns01_server.server.serve_forever)
    http01_thread.daemon = True
    dns01_thread.daemon = True

    http01_thread.start()
    dns01_thread.start()

    # Your code should go here
    challenge = args.challenge
    direct = args.dir
    record = args.record
    domain = args.domain
    revoke = args.revoke
    
    first_query = requests.get(direct,verify=certifacte_path)
    nonce_url = direct.replace("/dir", "/nonce-plz")
    nonce = get_nonce(nonce_url)

    new_account_url = direct.replace("/dir", "/sign-me-up")
    kid,nonce = get_new_account(new_account_url,nonce)

    order_url = direct.replace("/dir", "/order-plz")
    header = {"alg":"RS256","kid":kid,"nonce":nonce,"url":order_url}
    identifiers = []
    for i in range(len(domain)):
        dom = domain[i]
        identifiers.append({"type": "dns", "value": dom})
    payload = {"identifiers": identifiers}
    order_final = jws(payload,header)
    order = requests.post(url=order_url, headers={"Content-Type": "application/jose+json"}, data= order_final,verify= certifacte_path)
    nonce = order.headers["Replay-Nonce"]
    my_order = order.headers["location"]
    authz = json.loads(order.text)["authorizations"]
    finalize = json.loads(order.text)["finalize"]

    if challenge == "dns01":
        for i in range(len(authz)):
            a = 0
        for i in range(len(authz)):
            auth = authz[i]
            domain_name = domain[i]
            chal,nonce = get_chals(auth,nonce,challenge,kid)
            nonce = dns_chal(chal["url"],domain_name,nonce,chal["token"],{"e":e_64,"kty":"RSA","n":n_64},kid,auth,dns_handler)
    else:
        for i in range(len(authz)):
            auth = authz[i]
            domain_name = domain[i]
            chal,nonce = get_chals(auth,nonce,challenge,kid)
            nonce = http_chal(chal["url"],nonce,chal["token"],{"e":e_64,"kty":"RSA","n":n_64},kid,auth,http_handler)
    
    names = []
    for i in domain:
        names.append(cryptography.x509.DNSName(i))
    csr = cryptography.x509.CertificateSigningRequestBuilder()
    csr = csr.subject_name(cryptography.x509.Name([cryptography.x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),]))
    csr = csr.add_extension(cryptography.x509.SubjectAlternativeName(names),False)
    csr = csr.sign(private_csr_key,hashes.SHA256())
    b64_csr = base64.urlsafe_b64encode(csr.public_bytes(serialization.Encoding.DER)).decode().rstrip('=')
    payload = {"csr":b64_csr}

    road_to_certif = requests.post(url = finalize,headers={"Content-Type": "application/jose+json"},
                                   data=jws(payload,create_header(False,nonce,finalize,kid)),
                                   verify= certifacte_path)
    
    nonce = road_to_certif.headers["Replay-Nonce"]
    finalize = json.loads(road_to_certif.text)["finalize"]
    status = "processing"
    while(status == "processing"):
        time.sleep(5)
        data = jws("",create_header(False,nonce,my_order,kid)).decode()
        road_to_certif = requests.post(my_order,
                        headers={"Content-Type": "application/jose+json"},
                        data = data,
                        verify = certifacte_path)
        nonce = road_to_certif.headers["Replay-Nonce"]
        status = json.loads(road_to_certif.text)["status"]
    certif_url = json.loads(road_to_certif.text)["certificate"]
    certificate = requests.post(certif_url,
                                headers={"Content-Type": "application/jose+json"},
                                data = jws("",create_header(False,nonce,certif_url,kid)).decode(),
                                verify= certifacte_path)
    nonce = certificate.headers["Replay-Nonce"]
    file = open('acme_client/cert.pem', 'w')
    file.write(certificate.text)
    file.close()

    if(revoke):
        revoke_url = direct.replace("/dir", "/revoke-cert")
        cert =  cryptography.x509.load_pem_x509_certificate(certificate.text.encode())
        der = cert.public_bytes(serialization.Encoding.DER)
        payload = {"certificate": base64.urlsafe_b64encode(der).decode().rstrip('=')}
        revoke_msg = requests.post(revoke_url,
                      headers={"Content-Type": "application/jose+json"},
                      data = jws(payload,create_header(False,nonce,revoke_url,kid)),
                      verify= certifacte_path
                      )
        
    httpd= HTTPServer((record, 5001), HTTP01Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="acme_client/cert.pem", keyfile="acme_client/key.pem")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd_thread= Thread(target = httpd.serve_forever)
    httpd_thread.daemon = True
    httpd_thread.start()
    
    time.sleep(5)
    httpd.shutdown()
    http01_server.shutdown()
    dns01_server.server.shutdown()
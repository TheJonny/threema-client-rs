#!/usr/bin/env python3
import nacl
import nacl.public
import requests
import json
import sys
import base64

API = "https://ds-apip.threema.ch/"
USER_AGENT = "Threema is cool"

class RegistrationFailed(RuntimeError):
    """Identity creation on the Threema servers failed"""
    pass

def register(licensed_template):
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT

    privkey = nacl.public.PrivateKey.generate()
    r1 = s.post(API + "identity/create", json = {"publicKey": privkey.public_key.encode(nacl.encoding.Base64Encoder)})
    r1.raise_for_status()
    j1 = r1.json()
    their = nacl.public.PublicKey(j1["tokenRespKeyPub"], encoder=nacl.encoding.Base64Encoder)

    resp = nacl.public.Box(privkey, their).encrypt(base64.b64decode(j1["token"]), nonce=b"createIdentity response.").ciphertext

    body = {
        "publicKey": privkey.public_key.encode(nacl.encoding.Base64Encoder),
        "token": j1["token"],
        "response": base64.b64encode(resp)}
    body.update(licensed_template)
    r2 = s.post(API + "identity/create", json=body)
    r2.raise_for_status()
    j2 = r2.json()
    if not j2.get("success", False):
        raise RegistrationFailed(str(j2.get("error", "no error message given")))

    save = {"user":{
        "identity": j2["identity"],
        "privatekey":privkey.encode(nacl.encoding.Base64Encoder).decode(),
        "serverGroup":j2["serverGroup"]}}
    return save

if __name__ == "__main__":
    invalid = len(sys.argv) > 2
    help = len(sys.argv) == 2 and sys.argv[1] in ["-h", "--help", "-?", "/?", "/h", "/help"]
    if invalid or help:
        to = sys.stderr if invalid else sys.stdout
        print("usage:",sys.argv[0], "[LICEN-SEKEY]", file=to)
        exit(int(invalid))
    else:
        if len(sys.argv) == 2:
            l = {"licenseKey": sys.argv[1]}
        else:
            l = {}
        save = register(l)
        json.dump(save, sys.stdout)
        print()

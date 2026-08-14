#!/bin/pypy
import EAPModule
from binascii import hexlify
from scapy.layers.eap import EAP, EAPOL

print('Module loaded')
EAPModule.configure_peer('matheus_garbelini', 'testtest', '')

req = EAP(code='Request', id=1, type="Identity")

print('TX ---> ' + req.summary())
res = EAPModule.send_peer_request(raw(req))
pkt = EAP(res)
print('RX <--- ' + pkt.summary())

pkt.show()

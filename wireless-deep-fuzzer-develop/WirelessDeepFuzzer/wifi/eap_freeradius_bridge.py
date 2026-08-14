from scapy.layers.radius import Radius, RadiusAttr_Message_Authenticator, RadiusAttr_State, RadiusAttr_Vendor_Specific, \
    RadiusAttr_EAP_Message, RadiusAttribute
from scapy.layers.eap import EAP
from scapy.compat import raw
import random
import hmac
import hashlib
import string
import socket
import struct
from hashlib import md5
from binascii import unhexlify, hexlify
from scapy.all import Raw, fuzz
import os

radius_userid = None
radius_secret = 'testing123'  # type: str
radius_id = 1
radius_last_pkt = None
radius_last_authenticator = None
freeradius_users_file = '/etc/freeradius/3.0/users'  # Change here if the path doesn't match

UDP_IP = "127.0.0.1"
UDP_PORT = 1812

radius_request_base_pkt = Radius(
    "\x01=\x00?\xd1'`\xec\x05n=\xf9s\xa9W\xd5\x99\xe1\x97%\x01\ntestuserP\x12\xdf\xd2\x9bPE\xdb_\xed\x18u>\x03\xc3\xda\xc5\x0cO\x0f\x02\xd2\x00\r\x01testuser")
radius_challange_base_pkt = None

sock = socket.socket(socket.AF_INET,  # Internet
                     socket.SOCK_DGRAM)  # UDP
sock.settimeout(2.0)  # 2 seconds timeout

seq_xor = lambda c, b: ''.join(
    chr(x) for x in map(lambda X: ord(X[0]) ^ ord(X[1]), zip(c, b))
)


def radius_configure_socket(addr, port):
    UDP_IP = addr
    UDP_PORT = port


def radius_set_userid(userid):
    radius_userid = userid


def radius_update_message_authenticator(radius_packet, secret):
    packed_hdr = struct.pack("!B", radius_packet.code)
    packed_hdr += struct.pack("!B", radius_packet.id)
    packed_hdr += struct.pack("!H", radius_packet.len)

    packed_attrs = b''
    for attr in radius_packet.attributes:
        if type(attr) == RadiusAttr_Message_Authenticator:
            attr.value = bytearray(attr.len)
        packed_attrs += raw(attr)

    payload = packed_hdr + radius_packet.authenticator + packed_attrs

    message_authenticator = hmac.new(secret, payload, hashlib.md5).digest()
    radius_packet[RadiusAttr_Message_Authenticator].value = message_authenticator
    return message_authenticator


def radius_generate_authenticator():
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for x in range(16))


def radius_update_eap_fragments(radius_pkt):
    eap_fragment = b''
    idx = 0
    idxs_to_remove = []
    removed_count = 0

    for attr in radius_pkt.attributes:
        if type(attr) == RadiusAttr_EAP_Message and Raw in attr.value:
            eap_fragment += raw(attr.value)
            idxs_to_remove.append(idx)
        idx += 1

    if len(eap_fragment) > 0:
        for value in idxs_to_remove:
            del radius_pkt.attributes[value - removed_count]
            removed_count += 1

        radius_pkt.attributes.append(RadiusAttr_EAP_Message())
        radius_pkt[RadiusAttr_EAP_Message].value = EAP(eap_fragment)
        radius_pkt[RadiusAttr_EAP_Message].len = len(eap_fragment)


def radius_create_fragmentation(radius_pkt):
    if radius_pkt[RadiusAttr_EAP_Message].len > 255:

        data_total = raw(radius_pkt[RadiusAttr_EAP_Message].value)
        length_total = len(data_total)

        # Delete previous EAP packet
        for idx, value in enumerate(radius_pkt.attributes):
            if type(value) == RadiusAttr_EAP_Message:
                del radius_pkt.attributes[idx]

        # Find the start index for new attributes
        bytes_written = 0
        fragments = length_total / 253
        idx_start = len(radius_pkt.attributes)
        # Create entry for each fragment and update its value and parameters accordingly
        for idx in range(idx_start, idx_start + fragments + 1):
            radius_pkt.attributes.append(RadiusAttr_EAP_Message())
            radius_pkt.attributes[idx].value = Raw(data_total[bytes_written:bytes_written + 253])
            radius_pkt.attributes[idx].len = len(radius_pkt.attributes[idx].value) + 2
            bytes_written += 253
        return True
    else:
        return False


def radius_send_eap_request(eap_pkt):
    global radius_userid
    global radius_id
    global radius_request_base_pkt
    global radius_last_pkt
    global radius_last_authenticator

    if eap_pkt.type == 1 and eap_pkt.code == EAP.RESPONSE:
        radius_userid = eap_pkt.identity
    # radius_request_base_pkt = radius_request_base_pkt.copy()
    radius_request_base_pkt.code = 'Access-Request'
    radius_request_base_pkt.id = radius_id
    radius_id = (radius_id + 1) % 256
    radius_request_base_pkt.authenticator = radius_generate_authenticator()

    radius_request_base_pkt.attributes[0].type = 'User-Name'
    radius_request_base_pkt.attributes[0].len = len(radius_userid) + 2  # size of string + 2 bytes of the header
    radius_request_base_pkt.attributes[0].value = radius_userid

    radius_request_base_pkt[RadiusAttr_EAP_Message].type = 'EAP-Message'
    radius_request_base_pkt[RadiusAttr_EAP_Message].len = len(eap_pkt) + 2  # size of string + 2 bytes of the header
    radius_request_base_pkt[RadiusAttr_EAP_Message].value = eap_pkt

    # If EAP message length is great then 255, fragment eap packets
    fragmented = radius_create_fragmentation(radius_request_base_pkt)
    radius_request_base_pkt.len = len(raw(radius_request_base_pkt))

    radius_update_message_authenticator(radius_request_base_pkt, radius_secret)

    # save last pkt

    # send and receive Radius / EAP
    sock.sendto(raw(radius_request_base_pkt), (UDP_IP, UDP_PORT))
    data, server = sock.recvfrom(4096)
    pkt = Radius(data)

    radius_last_pkt = pkt
    radius_last_authenticator = radius_request_base_pkt.authenticator

    # update state variable
    if radius_request_base_pkt.haslayer(RadiusAttr_State) == False and pkt.haslayer(RadiusAttr_State):
        # If no state is prsent in the base pkt, append to it
        radius_request_base_pkt.attributes.append(pkt[RadiusAttr_State])
    elif pkt.haslayer(RadiusAttr_State):
        # If there's already a state attribute in the base pkt, update it
        radius_request_base_pkt[RadiusAttr_State].value = pkt[RadiusAttr_State].value

    radius_request_base_pkt.len = len(radius_request_base_pkt)

    # Reconstruct eap fragments if they are present (More flag)
    radius_update_eap_fragments(pkt)
    if fragmented:
        radius_update_eap_fragments(radius_request_base_pkt)
    return pkt


def radius_mppe_decrypt(cipher, secret, req_authenticator, pad="\0"):
    salt, C = cipher[0:2], cipher[2:]

    if len(C) % 16 or len(C) > 256:
        raise NameError('Bad encrypted data length')
    if len(req_authenticator) % 16:
        raise NameError('Bad request authenticator')
    if len(salt) != 2 or not ord(salt[0]) & 0x80:
        raise NameError('Bad salt')

    M = []
    h = secret + req_authenticator + salt

    for c in [C[i:i + 16] for i in range(0, len(C), 16)]:
        b = int(hexlify(md5(h).digest()), 16)
        m = unhexlify('%032x' % (b ^ int(hexlify(c), 16)))
        M.append(m)
        h = secret + c

    M = ''.join(M)
    L, clear = ord(M[0]), M[1:]

    if L > len(clear) or len(clear) - L > 15 or clear[L:] != pad * (len(clear) - L):
        raise NameError('Bad clear data')

    return clear[0:L]


def radius_mppe_msk():
    global radius_last_pkt
    global radius_secret
    global radius_last_authenticator
    recv_key = b''
    send_key = b''
    # Search for vendor receiver and send keys
    for attr in radius_last_pkt.attributes:
        if type(attr) == RadiusAttr_Vendor_Specific and attr.vendor_id == 311:  # Microsoft MPPE keys
            if attr.vendor_type == 17:
                recv_key = attr.value
            elif attr.vendor_type == 16:
                send_key = attr.value

    # decrypt them
    a = radius_mppe_decrypt(cipher=recv_key,
                            secret=radius_secret, req_authenticator=radius_last_authenticator)
    b = radius_mppe_decrypt(cipher=send_key,
                            secret=radius_secret, req_authenticator=radius_last_authenticator)
    return a + b


def setup(username, password):
    f = open(freeradius_users_file, "w")
    f.write(username + ' Cleartext-Password := "' + password + '"')
    f.close()
    os.system('service freeradius restart')
    print('Freeradius configured with username: ' + username + ' and password: ' + password)
    pass

# patch
# class EAP_PWD(EAP):
#
#     name = "EAP-pwd"
#     fields_desc = [
#         ByteEnumField("code", 1, eap_codes),
#         ByteField("id", 0),
#         FieldLenField("len", None, fmt="H", length_of="pwd_data",
#                       adjust=lambda pkt, x: len(pkt.value) + 2),
#         ByteEnumField("type", 52, eap_types),
#         XStrLenField("pwd_data", "", length_from=lambda pkt: 0 if pkt.len is None else pkt.len - 5)  # payload must be subtracted from header length (5)
#     ]
#

#
# class EAP_PWD(EAP):
#     """
#     RFC 5931 - "Extensible Authentication Protocol (EAP)"
#     """
#
#     name = "EAP-pwd"
#     fields_desc = [
#         ByteEnumField("code", 1, eap_codes),
#         ByteField("id", 0),
#         FieldLenField("len", None, fmt="H", length_of="pwd_data",
#                       adjust=lambda pkt, x: len(pkt.value) + 2),
#         ByteEnumField("type", 52, eap_types),
#         BitField('L', 0, 1),
#         BitField('M', 0, 1),
#         BitField('pwd_type', 0, 5),
#         ConditionalField(IntField("message_len", 0), lambda pkt: pkt.L == 1),
#         # payload must be subtracted from header length (5)
#         XStrLenField("pwd_data", "", length_from=lambda \
#                      pkt: 0 if pkt.len is None else pkt.len - 5)
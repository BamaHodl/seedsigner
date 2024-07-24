from embit import ec
from embit.util import key as eckey
import array
import binascii
import hmac
import pyaes
import hashlib
import base64
from typing import Union

def append_PKCS7_padding(data: bytes) -> bytes:
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen


def strip_PKCS7_padding(data: bytes) -> bytes:
    if len(data) % 16 != 0 or len(data) == 0:
        raise InvalidPadding("invalid length")
    padlen = data[-1]
    if not (0 < padlen <= 16):
        raise InvalidPadding("invalid padding byte (out of range)")
    for i in data[-padlen:]:
        if i != padlen:
            raise InvalidPadding("invalid padding byte (inconsistent)")
    return data[0:-padlen]


def aes_encrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    data = append_PKCS7_padding(data)
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Encrypter(aes_cbc, padding=pyaes.PADDING_NONE)
    e = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    return e


def aes_decrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Decrypter(aes_cbc, padding=pyaes.PADDING_NONE)
    data = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    try:
        return strip_PKCS7_padding(data)
    except InvalidPadding:
        raise Exception("Invalid Password")


def hmac_oneshot(key: bytes, msg: bytes, digest) -> bytes:
    return hmac.digest(key, msg, digest)


def get_random_key() -> eckey.ECKey:
    ret = eckey.ECKey()
    ret.generate()
    return ret


def pubkey_from_p(p) -> eckey.ECPubKey: 
    ecdh_key = eckey.ECPubKey()
    ecdh_key.p = p
    ecdh_key.compressed=True
    ecdh_key.valid=True
    return ecdh_key

     
def ecies_encrypt_message(ec_pubkey : ec.PublicKey, message: bytes, *, magic: bytes = b'BIE1') -> bytes:
    """
    ECIES encryption/decryption methods; AES-128-CBC with PKCS7 is used as the cipher; hmac-sha256 is used as the mac
    """
    baseKey = eckey.ECPubKey()
    baseKey.set(ec_pubkey.sec())

    ephemeral = get_random_key()
    ecdh_p = eckey.SECP256K1.mul([(baseKey.p, ephemeral.secret)])
    ecdh_key = pubkey_from_p(ecdh_p).get_bytes()
    key = hashlib.sha512(ecdh_key).digest()

    iv, key_e, key_m = key[0:16], key[16:32], key[32:]
    ciphertext = aes_encrypt_with_iv(key_e, iv, message)
    ephemeral_pubkey = ephemeral.get_pubkey()
    encrypted = magic + ephemeral_pubkey.get_bytes() + ciphertext
    mac = hmac_oneshot(key_m, encrypted, hashlib.sha256)
    return base64.b64encode(encrypted + mac)


def ecies_decrypt_message(ec_privkey : ec.PrivateKey, encrypted: Union[str, bytes], *, magic: bytes=b'BIE1') -> bytes:

    baseKey = eckey.ECKey()
    baseKey.set(ec_privkey.secret, True)

    encrypted = base64.b64decode(encrypted)  # type: bytes
    if len(encrypted) < 85:
        raise Exception('invalid ciphertext: length')
    magic_found = encrypted[:4]
    ephemeral_pubkey_bytes = encrypted[4:37]
    ciphertext = encrypted[37:-32]
    mac = encrypted[-32:]
    if magic_found != magic:
        raise Exception('invalid ciphertext: invalid magic bytes')
    ephemeral_pubkey = eckey.ECPubKey()
    ephemeral_pubkey.set(ephemeral_pubkey_bytes)
    if not ephemeral_pubkey.valid:
        raise Exception('invalid ciphertext: invalid ephemeral pubkey')
    ecdh_p = eckey.SECP256K1.mul([(ephemeral_pubkey.p, baseKey.secret)])
    ecdh_key = pubkey_from_p(ecdh_p).get_bytes()
    key = hashlib.sha512(ecdh_key).digest()
    iv, key_e, key_m = key[0:16], key[16:32], key[32:]
    if mac != hmac_oneshot(key_m, encrypted[:-32], hashlib.sha256):
        raise Exception('InvalidPassword')
    return aes_decrypt_with_iv(key_e, iv, ciphertext)

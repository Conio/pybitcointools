# Majority of code taken from reference implementation:
# https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py

# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Reference implementation for Bech32 and segwit addresses."""
import binascii

from bitcoin import encode_pubkey, hash160, SIGHASH_ALL, privkey_to_pubkey, encode, hashlib, sha256

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

BECH32_BITCOIN_PREFIX = 'bc'
BECH32_BITCOIN_TESTNET_PREFIX = 'tb'
BECH32_BITCOIN_REGTEST_PREFIX = 'bcrt'


def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data):
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])


def bech32_decode(bech):
    """Validate a Bech32 string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return None, None
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None, None
    if not all(x in CHARSET for x in bech[pos+1:]):
        return None, None
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    if not bech32_verify_checksum(hrp, data):
        return None, None
    return hrp, data[:-6]


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def _decode(hrp, addr):
    """Decode a segwit address."""
    hrpgot, data = bech32_decode(addr)
    if hrpgot != hrp:
        return None, None
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return None, None
    if data[0] > 16:
        return None, None
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return None, None
    return data[0], decoded


def _encode(hrp, witver, witprog):
    """Encode a segwit address."""
    ret = bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5))
    assert _decode(hrp, ret) is not (None, None)
    return ret


def bech32encode(script: str, prefix=BECH32_BITCOIN_PREFIX):
    from bitcoin.transaction import deserialize_script
    witnessversion, witnessprogram = deserialize_script(script)
    witnessversion = 0 if witnessversion is None else witnessversion
    assert 0 <= witnessversion <= 16
    if witnessversion == 0:
        assert len(witnessprogram) == 40 or len(witnessprogram) == 64
    return _encode(prefix, witnessversion, bytearray(binascii.unhexlify(witnessprogram))).lower()


def int_to_hex(n: int) -> str:
    return binascii.hexlify(chr(n).encode()).decode()


def bech32decode(text: str):
    assert isinstance(text, str)
    from bitcoin import from_int_to_byte
    if text[:4].lower() == BECH32_BITCOIN_REGTEST_PREFIX:
        human_readable_part_size = 4
    elif text[:2].lower() in (
        BECH32_BITCOIN_PREFIX,
        BECH32_BITCOIN_TESTNET_PREFIX
    ):
        human_readable_part_size = 2
    else:
        raise ValueError('Invalid readable part')

    if len(set([t.islower() for t in text if t.isalpha()])) > 1:
        raise ValueError('Mixed case')
    text = text.lower().encode("utf-8").decode()

    witnessversion, wit_ordnallist = _decode(text[:human_readable_part_size], text)
    if witnessversion is None and wit_ordnallist is None:
        raise ValueError('Exception with %s (prefix: %s)' % (text, text[:human_readable_part_size]))
    if not witnessversion:
        assert len(wit_ordnallist) == 20 or len(wit_ordnallist) == 32
    o = ""
    for ordinal in wit_ordnallist:
        o += binascii.hexlify(from_int_to_byte(ordinal)).decode()
    return int_to_hex(witnessversion + 0x50 if witnessversion else 0) + int_to_hex(int(len(o) / 2)) + o


def pubkey_to_bech32_address(pubkey, prefix=BECH32_BITCOIN_PREFIX):
    if isinstance(pubkey, (list, tuple)):
        pubkey = encode_pubkey(pubkey, 'bin')
    if len(pubkey) in [66, 130]:
        pubkey = binascii.unhexlify(pubkey)
        pubkey_hash = hash160(pubkey)
        return bech32encode('0014' + pubkey_hash, prefix=prefix)
    raise ValueError()


def bech32_sign(tx, i, priv, amount, script=None, hashcode=SIGHASH_ALL):
    from bitcoin import deserialize, segwit_signature_form, ecdsa_raw_sign, der_encode_sig, serialize, compress
    i = int(i)
    txobj = tx if isinstance(tx, dict) else deserialize(tx)
    if len(priv) <= 33:
        priv = binascii.hexlify(priv)
    pub = compress(privkey_to_pubkey(priv))
    script = script or ('76a914' + hash160(binascii.unhexlify(pub)) + '88ac')
    signing_tx = segwit_signature_form(tx, i, script, amount, hashcode=hashcode)
    rawsig = ecdsa_raw_sign(hashlib.sha256(hashlib.sha256(binascii.unhexlify(signing_tx)).digest()).hexdigest(), priv)
    sig = der_encode_sig(*rawsig)+encode(hashcode, 16, 2)
    txobj['ins'][i]['txinwitness'] = [sig, pub]
    return serialize(txobj)

#!/usr/bin/python
from _functools import reduce

import copy

from bitcoin.bech32 import bech32decode, BECH32_PREFIXES, bech32encode

from bitcoin.main import *
### Hex to bin converter and vice versa for objects


def json_is_base(obj, base):
    if not is_python2 and isinstance(obj, bytes):
        return False

    alpha = get_code_string(base)
    if isinstance(obj, string_types):
        for i in range(len(obj)):
            if alpha.find(obj[i]) == -1:
                return False
        return True
    elif isinstance(obj, int_types) or obj is None:
        return True
    elif isinstance(obj, list):
        for i in range(len(obj)):
            if not json_is_base(obj[i], base):
                return False
        return True
    else:
        for x in obj:
            if not json_is_base(obj[x], base):
                return False
        return True


def json_changebase(obj, changer):
    if isinstance(obj, string_or_bytes_types):
        return changer(obj)
    elif isinstance(obj, int_types) or obj is None:
        return obj
    elif isinstance(obj, list):
        return [json_changebase(x, changer) for x in obj]
    return dict((x, json_changebase(obj[x], changer)) for x in obj)

# Transaction serialization and deserialization

def deserialize(tx):
    if is_hexilified(tx):
        #tx = bytes(bytearray.fromhex(tx))
        return json_changebase(deserialize(binascii.unhexlify(tx)),
                              lambda x: safe_hexlify(x))
    # http://stackoverflow.com/questions/4851463/python-closure-write-to-variable-in-parent-scope
    # Python's scoping rules are demented, requiring me to make pos an object
    # so that it is call-by-reference
    pos = [0]

    def read_as_int(bytez):
        pos[0] += bytez
        return decode(tx[pos[0]-bytez:pos[0]][::-1], 256)

    def read_var_int():
        pos[0] += 1

        val = from_byte_to_int(tx[pos[0]-1])
        if val < 253:
            return val
        return read_as_int(pow(2, val - 252))

    def read_bytes(bytez):
        pos[0] += bytez
        return tx[pos[0]-bytez:pos[0]]

    def read_var_string():
        size = read_var_int()
        return read_bytes(size)

    obj = {"ins": [], "outs": []}
    obj["version"] = read_as_int(4)
    ins = read_var_int()

    " begin segwit "
    segwit_flag = False
    if not ins:
        segwit_flag = read_var_int()
        ins = read_var_int()
    " end segwit "

    for i in range(ins):
        obj["ins"].append({
            "outpoint": {
                "hash": read_bytes(32)[::-1],
                "index": read_as_int(4)
            },
            "script": read_var_string(),
            "sequence": read_as_int(4)
        })
    outs = read_var_int()
    for i in range(outs):
        obj["outs"].append({
            "value": read_as_int(8),
            "script": read_var_string()
        })
    if segwit_flag:
        obj["segwit"] = True
        for i in range(ins):
            howmany = read_var_int()
            if howmany:
                obj['ins'][i]['txinwitness'] = [read_var_string() for x in range(0, howmany)]

    obj["locktime"] = read_as_int(4)
    return obj


def serialize(txobj):
    SEGWIT_MARKER = b'\x00'
    SEGWIT_FLAG = b'\x01'
    o = []
    if json_is_base(txobj, 16):
        json_changedbase = json_changebase(txobj, lambda x: binascii.unhexlify(x))
        return str(binascii.hexlify(serialize(json_changedbase)).decode())
    o.append(encode(txobj["version"], 256, 4)[::-1])

    " begin segwit "
    segwit = txobj.get('segwit', False)
    " end segwit "

    o.append(num_to_var_int(len(txobj["ins"])))
    for inp in txobj["ins"]:
        inp['script'] = inp.get('script', '')
        " begin segwit "
        segwit = bool(inp.get("txinwitness") != None) if not segwit else segwit
        " end segwit "
        o.append(inp["outpoint"]["hash"][::-1])
        o.append(encode(inp["outpoint"]["index"], 256, 4)[::-1])
        out_len = num_to_var_int(len(inp["script"]))
        script = inp['script'] if inp.get('script') else b''
        o.append(out_len + script)
        o.append(encode(inp.get('sequence', 4294967295), 256, 4)[::-1])
    o.append(num_to_var_int(len(txobj["outs"])))
    for out in txobj["outs"]:
        out['script'] = out['script']
        o.append(encode(out["value"], 256, 8)[::-1])
        o.append(num_to_var_int(len(out["script"]))+out["script"])

    " begin segwit "
    if segwit:
        o.insert(1, SEGWIT_MARKER + SEGWIT_FLAG)
        for inp in txobj["ins"]:
            if not isinstance(inp.get('txinwitness', None), list):
                o.append(num_to_var_int(0))
            else:
                if len(inp.get('txinwitness')):
                    o.append(num_to_var_int(len(inp.get('txinwitness'))))
                    for i in inp.get('txinwitness'):
                        o.append(num_to_var_int(len(i)))
                        if i:
                            o.append(i)
                else:
                    o.append(num_to_var_int(2))
                    o.append(num_to_var_int(0) * 2)

    " end segwit "

    o.append(encode(txobj["locktime"], 256, 4)[::-1])
    return b''.join(o)


def signature_form(tx, i, script, hashcode=SIGHASH_ALL):
    i, hashcode = int(i), int(hashcode)
    if isinstance(tx, string_or_bytes_types):
        sform = signature_form(deserialize(tx), i, script, hashcode)
        return serialize(sform)

    newtx = copy.deepcopy(tx)
    for inp in newtx["ins"]:
        inp["script"] = ""
    newtx["ins"][i]["script"] = script

    if hashcode == SIGHASH_SINGLE:
        newtx["outs"] = newtx["outs"][:len(newtx["ins"])]
        for out in newtx["outs"][:len(newtx["ins"]) - 1]:
            out['value'] = 2**64 - 1
            out['script'] = ""
    elif hashcode & SIGHASH_NONE:
        newtx["outs"] = []
    if hashcode & SIGHASH_ANYONECANPAY:
        newtx["ins"] = [newtx["ins"][i]]
    return newtx


# Making the actual signatures


def encode_num(n):
    h = binascii.hexlify(encode(n,256))
    b = binascii.unhexlify(h)
    if ord(b[0]) < 0x80:
        return h
    else:
        return '00' + h

def der_encode_sig(v, r, s):
    b1, b2 = safe_hexlify(encode(r, 256)), safe_hexlify(encode(s, 256))
    if len(b1) and b1[0] in '89abcdef':
        b1 = '00' + b1
    if len(b2) and b2[0] in '89abcdef':
        b2 = '00' + b2
    left = '02'+encode(len(b1)//2, 16, 2)+b1
    right = '02'+encode(len(b2)//2, 16, 2)+b2
    return '30'+encode(len(left+right)//2, 16, 2)+left+right

def der_decode_sig(sig):
    leftlenbytes = decode(sig[6:8], 16)
    leftlen = leftlenbytes*2
    left = sig[8:8+leftlen]
    rightlenbytes = decode(sig[10+leftlen:12+leftlen], 16)
    rightlen = rightlenbytes*2
    right = sig[12+leftlen:12+leftlen+rightlen]
    return (leftlenbytes, decode(left, 16), rightlenbytes, decode(right, 16))

def is_bip66(sig):
    """Checks hex DER sig for BIP66 consistency"""
    #https://raw.githubusercontent.com/bitcoin/bips/master/bip-0066.mediawiki
    #0x30  [total-len]  0x02  [R-len]  [R]  0x02  [S-len]  [S]  [sighash]
    sig = bytearray.fromhex(sig) if re.match('^[0-9a-fA-F]*$', sig) else bytearray(sig)
    if (sig[0] == 0x30) and (sig[1] == len(sig)-2):     # check if sighash is missing
            sig.extend(b"\1")		                   	# add SIGHASH_ALL for testing
    #assert (sig[-1] & 124 == 0) and (not not sig[-1]), "Bad SIGHASH value"

    if len(sig) < 9 or len(sig) > 73: return False
    if (sig[0] != 0x30): return False
    if (sig[1] != len(sig)-3): return False
    rlen = sig[3]
    if (5+rlen >= len(sig)): return False
    slen = sig[5+rlen]
    if (rlen + slen + 7 != len(sig)): return False
    if (sig[2] != 0x02): return False
    if (rlen == 0): return False
    if (sig[4] & 0x80): return False
    if (rlen > 1 and (sig[4] == 0x00) and not (sig[5] & 0x80)): return False
    if (sig[4+rlen] != 0x02): return False
    if (slen == 0): return False
    if (sig[rlen+6] & 0x80): return False
    if (slen > 1 and (sig[6+rlen] == 0x00) and not (sig[7+rlen] & 0x80)):
        return False
    return True

def txhash(tx, hashcode=None):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        tx = changebase(tx, 16, 256)
    if hashcode is not None:
        return dbl_sha256(from_string_to_bytes(tx) + encode(int(hashcode), 256, 4)[::-1])
    else:
        return safe_hexlify(bin_dbl_sha256(tx)[::-1])


def bin_txhash(tx, hashcode=None):
    return binascii.unhexlify(txhash(tx, hashcode))


def ecdsa_tx_sign(tx, priv, hashcode=SIGHASH_ALL):
    rawsig = ecdsa_raw_sign(bin_txhash(tx, hashcode), priv)
    return der_encode_sig(*rawsig)+encode(hashcode, 16, 2)


def ecdsa_tx_verify(tx, sig, pub, hashcode=SIGHASH_ALL):
    return ecdsa_raw_verify(bin_txhash(tx, hashcode), der_decode_sig(sig), pub)


def ecdsa_tx_recover(tx, sig, hashcode=SIGHASH_ALL):
    z = bin_txhash(tx, hashcode)
    rlen, r, slen, s = der_decode_sig(sig)
    left = ecdsa_raw_recover(z, (0, r, s))
    right = ecdsa_raw_recover(z, (1, r, s))
    return (encode_pubkey(left, 'hex'), encode_pubkey(right, 'hex'))

# Scripts


def mk_pubkey_script(addr):
    # Keep the auxiliary functions around for altcoins' sake
    return '76a914' + b58check_to_hex(addr) + '88ac'


def mk_scripthash_script(addr):
    return 'a914' + b58check_to_hex(addr) + '87'

# Address representation to output script


def address_to_script(addr):
    if addr[0] in ('2', '3', 'S', 'r'):
        return mk_scripthash_script(addr)
    else:
        return mk_pubkey_script(addr)

# Output script to address representation


def scripthash_to_address(script: str, b58_vbyte: int, scripthash_byte: int, b32_prefix: str):
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if script[:2] == b'\x00\x20':
        return bech32encode(script.hex(), b32_prefix)
    if script[:2] == b'\x00\x14':
        return bech32encode(script.hex(), b32_prefix)

    if script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac' and len(script) == 25:
        return bin_to_b58check(script[3:-2], b58_vbyte)  # pubkey hash addresses
    else:
        return bin_to_b58check(script[2:-1], scripthash_byte)


def script_to_address(script, vbyte=0):
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac' and len(script) == 25:
        return bin_to_b58check(script[3:-2], vbyte)  # pubkey hash addresses
    else:
        if vbyte in [111, 196]:
            # Testnet
            scripthash_byte = 196
        elif vbyte == 0:
            # Mainnet
            scripthash_byte = 5
        else:
            scripthash_byte = vbyte
        # BIP0016 scripthash addresses
        return bin_to_b58check(script[2:-1], scripthash_byte)


def p2sh_scriptaddr(script, magicbyte=5):
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    return hex_to_b58check(hash160(script), magicbyte)
scriptaddr = p2sh_scriptaddr


def deserialize_script(script):
    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
       return json_changebase(deserialize_script(binascii.unhexlify(script)),
                              lambda x: safe_hexlify(x))
    out, pos = [], 0
    while pos < len(script):
        code = from_byte_to_int(script[pos])
        if code == 0:
            out.append(None)
            pos += 1
        elif code <= 75:
            out.append(script[pos+1:pos+1+code])
            pos += 1 + code
        elif code <= 78:
            szsz = pow(2, code - 76)
            sz = decode(script[pos+szsz: pos:-1], 256)
            out.append(script[pos + 1 + szsz:pos + 1 + szsz + sz])
            pos += 1 + szsz + sz
        elif code <= 96:
            out.append(code - 80)
            pos += 1
        else:
            out.append(code)
            pos += 1
    return out


def serialize_script_unit(unit):
    if isinstance(unit, int):
        if unit < 16:
            return from_int_to_byte(unit + 80)
        else:
            return from_int_to_byte(unit)
    elif unit is None:
        return b'\x00'
    else:
        if len(unit) <= 75:
            return from_int_to_byte(len(unit))+unit
        elif len(unit) < 256:
            return from_int_to_byte(76)+from_int_to_byte(len(unit))+unit
        elif len(unit) < 65536:
            return from_int_to_byte(77)+encode(len(unit), 256, 2)[::-1]+unit
        else:
            return from_int_to_byte(78)+encode(len(unit), 256, 4)[::-1]+unit


if is_python2:
    def serialize_script(script):
        if json_is_base(script, 16):
            return binascii.hexlify(serialize_script(json_changebase(script,
                                    lambda x: binascii.unhexlify(x))))
        return ''.join(map(serialize_script_unit, script))
else:
    def serialize_script(script):
        if json_is_base(script, 16):
            return safe_hexlify(serialize_script(json_changebase(script,
                                    lambda x: binascii.unhexlify(x))))

        result = bytes()
        for b in map(serialize_script_unit, script):
            result += b if isinstance(b, bytes) else bytes(b, 'utf-8')
        return result


def mk_OPCS_multisig_script(form):
    script = []
    OP_CODESEPARATOR = from_int_to_byte(0xAB)
    OP_CHECKSIG = from_int_to_byte(0xAC)
    OP_CHECKSIGVERIFY = from_int_to_byte(0xAD)
    OP_CHECKMULTISIG = from_int_to_byte(0xAE)
    OP_CHECKMULTISIGVERIFY = from_int_to_byte(0xAF)
    """
    uses OP_CODESEPARATOR to build the multisig redeem script
    form:

    {
    'keys': ['hex_pubkey_1',
             'hex_pubkey_2',
             'hex_pubkey_3'
    'schema': [
            {
                'reqs': 1,
                'keys': [0],
            },
            {
                'reqs': 1,
                'keys': [1, 2],
            }
        ]
    }

    """
    for i, s in enumerate(form['schema']):
        subscript = []
        for k in s['keys']:
            subscript.append(from_int_to_byte(len(form['keys'][k]) // 2))
            subscript.append(safe_from_hex(form['keys'][k]))
        if len(s['keys']) == 1:
            subscript.append(OP_CHECKSIG if i == len(s) -1 else OP_CHECKSIGVERIFY)
        elif len(s['keys']) > 1:
            subscript.insert(from_int_to_byte(s['reqs']), 0)
            subscript.insert(from_int_to_byte(len(s['keys'])), len(s['keys']) + 1)
            subscript.append(OP_CHECKMULTISIG if i == len(s) -1 else OP_CHECKMULTISIGVERIFY)
        else:
            raise ValueError('no keys condition')
        if i != len(s) - 1:
            subscript.append(OP_CODESEPARATOR)
        script = script + subscript
    res = binascii.hexlify(b''.join(script)).decode('ascii')
    return res


def mk_multisig_script(*args):  # [pubs],k or pub1,pub2...pub[n],k
    if isinstance(args[0], list):
        pubs, k = args[0], int(args[1])
    elif len(args) == 1 and isinstance(args[0], dict):
        return mk_OPCS_multisig_script(args[0])
    else:
        pubs = list(filter(lambda x: len(str(x)) >= 32, args))
        k = int(args[len(pubs)])
    return serialize_script([k]+pubs+[len(pubs)]+[0xae])

# Signing and verifying


def verify_tx_input(tx, i, script, sig, pub):
    if re.match('^[0-9a-fA-F]*$', tx):
        tx = binascii.unhexlify(tx)
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    if not re.match('^[0-9a-fA-F]*$', sig):
        sig = safe_hexlify(sig)
    hashcode = decode(sig[-2:], 16)
    modtx = signature_form(tx, int(i), script, hashcode)
    return ecdsa_tx_verify(modtx, sig, pub, hashcode)


def sign(tx, i, priv, hashcode=SIGHASH_ALL):
    i = int(i)
    txobj = tx if isinstance(tx, dict) else deserialize(tx)
    if not isinstance(tx, dict) and ((not is_python2 and isinstance(re, bytes)) or not re.match('^[0-9a-fA-F]*$', tx)):
        return binascii.unhexlify(sign(safe_hexlify(tx), i, priv))
    if len(priv) <= 33:
        priv = safe_hexlify(priv)
    pub = privkey_to_pubkey(priv)
    address = pubkey_to_address(pub)
    signing_tx = signature_form(tx, i, mk_pubkey_script(address), hashcode)
    sig = ecdsa_tx_sign(signing_tx, priv, hashcode)
    txobj["ins"][i]['script'] = serialize_script([sig, pub])
    return serialize(txobj)

def p2pk_sign(tx, i, priv, hashcode=SIGHASH_ALL):
    i = int(i)
    txobj = tx if isinstance(tx, dict) else deserialize(tx)
    if not isinstance(tx, dict) and ((not is_python2 and isinstance(re, bytes)) or not re.match('^[0-9a-fA-F]*$', tx)):
        return binascii.unhexlify(sign(safe_hexlify(tx), i, priv))
    if len(priv) <= 33:
        priv = safe_hexlify(priv)
    pub = privkey_to_pubkey(priv)
    signing_tx = signature_form(tx, i, '21' + pub + 'ac', hashcode)
    sig = ecdsa_tx_sign(signing_tx, priv, hashcode)
    txobj["ins"][i]['script'] = serialize_script([sig])
    return serialize(txobj)


def signall(tx, priv):
    # if priv is a dictionary, assume format is
    # { 'txinhash:txinidx' : privkey }
    if isinstance(priv, dict):
        for e, i in enumerate(deserialize(tx)["ins"]):
            k = priv["%s:%d" % (i["outpoint"]["hash"], i["outpoint"]["index"])]
            tx = sign(tx, e, k)
    else:
        for i in range(len(deserialize(tx)["ins"])):
            tx = sign(tx, i, priv)
    return tx


def multisign(tx, i, script, pk, hashcode=SIGHASH_ALL):
    if re.match('^[0-9a-fA-F]*$', tx):
        tx = binascii.unhexlify(tx)
    if re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    modtx = signature_form(tx, i, script, hashcode)
    return ecdsa_tx_sign(modtx, pk, hashcode)


def is_inp(arg):
    return len(arg) > 64 or "output" in arg or "outpoint" in arg


def mktx(*args, **kwargs):
    # [in0, in1...],[out0, out1...] or in0, in1 ... out0 out1 ...
    ser = kwargs.get('serialize', True)
    ins, outs = [], []
    for arg in args:
        if isinstance(arg, list):
            for a in arg: (ins if is_inp(a) else outs).append(a)
        else:
            (ins if is_inp(arg) else outs).append(arg)

    txobj = {"locktime": kwargs.get('locktime', 0), "version": 1, "ins": [], "outs": []}
    for i in ins:

        " begin segwit "
        seg_input = isinstance(i, dict) and i.get('segregated')
        sequence = isinstance(i, dict) and i.get('sequence', None)
        " end segwit "

        if isinstance(i, dict) and "outpoint" in i:
            txobj["ins"].append(i)
        else:
            if isinstance(i, dict) and "output" in i:
                i = i["output"]
            txobj["ins"].append({
                "outpoint": {"hash": i[:64], "index": int(i[65:])},
                "script": "",
                "sequence": 4294967295 if not sequence and sequence != 0 else sequence
            })
        if seg_input:
            txobj["ins"][-1].update({'txinwitness': []})

    for o in outs:
        if isinstance(o, string_or_bytes_types):
            addr = o[:o.find(':')]
            val = int(o[o.find(':')+1:])
            o = {}
            if re.match('^[0-9a-fA-F]*$', addr):
                o["script"] = addr
            else:
                o["address"] = addr
            o["value"] = val
        outobj = {}
        if "address" in o:
            if any(map(lambda x: o["address"].lower().startswith(x), BECH32_PREFIXES)):
                outobj["script"] = bech32decode(o["address"].lower())
            else:
                outobj["script"] = address_to_script(o["address"])
        elif "script" in o:
            outobj["script"] = o["script"]
        else:
            raise Exception("Could not find 'address' or 'script' in output.")
        outobj["value"] = o["value"]
        txobj["outs"].append(outobj)
    return txobj if not ser else serialize(txobj)


def select(unspent, value):
    value = int(value)
    high = [u for u in unspent if u["value"] >= value]
    high.sort(key=lambda u: u["value"])
    low = [u for u in unspent if u["value"] < value]
    low.sort(key=lambda u: -u["value"])
    if len(high):
        return [high[0]]
    i, tv = 0, 0
    while tv < value and i < len(low):
        tv += low[i]["value"]
        i += 1
    if tv < value:
        raise Exception("Not enough funds")
    return low[:i]

# Only takes inputs of the form { "output": blah, "value": foo }


def mksend(*args, **kwargs):
    argz, change, fee = args[:-2], args[-2], int(args[-1])
    ins, outs = [], []
    for arg in argz:
        if isinstance(arg, list):
            for a in arg:
                (ins if is_inp(a) else outs).append(a)
        else:
            (ins if is_inp(arg) else outs).append(arg)

    isum = sum([i["value"] for i in ins])
    osum, outputs2 = 0, []
    for o in outs:
        if isinstance(o, string_types):
            o2 = {
                "address": o[:o.find(':')],
                "value": int(o[o.find(':')+1:])
            }
        else:
            o2 = o
        outputs2.append(o2)
        osum += o2["value"]

    if isum < osum+fee:
        raise Exception("Not enough money")
    elif isum > osum+fee+5430:
        outputs2 += [{"address": change, "value": isum-osum-fee}]

    return mktx(ins, outputs2, **kwargs)

def mk_opreturn(msg, rawtx=None, json=0):
    def op_push(data):
        import struct
        if len(data) < 0x4c:
            return from_int_to_byte(len(data)) + data
        elif len(data) < 0xff:
            return from_int_to_byte(76) + struct.pack('<B', len(data)) + from_string_to_bytes(data)
        elif len(data) < 0xffff:
            return from_int_to_byte(77) + struct.pack('<H', len(data)) + from_string_to_bytes(data)
        elif len(data) < 0xffffffff:
            return from_int_to_byte(78) + struct.pack('<I', len(data)) + from_string_to_bytes(data)
        else:
            raise Exception("Input data error. Rawtx must be hex chars" \
                            + "0xffffffff > len(data) > 0 ??")

    orhex = safe_hexlify(b'\x6a' + op_push(msg))
    orjson = {'script' : orhex, 'value' : 0}
    if rawtx is not None:
        try:
            txo = deserialize(rawtx)
            if not 'outs' in txo.keys(): raise Exception("OP_Return cannot be the sole output!")
            txo['outs'].append(orjson)
            newrawtx = serialize(txo)
            return newrawtx
        except:
            raise Exception("Raw Tx Error!")
    return orhex if not json else orjson
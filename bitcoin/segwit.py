import binascii
import hashlib
import re
import struct
from bitcoin import changebase, is_python2, privkey_to_pubkey, pubkey_to_address, ecdsa_raw_sign, encode, \
    SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_SINGLE, SIGHASH_NONE, \
    deserialize, txhash, serialize, sign, mk_pubkey_script, der_encode_sig, serialize_script, \
    deserialize_script, decode, ecdsa_raw_verify, der_decode_sig


def get_hashcode_strategy(hashcode):
    return _STRATEGIES[hashcode]


class HashcodeStrategy():
    def get_inputs_for_sequences(self, tx, i):
        raise NotImplementedError()

    def get_outputs(self, tx, i):
        raise NotImplementedError()

    def get_sequences(self, tx, i):
        raise NotImplementedError()


class SIGHASH_ALL_Strategy(HashcodeStrategy):
    def get_inputs_for_sequences(self, tx, i):
        return tx['ins']

    def get_outputs(self, tx, i):
        return tx['outs']

    def get_sequences(self, tx, i):
        return [struct.pack('<I', (inps['sequence'])) for inps in self.get_inputs_for_sequences(tx, i)]


class SIGHASH_SINGLE_Strategy(HashcodeStrategy):
    def get_inputs_for_sequences(self, tx, i):
        return tx['ins']

    def get_outputs(self, tx, i):
        if len(tx['outs']) > i:
            return [tx['outs'][i]]
        return []

    def get_sequences(self, tx, i):
        return []

class SIGHASH_NONE_Strategy(HashcodeStrategy):
    def get_inputs_for_sequences(self, tx, i):
        return tx['ins']

    def get_outputs(self, tx, i):
        return []

    def get_sequences(self, tx, i):
        return []


class ANYONECANPAY_STRATEGY(HashcodeStrategy):
    def __init__(self, default_strategy):
        self.default = default_strategy

    def get_inputs_for_sequences(self, tx, i):
        return []

    def get_outputs(self, tx, i):
        return self.default.get_outputs(tx, i)

    def get_sequences(self, tx, i):
        return []

_STRATEGIES = {
    SIGHASH_ALL: SIGHASH_ALL_Strategy(),
    SIGHASH_SINGLE: SIGHASH_SINGLE_Strategy(),
    SIGHASH_NONE: SIGHASH_NONE_Strategy(),
    SIGHASH_ALL|SIGHASH_ANYONECANPAY: ANYONECANPAY_STRATEGY(SIGHASH_ALL_Strategy()),
    SIGHASH_SINGLE|SIGHASH_ANYONECANPAY: ANYONECANPAY_STRATEGY(SIGHASH_SINGLE_Strategy()),
    SIGHASH_NONE|SIGHASH_ANYONECANPAY: ANYONECANPAY_STRATEGY(SIGHASH_NONE_Strategy())
}


def is_segwit(tx, hashcode=None):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        tx = changebase(tx, 16, 256)
    return tx[4:6] == b'\x00\x01'


def segwit_signature_form_transaction_dict(tx, i, script, amount, hashcode=SIGHASH_ALL):
    def parse_vout(o):
        return b''.join([struct.pack('<Q', o['value']),
                         struct.pack('B', len(o['script']) // 2),
                         binascii.unhexlify(o['script'])])
    def parse_vin(inp):
        return b''.join([binascii.unhexlify(inp['outpoint']['hash'])[::-1],
                         struct.pack('<I', (inp['outpoint']['index']))])

    vin_outpoint = [binascii.unhexlify(tx['ins'][i]['outpoint']['hash'])[::-1],
                    struct.pack('<I', (tx['ins'][i]['outpoint']['index']))]
    hashcode_strategy = get_hashcode_strategy(hashcode)
    outpoints = [parse_vin(inp) for inp in hashcode_strategy.get_inputs_for_sequences(tx, i)]
    sequences = hashcode_strategy.get_sequences(tx, i)
    outputs_to_sign = hashcode_strategy.get_outputs(tx, i)
    outputs = [parse_vout(out) for out in outputs_to_sign]

    hash_outputs = hashlib.sha256(hashlib.sha256(b''.join(outputs)).digest()).digest() if outputs_to_sign else b'\x00'*32
    hash_sequences = hashlib.sha256(hashlib.sha256(b''.join(sequences)).digest()).digest() if sequences else b'\x00'*32
    hash_outpoints = hashlib.sha256(hashlib.sha256(b''.join(outpoints)).digest()).digest() if outpoints else b'\x00'*32

    preimage = [struct.pack('<I', tx['version']),
                hash_outpoints,
                hash_sequences,
                b''.join(vin_outpoint),
                struct.pack('B', len(script) // 2),
                binascii.unhexlify(script),
                struct.pack('<Q', amount),
                struct.pack('<I', tx['ins'][i]['sequence']),
                hash_outputs,
                struct.pack('<I', tx['locktime']),
                struct.pack('<I', hashcode)]
    return binascii.hexlify(b''.join(preimage)).decode('ascii')


def segwit_signature_form(tx, i, script, amount, hashcode=SIGHASH_ALL):
    return segwit_signature_form_transaction_dict(
        deserialize(tx), i, script, amount, hashcode=hashcode
    )


def segwit_txhash(tx):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        tx = changebase(tx, 16, 256)
    tx_hash = txhash(tx)
    tx = strip_witness_data(tx)
    tx_id = txhash(tx)
    return {'hash': tx_hash, 'txid': tx_id}


def strip_witness_data(tx):
    return serialize(
        strip_witness_deserialized_data(
            deserialize(tx)
        )
    )


def strip_witness_deserialized_data(tx_dict):
    tx_dict.pop('segwit', '')
    for inp in tx_dict['ins']:
        inp.pop('txinwitness', '')
    return tx_dict


def segwit_sign(tx, i, priv, amount, hashcode=SIGHASH_ALL, script=None, separator_index=None):
    i = int(i)
    txobj = tx if isinstance(tx, dict) else deserialize(tx)
    if not isinstance(tx, dict) and ((not is_python2 and isinstance(re, bytes)) or not re.match('^[0-9a-fA-F]*$', tx)):
        return binascii.unhexlify(sign(binascii.hexlify(tx), i, priv))
    if len(priv) <= 33:
        priv = binascii.hexlify(priv)
    pub = privkey_to_pubkey(priv)
    address = pubkey_to_address(pub)
    wscript = mk_pubkey_script(address) if not script else script
    stripped_script = segwit_strip_script_separator(wscript, separator_index)
    signing_tx = segwit_signature_form(tx, i, stripped_script, amount, hashcode=hashcode)
    rawsig = ecdsa_raw_sign(hashlib.sha256(hashlib.sha256(binascii.unhexlify(signing_tx)).digest()).hexdigest(), priv)
    sig = der_encode_sig(*rawsig)+encode(hashcode, 16, 2)
    txobj['ins'][i]['txinwitness'] = [sig, pub if not script else script]
    return serialize(txobj)


def apply_multisignatures(*args):
    # tx,i,script,sigs OR tx,i,script,sig1,sig2...,sig[n]
    tx, i, script = args[0], int(args[1]), args[2]
    sigs = args[3] if isinstance(args[3], list) else list(args[3:])

    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
        script = binascii.unhexlify(script)
    sigs = [binascii.unhexlify(x) if x[:2] == '30' else x for x in sigs]
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        signed_tx = apply_multisignatures(binascii.unhexlify(tx), i, script, sigs)
        return binascii.hexlify(signed_tx)

    # Not pushing empty elements on the top of the stack if passing no
    # script (in case of bare multisig inputs there is no script)
    script_blob = [] if script.__len__() == 0 else [script]

    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = serialize_script([None]+sigs+script_blob)
    return serialize(txobj)


def apply_segwit_multisignatures(tx, i, witness_program, signatures, dummy=True, nested=False):
    txobj = deserialize(tx)
    signed = apply_segwit_multisignatures_deserialized_data(
        txobj, i, witness_program, signatures, dummy=dummy, nested=nested
    )
    return serialize(signed)


def apply_segwit_multisignatures_deserialized_data(
    deserialized_tx, i, witness_program, signatures, dummy=True, nested=True
):
    o = [""] + signatures + [witness_program] if dummy else signatures + [witness_program]
    deserialized_tx['ins'][i]['txinwitness'] = o
    if nested:
        redeem_script = hashlib.sha256(binascii.unhexlify(
            witness_program
        )).hexdigest()
        length = len(redeem_script) // 2
        redeem_script = serialize_script(
            [length + 2, None, redeem_script])
        deserialized_tx["ins"][i]["script"] = redeem_script
    return deserialized_tx


def segwit_strip_script_separator(script, index=0):
    if index == None:
        return script
    OP_CODESEPARATOR = 171
    def get_pos(script, index):
        i = 0
        for x in range(0, index):
            try:
                i = script.index(OP_CODESEPARATOR, i)
            except ValueError:
                return i
        return i + 1
    deserialized_script = deserialize_script(str(script))
    pos = get_pos(deserialized_script, index)
    return serialize_script(deserialized_script[pos:])


def segwit_multisign(tx, i, script, pk, amount, hashcode=SIGHASH_ALL, separator_index=None):
    wscript = segwit_strip_script_separator(script, index=separator_index)
    signing_tx = segwit_signature_form(tx, i, wscript, amount, hashcode=hashcode)
    rawsig = ecdsa_raw_sign(hashlib.sha256(hashlib.sha256(
        binascii.unhexlify(signing_tx)).digest()).hexdigest(), pk)
    sig = der_encode_sig(*rawsig)+encode(hashcode, 16, 2)
    return sig


def segwit_verify_tx_input(tx, i, script, sig, pub, amount):
    hashcode = decode(sig[-2:], 16)
    signing_tx = segwit_signature_form(tx, int(i), script, amount, hashcode=hashcode)
    hashed_signing_tx = hashlib.sha256(hashlib.sha256(binascii.unhexlify(signing_tx)).digest()).hexdigest()
    return ecdsa_raw_verify(hashed_signing_tx, der_decode_sig(sig), pub)

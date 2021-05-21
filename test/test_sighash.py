import unittest

import bitcoin
from bitcoin import *


class TestTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Attempting transaction creation")

    def test3(self):
        print(
            deserialize_script('52210248905f94419795ea33cd42474e10bfaddc3ee5f0f0c66ecc29238fea6555f29c2103fde505b2f67b2c8ec17c7540bbc9aafb527366c0863d655d03a00e5f3c4bbbd121023f96141f1bec4df22465539ecd807762e2c96b75e436540d3e7654d461b62a1953ae')
        )

    def test2(self):
        pub = '029b06d73294a2fe59dd5d2156f9d7bf1cadc8e741b39fff834d39a055ab8f5c97'
        addr = 'bcrt1q8s2hkukgulyf575hakxazset8v2z5ltxnvepy8'
        self.assertEqual(pubkey_to_bech32_address(pub, prefix='bcrt'), addr)
        print(deserialize_script('00141976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac'))
        print(hash160(binascii.unhexlify('025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357')))

    def test_multisig(self):
        priv1 = sha256(b'sighash_priv_key_text')
        priv2 = sha256(b'sighash_priv_key_text_2')
        pub1 = compress(privtopub(priv1))
        pub2 = compress(privtopub(priv2))
        witness_program = mk_multisig_script([pub1, pub2], 2, 2)
        addr = bech32_script_to_address(witness_program, prefix='bc')
        print('addr', addr)
        recipient = '3AbjFnwcChgaAGsPx28hnpDWF3yUobvTFT'
        amount = 0.00028295
        transaction_to_sign = mktx(
            {
                'output': '99911f6ddabc51290a45194f268d7e618284d7f42d79a2b57bee9bc5b11787c5:0',
                'segregated': True
            },
            [
                {'address': recipient, 'value': int(amount * 10**8) - 4500}
            ]
        )

        tx = bitcoin.deserialize(transaction_to_sign)
        """ test big opreturn size"""
        bigscript = [os.urandom(1024).hex() for _ in range(0, 1000)]
        tx['outs'].append(
            {
                'value': 0,
                'script': '00' + bitcoin.serialize_script(bigscript)
            }
        )
        txs = bitcoin.serialize(tx)
        tx = bitcoin.deserialize(txs)
        s = bitcoin.deserialize_script(tx['outs'][-1]['script'])
        self.assertEqual(s[0], None)
        self.assertEqual(s[1:], bigscript)

        sig1 = bech32_multisign(
            transaction_to_sign, 0, priv1, int(amount * 10 ** 8),
            witness_program, hashcode=SIGHASH_NONE|SIGHASH_ANYONECANPAY
        )
        sig2 = bech32_multisign(transaction_to_sign, 0, priv2, int(amount * 10 ** 8), witness_program)
        tx = apply_bech32_multisignatures(transaction_to_sign, 0, witness_program, [sig1, sig2])
        print(tx)

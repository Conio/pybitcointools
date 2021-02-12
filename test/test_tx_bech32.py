import unittest
from bitcoin import *
from bitcoin.bech32 import bech32decode


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

    def test(self):
        addr = 'bcrt1qpkye5029qngu6jflsg4wnmrtmj47py4mhsvhav'
        priv = sha256(b'priv_key_text')
        pub = compress(privtopub(priv))
        address = pubkey_to_bech32_address(pub, prefix='bcrt')
        self.assertEqual(addr, address)
        transaction_to_sign = mktx(
            {
                'output': '2ecfbf58dd128a3f1a6d4c1cdb1740c706389494c7ed94b9e027582d71602ade:1',
                'segregated': True
            },
            [
                {'address': addr, 'value': int(1 * 10**8) - 5000}
            ]
        )
        tx = bech32_sign(transaction_to_sign, 0, priv, int(1 * 10**8))
        self.assertEqual(segwit_txhash(tx)['txid'], '2fe3694f5b62097211a04521593eaa9661ff6beb5aec9696efc2ce6d2b78959d')

    def test_multisig(self):
        priv1 = sha256(b'priv_key_text')
        priv2 = sha256(b'priv_key_text_2')
        priv3 = sha256(b'priv_key_text_3')
        pub1 = compress(privtopub(priv1))
        pub2 = compress(privtopub(priv2))
        pub3 = compress(privtopub(priv3))
        witness_program = mk_multisig_script([pub1, pub2, pub3], 2, 3)
        addr = bech32_script_to_address(witness_program, prefix='bcrt')
        self.assertEqual(
            witness_program,
            '52210248905f94419795ea33cd42474e10bfaddc3ee5f0f0c66ecc'
            '29238fea6555f29c2103fde505b2f67b2c8ec17c7540bbc9aafb52'
            '7366c0863d655d03a00e5f3c4bbbd121023f96141f1bec4df22465'
            '539ecd807762e2c96b75e436540d3e7654d461b62a1953ae'
        )
        self.assertEqual(
            addr, 'bcrt1qd3rdg790qea4gdw0k9lmp5tjl74q0hg9t09x64x2tnt9zl0sepasqjv7vn'
        )
        transaction_to_sign = mktx(
            {
                'output': '940fe2aa34c4d29b2df0e0486d4cb7e6821f426136d87e7a1a949d43ad248340:0',
                'segregated': True
            },
            [
                {'address': addr, 'value': int(1 * 10**8) - 5000}
            ]
        )
        sig1 = bech32_multisign(transaction_to_sign, 0, priv1, int(1 * 10 ** 8), witness_program)
        sig2 = bech32_multisign(transaction_to_sign, 0, priv2, int(1 * 10 ** 8), witness_program)
        self.assertEqual(
            apply_bech32_multisignatures(transaction_to_sign, 0, witness_program, [sig1, sig2]),
            "01000000000101408324ad439d941a7a7ed83661421f82e6b74c6d48e0f02d9bd2c434aae20f94000000"
            "0000ffffffff0178cdf505000000002200206c46d478af067b5435cfb17fb0d172ffaa07dd055bca6d54"
            "ca5cd6517df0c87b040048304502210092e960ab3ffe263620e22a4b5b61b452bbeee04aae736e237a09"
            "47027642a6310220116cc4db1afd7ed02dc27caea2c01cd578ad9c1b4b5531e8af129f66aa75b2a60147"
            "30440220129f3bdc8bd5a62b24cd32cb920703961ffde897e430fe3f3b47141dc5852731022077b869a8"
            "c33b7d016fb96b23c3bfffa638cc4a7ca87c4129218183ae0ed45c44016952210248905f94419795ea33"
            "cd42474e10bfaddc3ee5f0f0c66ecc29238fea6555f29c2103fde505b2f67b2c8ec17c7540bbc9aafb52"
            "7366c0863d655d03a00e5f3c4bbbd121023f96141f1bec4df22465539ecd807762e2c96b75e436540d3e"
            "7654d461b62a1953ae00000000"
        )

import unittest
from bitcoin import *
from bitcoin.bech32 import bech32decode


class TestTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Attempting transaction creation")

    def test3(self):
        print(
            deserialize_script('76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac')
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

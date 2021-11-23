import unittest

from bitcoin import *


class TestP2TRTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Attempting P2TR transaction creation")

    def test2(self):
        pub = '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        addr = 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'
        self.assertEqual(bech32decode(addr), pub)
        self.assertEqual(pubkey_to_bech32_address(pub), addr)
        rtaddr = 'bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6'
        self.assertEqual(pubkey_to_bech32_address(pub, prefix=BECH32_BITCOIN_REGTEST_PREFIX), rtaddr)
        self.assertEqual(bech32decode(rtaddr), pub)


    def test(self):
        bech32_taproot_addr = 'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c'
        priv = sha256(b'priv_key_text0rr')
        pub = compress(privtopub(priv))
        address = pubkey_to_bech32_address(pub, prefix='tb')
        print('depositaddr', address)
        transaction_to_sign = mktx(
            {
                'output': '341b1288a6e27673aeeff3a447218280550e71b2f0e4c86d301aa3cbab0b67f4:0',
                'segregated': True
            },
            [
                {'address': bech32_taproot_addr, 'value': int(0.001 * 10**8) - 5000}
            ]
        )
        tx = bech32_sign(transaction_to_sign, 0, priv, int(0.001 * 10**8))
        print(tx)
        self.assertEqual(segwit_txhash(tx)['txid'], '79a71c0e08b63b2f786b7649c765570e5aff93740eb295b5db4197390ceb4077')

import os
import unittest

import bitcoin
from bitcoin import sha256, compress, privtopub, mk_multisig_script


class TestCustomTestSignet(unittest.TestCase):
    def setUp(self) -> None:
        self.test_signet_params = [31, 63, 20]  # addr, p2sh, priv

    def test_custom_signet_bip32(self):
        seed = b'custom signet bip32'
        print('doing')
        priv = bitcoin.bip32_master_key(seed, vbytes=bitcoin.deterministic.CUSTOM_SIGNET_TEST_PRIVATE)
        for path_element in [44 + 2 ** 31, 2 + 2 ** 31]:
            priv = bitcoin.bip32_ckd(priv, path_element)
        self.assertEqual(
            priv,
            'tprsZ9ywKur445iQcrHVg5LYS2jZHvK26RLvGPUiDtTuDmYV5vXGk2'
            'BpXCPzKRwvLJyTKm1diPYWhDRRALqfsE3uoNcA7Z7GJNJ96Nai4q3fAKk'
        )
        pub = bitcoin.bip32_privtopub(priv)
        self.assertEqual(
            pub,
            'tpqcXWEW4DmTkxsqr3pJWNdETrsxYjUYLfSi3GxWrmsQ8c1oQs1z4i'
            'DBrqXgUbMTyugnTC3vuAnxHNVxFH7BamKwVSHEzXMchi7k6oa2p6bHWyc'
        )

    def test_custom_signet_bip32_2(self):
        seed = b'custom signet bip32'
        print('doing')
        priv = bitcoin.bip32_master_key(seed, vbytes=bitcoin.deterministic.CUSTOM_SIGNET_PRIVATE)
        for path_element in [44 + 2 ** 31, 2 + 2 ** 31]:
            priv = bitcoin.bip32_ckd(priv, path_element)
        self.assertEqual(
            priv,
            'xprg83CBNA3hpdiSFUk45g268i3CcEVHMHzVGPX8YwSTrwnxVFpR4NNzPs'
            '3kPQVtmWBTD5JMmp3xYDBzKMcbAHJQwiaetK8w2JqNaXGEMZ1c3ck'
        )
        pub = bitcoin.bip32_privtopub(priv)
        self.assertEqual(
            pub,
            'xpuqhJUZiindjShTtMbJWHiUL2frbALb2n1QHjYtMeMXcQUZPj3zLcr'
            'wUdKDGoRmLv3LEnPqCZKMzWQB9f5GJbg23Cp6F7BucakeCypR7uakqJG'
        )

    def test_b58_p2pkh(self):
        priv1 = sha256(b'priv_key_text')
        pub1 = compress(privtopub(priv1))
        address = bitcoin.pubtoaddr(pub1, magicbyte=self.test_signet_params[0])
        self.assertEqual(address, 'DViH9eehQSZ41NQA9CLhpCPP1WWxJpNshH')
        scriptPubKey = bitcoin.address_to_script(address)
        self.assertEqual(
            address,
            bitcoin.script_to_address(scriptPubKey, self.test_signet_params[0])
        )
        self.assertEqual(scriptPubKey, '76a9140d899a3d4504d1cd493f822ae9ec6bdcabe092bb88ac')

    def test_b58_p2sh(self):
        priv1 = sha256(b'priv_key_text')
        priv2 = sha256(b'priv_key_text_2')
        priv3 = sha256(b'priv_key_text_3')
        pub1 = compress(privtopub(priv1))
        pub2 = compress(privtopub(priv2))
        pub3 = compress(privtopub(priv3))
        witness_program = mk_multisig_script([pub1, pub2, pub3], 2, 3)
        address = bitcoin.p2sh_scriptaddr(witness_program, self.test_signet_params[1])
        self.assertEqual(address, 'SMJgdd7bDnDKByBZdmrgoCu8TAUNypAqjE')
        script_p2sh = bitcoin.address_to_script(address)
        deserialized = bitcoin.deserialize_script(script_p2sh)
        self.assertEqual(deserialized[1], bitcoin.hash160(bytes.fromhex(witness_program)))
        self.assertEqual(script_p2sh, 'a91400210e5fea6ad1574d8cab58478a9f7c43f23bf587')

    def test_priv_wif(self):
        priv = sha256(b'priv_key_text')
        wif = bitcoin.encode_privkey(priv, 'wif', vbyte=self.test_signet_params[2])
        self.assertEqual(wif, '5yEK9ezuAC9tRBhokKKtXeLHzCEL5tNALdYQPsaiQBJwMgtWBCD')
        self.assertEqual(bitcoin.encode_privkey(wif, 'hex'), priv)

    def test_bf_p2sh(self):
        for _ in range(0, 10000):
            if not _ % 1000:
                print(_)
            priv1 = sha256(os.urandom(32))
            priv2 = sha256(b'priv_key_text_2')
            priv3 = sha256(b'priv_key_text_3')
            pub1 = compress(privtopub(priv1))
            pub2 = compress(privtopub(priv2))
            pub3 = compress(privtopub(priv3))
            witness_program = mk_multisig_script([pub1, pub2, pub3], 2, 3)
            address = bitcoin.p2sh_scriptaddr(witness_program, self.test_signet_params[1])
            self.assertTrue(address.startswith('S'), msg=address)
            script_p2sh = bitcoin.address_to_script(address)
            deserialized = bitcoin.deserialize_script(script_p2sh)
            self.assertEqual(deserialized[1], bitcoin.hash160(bytes.fromhex(witness_program)))

    def test_bf_p2pkh(self):
        for _ in range(0, 10000):
            if not _ % 1000:
                print(_)
            priv1 = sha256(os.urandom(32))
            pub1 = compress(privtopub(priv1))
            address = bitcoin.pubtoaddr(pub1, magicbyte=self.test_signet_params[0])
            self.assertTrue(address.startswith('D'), msg=address)
            scriptPubKey = bitcoin.address_to_script(address)
            self.assertEqual(
                address,
                bitcoin.script_to_address(scriptPubKey, self.test_signet_params[0])
            )

    def test_bf_wif_priv(self):
        for _ in range(0, 1000):
            if not _ % 1000:
                print(_)
            priv = sha256(os.urandom(32))
            wif = bitcoin.encode_privkey(priv, 'wif', vbyte=self.test_signet_params[2])
            self.assertTrue(wif.startswith('5'), msg=wif)
            self.assertEqual(bitcoin.encode_privkey(wif, 'hex'), priv)

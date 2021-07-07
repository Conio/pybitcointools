from unittest import TestCase

import bitcoin


class TestVarPybitcointoolsStuff(TestCase):
    def test_script_to_address(self):
        scripts = {
            '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262': [
                'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
                196, False
            ],
            '00202a11fadf4a96c60669ae50b2ac7c0b3cae0b3d94483670504dc154a255826322': [
              'bcrt1q9ggl4h62jmrqv6dw2ze2clqt8jhqk0v5fqm8q5zdc922y4vzvv3qj3le86',
                196, True
            ],
            '00142a3af484ba735f3de4535f0fd522d4666646ef3f': [
                'bcrt1q9ga0fp96wd0nmezntu8a2gk5venydmelf8ddtm',
                111, True
            ],
            '00143262354a6825b39de7f35534ddb04f45ea7a1f43': [
                'bc1qxf3r2jngykeemeln256dmvz0gh48586rfx4j2p',
                0, False
            ]
        }
        for s, a in scripts.items():
            self.assertEqual(a[0], bitcoin.script_to_address(s, a[1], regtest=a[2]))

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

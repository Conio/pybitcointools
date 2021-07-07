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

    def test_signet(self):
        priv = 'bLnPotUnS3sQRefhjFPFNcJ5WS92ajuGtpsrGrqcu8reweQCiJpt'
        privhex = encode_privkey(decode_privkey(priv), 'hex', vbyte=0x6f)
        pub = compress(privtopub(privhex))
        addr = pubkey_to_bech32_address(pub, prefix='cbt')
        print(addr)
        print(pub)
        transaction_to_sign = mktx(
            [{
                'output': 'aef21e0003b31fc2cb8bafa83c271102b7ea06a5e70ac10deedc05fa86c0d697:0',
                'segregated': True
            }],
            [
                {'address': addr, 'value': int(200000 * 10**8)}
            ]
        )
        tx = bech32_sign(transaction_to_sign, 0, privhex, int(200000 * 10**8))
        print(tx)

    def test_oldscriptoaddr(self):

        def _script_to_address(script, vbyte=0, regtest=False):
            b32_prefix = {
                0: {
                    False: BECH32_BITCOIN_PREFIX
                },
                5: {
                    False: BECH32_BITCOIN_PREFIX
                },
                111: {
                    True: BECH32_BITCOIN_REGTEST_PREFIX,
                    False: BECH32_BITCOIN_TESTNET_PREFIX
                },
                196: {
                    True: BECH32_BITCOIN_REGTEST_PREFIX,
                    False: BECH32_BITCOIN_TESTNET_PREFIX
                }
            }[vbyte][regtest]
            if re.match('^[0-9a-fA-F]*$', script):
                script = binascii.unhexlify(script)
            if script[:2] == b'\x00\x20':
                return bech32encode(script.hex(), b32_prefix)
            if script[:2] == b'\x00\x14':
                return bech32encode(script.hex(), b32_prefix)
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

        scripts =  {
            '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262': [
                'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
                196, False, BECH32_BITCOIN_TESTNET_PREFIX
            ],
            '00202a11fadf4a96c60669ae50b2ac7c0b3cae0b3d94483670504dc154a255826322': [
              'bcrt1q9ggl4h62jmrqv6dw2ze2clqt8jhqk0v5fqm8q5zdc922y4vzvv3qj3le86',
                196, True, BECH32_BITCOIN_REGTEST_PREFIX
            ],
            '00142a3af484ba735f3de4535f0fd522d4666646ef3f': [
                'bcrt1q9ga0fp96wd0nmezntu8a2gk5venydmelf8ddtm',
                111, True, BECH32_BITCOIN_REGTEST_PREFIX
            ],
            '00143262354a6825b39de7f35534ddb04f45ea7a1f43': [
                'bc1qxf3r2jngykeemeln256dmvz0gh48586rfx4j2p',
                0, False, BECH32_BITCOIN_PREFIX
            ]
        }

        for script in scripts:
            resp = _script_to_address(script, vbyte=scripts[script][1], regtest=scripts[script][2])
            self.assertEqual(scripts[script][0], resp)
            b32_resp = bech32_scripthash_to_address(script, prefix=scripts[script][3])
            self.assertEqual(b32_resp, resp)

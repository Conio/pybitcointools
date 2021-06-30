from unittest import TestCase

from bitcoin import deserialize, mktx, BECH32_BITCOIN_TESTNET_PREFIX, BECH32_BITCOIN_REGTEST_PREFIX, \
    BECH32_BITCOIN_PREFIX
from bitcoin.bech32 import bech32encode, bech32decode, BECH32_CUSTOM_SIGNET_PREFIX


class TestBech32(TestCase):
    def setUp(self):
        pass

    def test_encode_decode_addresses(self):
        addrs = ['bcrt1qs4xe0x388ygy7drku9gkf2n0emcwj5xms0tnkw']
        print('Decoding')
        for addr in addrs:
            decoded = bech32decode(addr)
            print(decoded)
            assert addr == bech32encode(decoded, prefix=BECH32_BITCOIN_REGTEST_PREFIX)

    def test_encode_decode_mainnet_addresses(self):
        addrs = [
            'bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej',
            'bc1qepn5e55urrelwar3jnzz6w853lxz4vfpysskmmat9mk36u46cvvqtnala0',
            'bc1qurj278havq0phe7y3heufmck246xrnxhtyx5sa92pytky655pr6qsqzzxa',
            'bc1q9909xggg842c58v3cncp9l35vv65gxx8mu3483x3w8xvk8a8ng0stfyrd9',
            'bc1qakft6s8shk0dgunet53pzapsuxc7ewagfj77l6j8358xt6sumtgq9g650j',
            'bc1qkmtl43j4kqucux3tgr52wx9jqfqwy0xjyn89rldu8pm2ksneynksul2ta2',
            'bc1qfa4ycsdv6uv774zjrtvxrp55qvg439ykre3ttm56vw2dhvk8hhnssjjyzs'
        ]
        print('Decoding')
        for addr in addrs:
            decoded = bech32decode(addr)
            assert addr == bech32encode(decoded, prefix=BECH32_BITCOIN_PREFIX)

    def test_encode_decode_custom_signet_addresses(self):
        addrs = [
            'cbc1q782kzgu4s4l2mke75rta8u0uakyh5qymxduxxt',
            'cbc1qec0ye5g7ldmmfs88597j7tdl63c9xekrfszwrg',
            'cbc1qcsupznu7kta43fmrsu4dkcwargwwudd05rljhg',
            'cbc1q3f9fder9ss9x25l8auu0pm8gaa25p7u7m5yzlk',
            'cbc1qclg2sltl80ux22rxsx3mqmh2wpjd46gltvenva',
            'cbc1qs2fmhkg3cx9fxvy8gtq8ppxq0qlcccck4ghlz2',
        ]
        print('Decoding')
        for addr in addrs:
            decoded = bech32decode(addr)
            assert addr == bech32encode(decoded, prefix=BECH32_CUSTOM_SIGNET_PREFIX)

    def test_encode_decode(self):
        transaction = "010000000001019fa7fad392a29f74d124a8770d24e23f0fcc3e3007e756e4114e4b950a5cf37a0200000000f" \
                      "fffffff02402d0e20000000001976a914c0123fd352e7f53a9c4c0e512c490e1a6817dffa88acb19066000000" \
                      "0000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d040048304502210" \
                      "0f227d07b7ca8bef3b9d591fc46803b1fc6b41290b3b229064726eee5c3d6fc8b02206450b248d4d035a121e6" \
                      "92d7a0e1b720801e1fd30255f5d1f099dbca61eb92dc01483045022100966181ecf84d9a75be1c7654a29ce2a" \
                      "1cba32b2bfb9988d6564ae3bc7358420702200a5e54430e1a9c4537c84d9159243cbfe020fbac2fa7e09b8cd6" \
                      "efb08c984432016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c210" \
                      "3a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3" \
                      "e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"

        expected_address = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
        decoded_expected_address = bech32decode(expected_address)
        deserialized = deserialize(transaction)
        assert decoded_expected_address == deserialized['outs'][1]['script']
        re_encoded_address = bech32encode(deserialized['outs'][1]['script'])
        assert re_encoded_address == expected_address

    def test_testnet_encode_decode(self):
        transaction = "01000000000104acb16c8695c04bfff4857d7b6115ca1a539775c4ea396804038c0cd1acbd595c01000000171600" \
                      "14c7ed016bcf101160cd0b146a40133dc8eb6585fbffffffff87b40d41dac1f128fdf89e72ecda7fb5b286f5f586" \
                      "7164e3dd7a581ab53324270000000000ffffffff9b81806b10bf25e255164f026b9fff2ea9af0fe7b3a2ecdce974" \
                      "09b8f85d0e5a0000000000ffffffffdb7234b54fa8bb299248010e0062e141a42579f4e7642d258d1a889a0210c7" \
                      "490000000000ffffffff015838a21e00000000160014854d979a2739104f3476e15164aa6fcef0e950db02473044" \
                      "02206cc1163d3dfe22155c6479470391dcba86e3ccec7d783bb87bbce7cc47660ab102207c02779f21c835085e39" \
                      "24ff85541efa980cb350e1a3513b880b250fac491dd6012102b99f659fadd83993c4858d181922d5c9a8db74edb3" \
                      "6f2a7bbd84300a234d571b0247304402203eb46a7f5c84909291f81d5852421c62a6c19424343d4330f94a50eaf3" \
                      "01c31902200b9e406cd21613ba8022e3b2fe16bf00acf90b6faf8980ee56bd92c10bc2a8db012102d732900601aa" \
                      "2915532ff55ad8603f0c433eef9370ff9292b9696f2681588a720247304402201faecf60e30ebab7d3bbd05984ff" \
                      "f39c5c572fdf03567449a24152c24cdc1cab022078f9e0b338f26d2296c6882fb202ca73f7e229b441617951d879" \
                      "54c5881fb7eb01210376e28d103288b69b4e727ea384b9fa5a2833d68706b411f1cade00b681faea670248304502" \
                      "2100b0bc4018cf71e7d8f0af6b47e8c3bf531ed436abc946bc16fd466cd4f4d535ac02206f3706a9c423933855e6" \
                      "0ff876f4938aee30c0e81ed683c7e4c6286e97992ae0012103820065f5d287223d1c098db514c87e76d24089ca4c" \
                      "e5d4f208b4da97f2b5615800000000"

        expected_address = "tb1qs4xe0x388ygy7drku9gkf2n0emcwj5xmjxj7p8"
        decoded_expected_address = bech32decode(expected_address)
        deserialized = deserialize(transaction)
        assert decoded_expected_address == deserialized['outs'][0]['script']
        re_encoded_address = bech32encode(deserialized['outs'][0]['script'], prefix=BECH32_BITCOIN_TESTNET_PREFIX)
        assert re_encoded_address == expected_address

    def test_vectors(self):
        vectors = {
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4":
                "0014751e76e8199196d454941c45d1b3a323f1433bd6",

            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7":
                "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",

            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx":
                "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",

            "BC1SW50QA3JX3S":
                "6002751e",

            "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj":
                "5210751e76e8199196d454941c45d1b3a323",

            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy":
                "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
        }
        for vector in vectors.items():
            assert bech32decode(vector[0]) == vector[1], (bech32decode(vector[0]), vector[1])

    def test_invalid_vectors(self):
        vectors = [
            'tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty',
            'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
            'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2',
            'bc1rw5uspcuh',
            'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90',
            'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
            'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
            'bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du',
            'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv',
            'bc1gmk9yu'
        ]
        with self.assertRaises(Exception):
            for vector in vectors:
                bech32decode(vector)

    def test_mktx(self):
        address = 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7'
        inputs = [
            {
                'output': 'ff'*32 + ':0',
                'value': 100,
                'segregated': True
            }
        ]
        outputs = [
            {
                'value': 100,
                'address': address
            }
        ]
        tx = mktx(inputs, outputs)
        print(tx)
        deserialized = deserialize(tx)
        re_encoded_address = bech32encode(deserialized['outs'][0]['script'], prefix=BECH32_BITCOIN_TESTNET_PREFIX)
        assert re_encoded_address == address
        decoded = bech32decode(re_encoded_address)
        self.assertEqual(deserialized['outs'][0]['script'], decoded)

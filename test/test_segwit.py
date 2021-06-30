import unittest

import bitcoin
from bitcoin import deserialize, segwit_sign, mktx, serialize, SIGHASH_ALL, p2pk_sign, \
    strip_witness_data, privtopub, segwit_multisign, \
    apply_segwit_multisignatures, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY, mk_multisig_script, \
    SIGHASH_NONE, mk_OPCS_multisig_script
import os

TEST_CASES = [
    {
        'description': 'Native P2WPKH. SIGHASH_ALL',
        'unsigned': '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000',
        'ins': [
            {
                'txid': '9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff',
                'sequence': 4294967278,
                'index': 0,
                'scriptSig': '2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac',
                'privkey': 'bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866',
            },
            {
                'txid': '8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef',
                'amount': 6,
                'sequence': 4294967295,
                'index': 1,
                'txinwitness': [
                    '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01',
                    '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357'
                ],
                'scriptSig': '',
                'privkey': '619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9',
                'pubkey': '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357'
            }
        ],
        'outs': [
            {
                'value': 1.12340000,
                'script': '76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac',
                'address': 'DH38ZWSZ7u6xpkXx9td6rfrZpvkU9ssuJf'
            },
            {
                'value': 2.23450000,
                'script': '76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac',
                'address': 'DAbefZ33P8TbiWubFaEj6Z2UTwgNsksfKf'
            }
        ],
        'locktime': 17,
        'sighash': 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670',
        'signature': '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee',
        'signed': '01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000',
        'txid': 'e8151a2af31c368a35053ddd4bdb285a8595c769a3ad83e0fa02314a602d4609',
        'hash': 'c36c38370907df2324d9ce9d149d191192f338b37665a82e78e76a12c909b762'
    },
    {
        'description': 'Native P2WSH. SIGHASH_SINGLE on segregated input, SIGHASH_ALL on P2PK input. OP_CODESEPARATOR is present and must be evaluated',
        'unsigned': '0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000',
        'ins': [
            {
                'txid': '6eb316926b1c5d567cd6f5e6a84fec606fc53d7b474526d1fff3948020c93dfe',
                'sequence': 4294967295,
                'index': 0,
                'scriptSig': '21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac',
                'privkey': 'b8f28a772fccbf9b4f58a4f027e07dc2e35e7cd80529975e292ea34f84c4580c',
                'pubkey': '036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8'
            },
            {
                'txid': 'f825690aee1b3dc247da796cacb12687a5e802429fd291cfd63e010f02cf1508',
                'amount': 49,
                'sequence': 4294967295,
                'index': 0,
                'witness_script': '21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac',
                'txinwitness': [
                    '304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503',
                    '3044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e2703',
                    '21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac'
                ],
                'scriptSig': '',
                'privkeys': [
                    '8e02b539b1500aa7c81cf3fed177448a546f19d2be416c0c61ff28e577d8d0cd',
                    '86bf2ed75935a0cbef03b89d72034bb4c189d381037a5ac121a70016db8896ec'
                ],
                'pubkeys': [
                    '026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae'
                    '0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465'
                ],
                'sighashes': [
                    '82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391',
                    'fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47'
                ],
                'signatures': [
                    '3044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e2703',
                    '304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503'
                ]
            }
        ],
        'outs': [
            {
                'value': 50,
                'script': '76a914a30741f8145e5acadf23f751864167f32e0963f788ac',
                'address': 'DL17NoMdkcSvxc911P1worbVuLKBpUqpQ5'
            }
        ],
        'locktime': 0,
        'signed': '01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000',
        'txid': '570e3730deeea7bd8bc92c836ccdeb4dd4556f2c33f2a1f7b889a4cb4e48d3ab',
        'hash': 'dbff04c7044a569f179c843e929449f6a24be183e42c66be9032f1c9eaaf5811'
    },
    {
        'description': 'Native P2WSH. SIGHASH_SINGLE|ANYONECANPAY on segregated inputs',
        'unsigned': '0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000',
        'ins': [
            {
                'txid': '01c0cf7fba650638e55eb91261b183251fbb466f90dff17f10086817c542b5e9',
                'sequence': 4294967295,
                'amount': 0.16777215,
                'index': 0,
                'scriptSig': '',
                'privkey': 'f52b3484edd96598e02a9c89c4492e9c1e2031f471c49fd721fe68b3ce37780d',
                'pubkey': '0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98',
                'txinwitness': [
                    '3045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683',
                    '0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac'
                ],
                'separator': None
            },
            {
                'txid': '1b2a9a426ba603ba357ce7773cb5805cb9c7c2b386d100d1fc9263513188e680',
                'amount': 0.16777215,
                'sequence': 4294967295,
                'index': 0,
                'scriptSig': '',
                'privkey': 'f52b3484edd96598e02a9c89c4492e9c1e2031f471c49fd721fe68b3ce37780d',
                'pubkey': '0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98',
                'txinwitness': [
                    '30440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83',
                    '5163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac'
                ],
                'separator': 1
            }
        ],
        'outs': [
            {
                'value': 0.1,
                'script': '76a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac',
                'address': 'DRQUZTaPzSE2rfp9DPBdfzYhkmEndN2at7'
            },
            {
                'value': 0.1,
                'script': '76a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac',
                'address': 'DETvWHdUXVFWkX1ZyfZhkvRzEAUYp7pEVX'
            }
        ],
        'locktime': 0,
        'signed': '01000000000102e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000',
        'txid': 'e0b8142f587aaa322ca32abce469e90eda187f3851043cc4f2a0fff8c13fc84e',
        'hash': '6e4dd6473b52c00afec3af31b4a522eb9b51489683ce407a6c403313a0caa7a9'
    },
    {
        'description': 'This example is a P2SH-P2WSH 6-of-6 multisig witness program signed with 6 different SIGHASH types.',
        'unsigned': '010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000',
        'ins': [
            {
                'txid': '6eb98797a21c6c10aa74edf29d618be109f48a8e94c694f3701e08ca69186436',
                'amount': 9.87654321,
                'sequence': 4294967295,
                'index': 1,
                'scriptSig': 'a9149993a429037b5d912407a71c252019287b8d27a587',
                'redeem_script': '0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54',
                'witness_script': '56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae',
                'pubkeys': [
                    '0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3',
                    '03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b',
                    '034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a',
                    '033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f4',
                    '03a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac16',
                    '02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b',
                ],
                'privkeys': [
                    '730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6',
                    '11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3',
                    '77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661',
                    '14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49',
                    'fe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323',
                    '428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890'
                ],
                'txinwitness': [
                    '',
                    '304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01',
                    '3044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502',
                    '3044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403',
                    '3045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381',
                    '3045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a0882',
                    '30440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783',
                    '56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae'

                ],
                'separator': 0
            }
        ],
        'outs': [
            {
                'value': 9,
                'script': '76a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688ac',
                'address': 'DAJW3A81BXuRS2TnMBxZRvj4LADkcYDxp2'
            },
            {
                'value': 0.87,
                'script': '76a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac',
                'address': 'DFm72QyF5ke5ikFQYL2qYv4APNC3T76T8P'
            }
        ],
        'locktime': 0,
        'signed': '0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000',
        'txid': '27eae69aff1dd4388c0fa05cbbfe9a3983d1b0b5811ebcd4199b86f299370aac',
        'hash': '65dab5dd46a501fc695822c73d779067f2feb7c49dc47d39f86fdb2e3960b3bd'
    },
]

class Test_SegregatedWitness(unittest.TestCase):

    """
    BIPs in these tests:
    - https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    - https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    """
    @staticmethod
    def get_pybtc_vins(tx):
        ins = []
        for vin in tx['ins']:
            v = {'output': '{}:{}'.format(vin['txid'], vin['index'])}
            if vin.get('txinwitness'):
                v['segregated'] = True
            if vin.get('sequence'):
                v['sequence'] = vin['sequence']
            ins.append(v)
        return ins

    @staticmethod
    def get_pybtc_outs(tx):
        outs = []
        for out in tx['outs']:
            o = {'value': int(out['value'] * 10**8)}
            if out.get('address'):
                o['address'] = out['address']
            else:
                o['script'] = out['script']
            outs.append(o)
        return outs

    @staticmethod
    def append_compressed_flag_to_privkey(privkey):
        return privkey + '01'

    def test_native_P2WPKH_SIGHASH_ALL(self):
        tx = TEST_CASES[0]
        deserialized = deserialize(tx['unsigned'])
        serialized = serialize(deserialized)
        self.assertEqual(serialized, tx['unsigned'])
        self.assertEqual(deserialized['locktime'], tx['locktime'])
        ins = self.get_pybtc_vins(tx)
        outs = self.get_pybtc_outs(tx)
        generated_tx = mktx(ins, outs, locktime=tx['locktime'])
        stripped_tx = strip_witness_data(generated_tx)
        self.assertEqual(stripped_tx, serialized)
        partially_signed = p2pk_sign(stripped_tx,
                                     0,
                                     self.append_compressed_flag_to_privkey(tx['ins'][0]['privkey']))
        signed = segwit_sign(partially_signed,
                             1,
                             self.append_compressed_flag_to_privkey(tx['ins'][1]['privkey']),
                             tx['ins'][1]['amount'] * 10**8)
        self.assertEqual(signed, tx['signed'])
        print('[Native P2WPKH] SIGHASH_ALL OK')

    def test_native_P2WSH_SIGHASH_SINGLE(self):
        tx = TEST_CASES[1]
        deserialized = deserialize(tx['unsigned'])
        serialized = serialize(deserialized)
        self.assertEqual(serialized, tx['unsigned'])
        self.assertEqual(deserialized['locktime'], tx['locktime'])
        ins = self.get_pybtc_vins(tx)
        outs = self.get_pybtc_outs(tx)
        generated_tx = mktx(ins, outs)
        stripped_tx = strip_witness_data(generated_tx)
        self.assertEqual(stripped_tx, serialized)
        partially_signed = p2pk_sign(stripped_tx,
                                     0,
                                     self.append_compressed_flag_to_privkey(tx['ins'][0]['privkey']),
                                     hashcode=SIGHASH_ALL)
        priv0 = self.append_compressed_flag_to_privkey(tx['ins'][1]['privkeys'][0])
        priv1 = self.append_compressed_flag_to_privkey(tx['ins'][1]['privkeys'][1])
        pub0 = privtopub(priv0)
        pub1 = privtopub(priv1)
        REDEEM_SCRIPT_STRUCTURE = {
            'keys': [
                pub0,
                pub1
            ],
            'schema': [
                {
                    'reqs': 1,
                    'keys': [0],
                },
                {
                    'reqs': 1,
                    'keys': [1],
                }
            ]
        }
        witness_script = mk_OPCS_multisig_script(REDEEM_SCRIPT_STRUCTURE)
        sign1 = segwit_multisign(partially_signed,
                                 1,
                                 witness_script,
                                 priv0,
                                 49 * 10**8,
                                 hashcode=SIGHASH_SINGLE)
        sign2 = segwit_multisign(partially_signed,
                                 1,
                                 witness_script,
                                 priv1,
                                 49 * 10 ** 8,
                                 hashcode=SIGHASH_SINGLE,
                                 separator_index=1)
        signed = apply_segwit_multisignatures(partially_signed, 1, witness_script, [sign2, sign1], dummy=False)
        self.assertEqual(signed, tx['signed'])
        print('[Native P2WSH] SIGHASH_SINGLE OK')


    def test_native_P2WSH_SIGHASH_SINGLE_ANYONECANPAY(self):
        tx = TEST_CASES[2]
        deserialized = deserialize(tx['unsigned'])
        serialized = serialize(deserialized)
        self.assertEqual(serialized, tx['unsigned'])
        self.assertEqual(deserialized['locktime'], tx['locktime'])
        ins = self.get_pybtc_vins(tx)
        outs = self.get_pybtc_outs(tx)
        generated_tx = mktx(ins, outs)
        stripped_tx = strip_witness_data(generated_tx)
        self.assertEqual(stripped_tx, serialized)
        priv0 = self.append_compressed_flag_to_privkey(tx['ins'][1]['privkey'])
        partially_signed = segwit_sign(generated_tx,
                                       0,
                                       priv0,
                                       int(0.16777215 * 10**8),
                                       hashcode=SIGHASH_SINGLE|SIGHASH_ANYONECANPAY,
                                       script=tx['ins'][0]['txinwitness'][1])

        signed = segwit_sign(partially_signed,
                             1,
                             priv0,
                             int(0.16777215 * 10 ** 8),
                             hashcode=SIGHASH_SINGLE|SIGHASH_ANYONECANPAY,
                             script=tx['ins'][1]['txinwitness'][1],
                             separator_index=tx['ins'][1]['separator'])
        self.assertEqual(signed, tx['signed'])
        print('[Native P2WSH] SIGHASH_SINGLE OK')


    def test_P2SH_P2WSH_ALL_SIGHASH(self):
        tx = TEST_CASES[3]
        VIN_AMOUNT = int(9.87654321 * 10**8)
        deserialized = deserialize(tx['unsigned'])
        serialized = serialize(deserialized)
        self.assertEqual(serialized, tx['unsigned'])
        self.assertEqual(deserialized['locktime'], tx['locktime'])
        ins = self.get_pybtc_vins(tx)
        outs = self.get_pybtc_outs(tx)
        generated_tx = mktx(ins, outs)
        stripped_tx = strip_witness_data(generated_tx)
        self.assertEqual(stripped_tx, serialized)
        priv0 = self.append_compressed_flag_to_privkey(tx['ins'][0]['privkeys'][0])
        priv1 = self.append_compressed_flag_to_privkey(tx['ins'][0]['privkeys'][1])
        priv2 = self.append_compressed_flag_to_privkey(tx['ins'][0]['privkeys'][2])
        priv3 = self.append_compressed_flag_to_privkey(tx['ins'][0]['privkeys'][3])
        priv4 = self.append_compressed_flag_to_privkey(tx['ins'][0]['privkeys'][4])
        priv5 = self.append_compressed_flag_to_privkey(tx['ins'][0]['privkeys'][5])
        witness_script = mk_multisig_script(privtopub(priv0),
                                            privtopub(priv1),
                                            privtopub(priv2),
                                            privtopub(priv3),
                                            privtopub(priv4),
                                            privtopub(priv5),
                                            6)
        self.assertEqual(witness_script, tx['ins'][0]['witness_script'])
        sign0 = segwit_multisign(generated_tx,
                                 0,
                                 witness_script,
                                 priv0,
                                 VIN_AMOUNT,
                                 hashcode=SIGHASH_ALL)
        sign1 = segwit_multisign(generated_tx,
                                 0,
                                 witness_script,
                                 priv1,
                                 VIN_AMOUNT,
                                 hashcode=SIGHASH_NONE)
        sign2 = segwit_multisign(generated_tx,
                                 0,
                                 witness_script,
                                 priv2,
                                 VIN_AMOUNT,
                                 hashcode=SIGHASH_SINGLE)
        sign3 = segwit_multisign(generated_tx,
                                 0,
                                 witness_script,
                                 priv3,
                                 VIN_AMOUNT,
                                 hashcode=SIGHASH_ALL|SIGHASH_ANYONECANPAY)
        sign4 = segwit_multisign(generated_tx,
                                 0,
                                 witness_script,
                                 priv4,
                                 VIN_AMOUNT,
                                 hashcode=SIGHASH_NONE|SIGHASH_ANYONECANPAY)
        sign5 = segwit_multisign(generated_tx,
                                 0,
                                 witness_script,
                                 priv5,
                                 VIN_AMOUNT,
                                 hashcode=SIGHASH_SINGLE|SIGHASH_ANYONECANPAY)
        signed = apply_segwit_multisignatures(stripped_tx, 0, witness_script,
                                              [sign0, sign1, sign2, sign3, sign4, sign5],
                                              nested=True)
        self.assertEqual(signed, tx['signed'])
        print('[P2WSH 6-of-6 multisig NESTED in P2SH] SIGHASH_SINGLE\SIGHASH_ALL\SIGHASH_NONE & ANYONECANPAY')

    def test_strip_witness_data(self):
        tx = '010000000001000000000000000017a9140c1ca20d939dab33b3bc97c7afd1cd9a47bd817b8700000000'
        deserialized = bitcoin.deserialize(tx)
        print(deserialized)
        #bitcoin.strip_witness_data(tx)
        x = "010000000001015db5dc862868c35854cf987cc926d3184913d592d5d2e75a6a40cb304047d7170000000000fdffffff0270460d000000000022002023a714e47dfa0e29b3d0a3d97c352f18b49d8c5b4786500ec3b64280628af9f342260000000000002200205b3f2605d30023c8f56759ee3ccbeb86e22bf9ae8f262a66ce90eb12ceb96b5b040047304402206ec9d8923d331b985a38c59e324b43716bcdda0d14d9f88b1ba488b3d67404bc02202771d4ed7aae55fd2e1f11acedd38dfcfd00051b77e152496762f5efcefd64b701483045022100b52c4efd67eff8d63269876ef6dc0b3f77bb738bca4a73281400041b0c79c94002207f9b6019e16f15a4770a98718ebed2e97c079d6bf47729bac45ce9695b5cc4210169522103b6213add5c25b1753f8c4cf1c6886082b2102faaee42519c2c08b3e4ec6564f22102dd4140b47bdea1d0d283f2ded030635f549389ecfc3470e343921df24bce31982103f70d869176ab1c57b16f79b5f0505c0d90ee1f7ea0b6f473d4f82c2d6beff4f853ae00000000"
        y = bitcoin.deserialize(x)
        for i, x in enumerate(y['ins']):
            y['ins'][i]['txinwitness'] = []
        print('ddd', bitcoin.serialize(y))


if __name__ == '__main__':
    unittest.main()


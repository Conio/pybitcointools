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

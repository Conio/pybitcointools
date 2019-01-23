import unittest
from bitcoin import *


class TestTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Attempting transaction creation")

    # FIXME: I don't know how to write this as a unit test.
    # What should be asserted?
    def test_all(self):
        start = time.time()
        privs = [sha256(str(random.randrange(2**256))) for x in range(4)]
        pubs = [privtopub(priv) for priv in privs]
        addresses = [pubtoaddr(pub) for pub in pubs]
        mscript = mk_multisig_script(pubs[1:], 2, 3)
        msigaddr = p2sh_scriptaddr(mscript)
        tx = mktx(['01'*32+':1', '23'*32+':2'], [msigaddr+':20202', addresses[0]+':40404'], locktime=2222222222)
        tx1 = sign(tx, 1, privs[0])

        self.assertEqual(deserialize(tx)['locktime'], 2222222222, "Locktime incorrect")

        sig1 = multisign(tx, 0, mscript, privs[1])
        self.assertTrue(verify_tx_input(tx1, 0, mscript, sig1, pubs[1]), "Verification Error")

        sig3 = multisign(tx, 0, mscript, privs[3])
        self.assertTrue(verify_tx_input(tx1, 0, mscript, sig3, pubs[3]), "Verification Error")

        tx2 = apply_multisignatures(tx1, 0, mscript, [sig1, sig3])
        print('end %s' % (time.time() - start))

    # https://github.com/vbuterin/pybitcointools/issues/71
    def test_multisig(self):
        start = time.time()
        script = mk_multisig_script(["0254236f7d1124fc07600ad3eec5ac47393bf963fbf0608bcce255e685580d16d9",
                                     "03560cad89031c412ad8619398bd43b3d673cb5bdcdac1afc46449382c6a8e0b2b"],
                                     2)

        self.assertEqual(p2sh_scriptaddr(script), "33byJBaS5N45RHFcatTSt9ZjiGb6nK4iV3")

        self.assertEqual(p2sh_scriptaddr(script, 0x05), "33byJBaS5N45RHFcatTSt9ZjiGb6nK4iV3")
        self.assertEqual(p2sh_scriptaddr(script, 5), "33byJBaS5N45RHFcatTSt9ZjiGb6nK4iV3")

        self.assertEqual(p2sh_scriptaddr(script, 0xc4), "2MuABMvWTgpZRd4tAG25KW6YzvcoGVZDZYP")
        self.assertEqual(p2sh_scriptaddr(script, 196), "2MuABMvWTgpZRd4tAG25KW6YzvcoGVZDZYP")
        print('end %s' % (time.time() - start))

    def test_preparetx(self):
        start = time.time()
        hextx = preparetx('12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX', '1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1', 13)
        tx = deserialize(hextx)
        self.assertEqual(tx['locktime'], 0, "Locktime incorrect")
        self.assertEqual(tx['outs'][0]['value'], 13, "Value incorrect")

        hextx = preparetx('12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX', '1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1', 13, locktime=2222222222)
        tx = deserialize(hextx)
        self.assertEqual(tx['locktime'], 2222222222, "Locktime incorrect")
        self.assertEqual(tx['outs'][0]['value'], 13, "Value incorrect")
        print('end %s' % (time.time() - start))
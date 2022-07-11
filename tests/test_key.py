#!/usr/bin/env python

"""Test cases for "key.py". """

import copy
import os
import unittest
import tempfile
import shutil


import securesystemslib.formats
import securesystemslib.keys as KEYS
from securesystemslib.exceptions import (
    CryptoError,
    FormatError,
)
from securesystemslib.key import GPGKey, SSlibKey
from securesystemslib.signer import GPGSigner, SSlibSigner
from securesystemslib.gpg.constants import HAVE_GPG
from securesystemslib.gpg.functions import export_pubkey


class TestSSlibKey(unittest.TestCase):
    """SSlibKey Test Case."""

    @classmethod
    def setUpClass(cls):
        cls.key_pairs = [
            KEYS.generate_rsa_key(),
            KEYS.generate_ed25519_key(),
            KEYS.generate_ecdsa_key(),
        ]
        cls.DATA_STR = "SOME DATA REQUIRING AUTHENTICITY."
        cls.DATA = securesystemslib.formats.encode_canonical(cls.DATA_STR).encode(
            "utf-8"
        )

    def test_sslib_verify(self):
        """Test to check verify method of key."""

        for key_pair in self.key_pairs:
            sslib_signer = SSlibSigner(key_pair)
            sig_obj = sslib_signer.sign(self.DATA)

            # Verify signature.
            sslib_key = SSlibKey.from_securesystemslib_key(key_pair)
            verified = sslib_key.verify(sig_obj, self.DATA)
            self.assertTrue(verified, "Incorrect signature.")

            # Test for invalid public key.
            public = key_pair["keyval"]["public"]
            key_pair["keyval"]["public"] = ""
            sslib_key = SSlibKey.from_securesystemslib_key(key_pair)

            with self.assertRaises((CryptoError, FormatError)):
                sslib_key.verify(sig_obj, self.DATA)

            key_pair["keyval"]["public"] = public

    def test_sslib_serialization(self):
        """Test to check serialization methods of key."""

        for key_pair in self.key_pairs:
            # Format key.
            key_dict = KEYS.format_keyval_to_metadata(
                key_pair["keytype"],
                key_pair["scheme"],
                key_pair["keyval"],
            )
            # key_dict contains keyid_hash_algorithms.
            key_dict.pop("keyid_hash_algorithms")

            keyid = key_pair["keyid"]

            # Test for load and dump key_dict.
            sslib_key = SSlibKey.from_dict(copy.copy(key_dict), keyid)
            self.assertEqual(key_dict, sslib_key.to_dict())

            # Test for load and dump securesystemslib_key.
            key_dict["keyid"] = keyid
            sslib_key = SSlibKey.from_securesystemslib_key(key_dict)
            self.assertEqual(key_dict, sslib_key.to_securesystemslib_key())

            # Test for invalid keytype.
            valid_keytype = key_pair["keytype"]
            key_pair["keytype"] = "invalid_keytype"
            with self.assertRaises(FormatError):
                SSlibKey.from_securesystemslib_key(key_pair)

            key_pair["keytype"] = valid_keytype

    def test_sslib_equality(self):
        """Test to check equality of key."""

        for key_pair in self.key_pairs:
            # Create two keys.
            sslib_key = SSlibKey.from_securesystemslib_key(key_pair)
            sslib_key_2 = SSlibKey.from_securesystemslib_key(key_pair)

            # Assert not equal with key_pair.
            self.assertNotEqual(key_pair, sslib_key)

            # Assert equality of two keys created from same securesystemslib_key.
            self.assertEqual(sslib_key_2, sslib_key)

            # Assert equality of key created from dict of first sslib_key.
            sslib_key_2 = SSlibKey.from_securesystemslib_key(
                sslib_key.to_securesystemslib_key()
            )
            self.assertEqual(sslib_key_2, sslib_key)

            # Assert inequalities.
            sslib_key_2.scheme = "invalid"
            self.assertNotEqual(sslib_key_2, sslib_key)
            sslib_key_2.scheme = sslib_key.scheme

            sslib_key_2.keytype = "invalid"
            self.assertNotEqual(sslib_key_2, sslib_key)
            sslib_key_2.keytype = sslib_key.keytype

            sslib_key_2.keyval = {"public": "invalid"}
            self.assertNotEqual(sslib_key_2, sslib_key)
            sslib_key_2.keyval = sslib_key.keyval

            self.assertEqual(sslib_key_2, sslib_key)


@unittest.skipIf(not HAVE_GPG, "gpg not found")
class TestGPGKey(unittest.TestCase):
    """GPGKey Test Case."""

    @classmethod
    def setUpClass(cls):

        cls.default_keyid = "8465A1E2E0FB2B40ADB2478E18FB3F537E0C8A17"
        cls.signing_subkey_keyid = "C5A0ABE6EC19D0D65F85E2C39BE9DF5131D924E9"

        # Create directory to run the tests without having everything blow up.
        cls.working_dir = os.getcwd()
        cls.test_data = b"test_data"
        cls.wrong_data = b"wrong_data"

        # Find demo files.
        gpg_keyring_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "rsa"
        )

        cls.test_dir = os.path.realpath(tempfile.mkdtemp())
        cls.gnupg_home = os.path.join(cls.test_dir, "rsa")
        shutil.copytree(gpg_keyring_path, cls.gnupg_home)
        os.chdir(cls.test_dir)

        cls.default_key_dict = export_pubkey(cls.default_keyid, cls.gnupg_home)

    @classmethod
    def tearDownClass(cls):
        """Change back to initial working dir and remove temp test directory."""

        os.chdir(cls.working_dir)
        shutil.rmtree(cls.test_dir)

    def test_gpg_verify_with_default_key(self):
        """Test to check verify method of GPGkey."""

        # Create a signature.
        signer = GPGSigner(homedir=self.gnupg_home)
        signature = signer.sign(self.test_data)

        # Generate Key from gnupg keyring.
        key = GPGKey.from_keyring(self.default_keyid, self.gnupg_home)

        self.assertTrue(key.verify(signature, self.test_data))
        self.assertFalse(key.verify(signature, self.wrong_data))

        # Generate Key from dict.
        key = GPGKey.from_dict(self.default_key_dict)

        self.assertTrue(key.verify(signature, self.test_data))
        self.assertFalse(key.verify(signature, self.wrong_data))

    def test_gpg_verify(self):
        """Test to check verify method of GPGKey."""

        # Create a signature.
        signer = GPGSigner(self.signing_subkey_keyid, self.gnupg_home)
        signature = signer.sign(self.test_data)

        # Generate Key from gnupg keyring.
        key = GPGKey.from_keyring(self.signing_subkey_keyid, self.gnupg_home)

        self.assertTrue(key.verify(signature, self.test_data))
        self.assertFalse(key.verify(signature, self.wrong_data))

        # Generate Key from dict.
        key_dict = export_pubkey(self.signing_subkey_keyid, self.gnupg_home)
        key = GPGKey.from_dict(key_dict)

        self.assertTrue(key.verify(signature, self.test_data))
        self.assertFalse(key.verify(signature, self.wrong_data))

    def test_sslib_serialization(self):
        """Test to check serialization methods of GPGKey."""

        # Test loading and dumping of GPGKey.
        key = GPGKey.from_dict(self.default_key_dict)
        self.assertEqual(key.to_dict(), self.default_key_dict)

        # Test loading and dumping of GPGKey from keyring.
        key = GPGKey.from_keyring(self.default_keyid, self.gnupg_home)
        self.assertEqual(key.to_dict(), self.default_key_dict)

    def test_gpg_key_equality(self):
        """Test to check equality between two GPGKey."""

        # Generate two GPGkey.
        key1 = GPGKey.from_dict(self.default_key_dict)
        key2 = GPGKey.from_dict(self.default_key_dict)

        self.assertNotEqual(self.default_key_dict, key1)
        self.assertEqual(key2, key1)

        # Assert equality of key created from dict of first GPGKey.
        key2 = GPGKey.from_dict(key1.to_dict())
        self.assertEqual(key2, key1)

        # Assert Inequalities.
        key2.type = "invalid"
        self.assertNotEqual(key2, key1)
        key2.type = key1.type

        key2.subkeys = {}
        self.assertNotEqual(key2, key1)
        key2.subkeys = key1.subkeys

        key2.keyval = {}
        self.assertNotEqual(key2, key1)
        key2.keyval = key1.keyval

        self.assertEqual(key2, key1)


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()

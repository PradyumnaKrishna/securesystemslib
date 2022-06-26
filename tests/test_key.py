#!/usr/bin/env python

"""Test cases for "key.py". """

import copy
import unittest

import securesystemslib.formats
import securesystemslib.keys as KEYS
from securesystemslib.exceptions import (
    CryptoError,
    FormatError,
    UnsupportedAlgorithmError,
)
from securesystemslib.key import SSlibKey
from securesystemslib.signer import SSlibSigner


class TestSSlibKey(unittest.TestCase):
    """SSlibKey Test Case."""

    @classmethod
    def setUpClass(cls):
        cls.dicts = [
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

        for scheme_dict in self.dicts:
            sslib_signer = SSlibSigner(scheme_dict)
            sig_obj = sslib_signer.sign(self.DATA)

            # Verify signature.
            sslib_key = SSlibKey.from_securesystemslib_key(scheme_dict)
            verified = sslib_key.verify(sig_obj, self.DATA)
            self.assertTrue(verified, "Incorrect signature.")

            # Test for invalid public key.
            public = scheme_dict["keyval"]["public"]
            scheme_dict["keyval"]["public"] = ""
            sslib_key = SSlibKey.from_securesystemslib_key(scheme_dict)

            with self.assertRaises(
                (CryptoError, UnsupportedAlgorithmError, FormatError)
            ):
                sslib_key.verify(sig_obj, self.DATA)

            scheme_dict["keyval"]["public"] = public

    def test_sslib_serialization(self):
        """Test to check serialization methods of key."""

        for scheme_dict in self.dicts:
            # Format key.
            key_dict = KEYS.format_keyval_to_metadata(
                scheme_dict["keytype"],
                scheme_dict["scheme"],
                scheme_dict["keyval"],
            )
            # key_dict contains keyid_hash_algorithms.
            key_dict.pop("keyid_hash_algorithms")

            keyid = scheme_dict["keyid"]

            # Test for load and dump key_dict.
            sslib_key = SSlibKey.from_dict(copy.copy(key_dict), keyid)
            self.assertEqual(key_dict, sslib_key.to_dict())

            # Test for load and dump key_dict without keyid.
            sslib_key = SSlibKey.from_dict(copy.copy(key_dict))
            self.assertEqual(key_dict, sslib_key.to_dict())

            # Test for load and dump securesystemslib_key.
            key_dict["keyid"] = keyid
            sslib_key = SSlibKey.from_securesystemslib_key(key_dict)
            self.assertEqual(key_dict, sslib_key.to_securesystemslib_key())

            # Test for invalid keytype.
            valid_keytype = scheme_dict["keytype"]
            scheme_dict["keytype"] = "invalid_keytype"
            with self.assertRaises((ValueError, FormatError)):
                SSlibKey.from_securesystemslib_key(scheme_dict)

            scheme_dict["keytype"] = valid_keytype

    def test_sslib_equality(self):
        """Test to check equality of key."""

        for scheme_dict in self.dicts:
            # Create two keys.
            sslib_key = SSlibKey.from_securesystemslib_key(scheme_dict)
            sslib_key_2 = SSlibKey.from_securesystemslib_key(scheme_dict)

            # Assert not equal with scheme_dict.
            self.assertNotEqual(scheme_dict, sslib_key)

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


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()

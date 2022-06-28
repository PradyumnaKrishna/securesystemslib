#!/usr/bin/env python

"""Test cases for "metadata.py". """

import copy
import unittest

import securesystemslib.keys as KEYS
from securesystemslib.exceptions import (
    FormatError,
    SignatureVerificationError,
    UnsupportedAlgorithmError,
)
from securesystemslib.key import SSlibKey
from securesystemslib.metadata import Envelope
from securesystemslib.signer import Signature, SSlibSigner


class TestEnvelope(unittest.TestCase):
    """Test metadata interface provided by DSSE envelope."""

    @classmethod
    def setUpClass(cls):
        cls.key_dicts = [
            ("rsa", KEYS.generate_rsa_key()),
            ("ecdsa", KEYS.generate_ed25519_key()),
            ("ed25519", KEYS.generate_ecdsa_key()),
        ]

        cls.signature_dict = {
            "keyid": "11fa391a0ed7a447cbfeb4b2667e286fc248f64d5e6d0eeed2e5e23f97f9f714",
            "sig": "30460221009342e4566528fcecf6a7a5d53ebacdb1df151e242f55f8775883469cb01dbc6602210086b426cc826709acfa2c3f9214610cb0a832db94bbd266fd7c5939a48064a851",
        }
        cls.envelope_dict = {
            "payload": "aGVsbG8gd29ybGQ=",
            "payloadType": "http://example.com/HelloWorld",
            "signatures": [cls.signature_dict],
        }
        cls.pae = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"

    def test_envelope_from_to_dict(self):
        """Test envelope to_dict and from_dict methods"""

        envelope_dict = copy.deepcopy(self.envelope_dict)

        # create envelope object from its dict.
        envelope_obj = Envelope.from_dict(envelope_dict)

        # Assert envelope dict created by to_dict will be equal.
        self.assertDictEqual(self.envelope_dict, envelope_obj.to_dict())

        # Assert TypeError on invalid signature
        envelope_dict["signatures"] = [""]
        self.assertRaises(FormatError, Envelope.from_dict, envelope_dict)

    def test_envelope_eq_(self):
        """Test envelope equality"""

        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))

        # Assert that object and None will not be equal.
        self.assertNotEqual(None, envelope_obj)

        # Assert a copy of envelope_obj will be equal to envelope_obj.
        envelope_obj_2 = copy.deepcopy(envelope_obj)
        self.assertEqual(envelope_obj, envelope_obj_2)

        # Assert that changing the "payload" will make the objects not equal.
        envelope_obj_2.payload = b"wrong_payload"
        self.assertNotEqual(envelope_obj, envelope_obj_2)
        envelope_obj_2.payload = envelope_obj.payload

        # Assert that changing the "payload_type" will make the objects not equal.
        envelope_obj_2.payload_type = "wrong_payload_type"
        self.assertNotEqual(envelope_obj, envelope_obj_2)
        envelope_obj_2.payload = envelope_obj.payload

        # Assert that changing the "signatures" will make the objects not equal.
        sig_obg = Signature("", self.signature_dict["sig"])
        envelope_obj_2.signatures = [sig_obg]
        self.assertNotEqual(envelope_obj, envelope_obj_2)

    def test_preauthencoding(self):
        """Test envelope Pre-Auth-Encoding"""

        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))

        # Checking for Pre-Auth-Encoding generated is correct.
        self.assertEqual(self.pae, envelope_obj.pae)

    def test_sign(self):
        """Test payload signing of envelope."""

        # Create an Envelope with no signatures.
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)

        for (_, key_dict) in self.key_dicts:
            # Test with key_dict that is not a signer.
            with self.assertRaises(TypeError):
                envelope_obj.sign(key_dict)

            # Test for invalid scheme.
            valid_scheme = key_dict["scheme"]
            key_dict["scheme"] = "invalid_scheme"
            signer = SSlibSigner(key_dict)
            with self.assertRaises((FormatError, UnsupportedAlgorithmError)):
                envelope_obj.sign(signer)

            # Sign the payload.
            key_dict["scheme"] = valid_scheme
            signer = SSlibSigner(key_dict)
            envelope_obj.sign(signer)

        # Tests for signatures created.
        self.assertEqual(len(self.key_dicts), len(envelope_obj.signatures))
        for signature in envelope_obj.signatures:
            self.assertIsInstance(signature, Signature)

    def test_verify(self):
        "Test payload verification of envelope."

        # Create an Evnvelope with no signatures.
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)

        # Sign payload of Envelope.
        for (_, key_dict) in self.key_dicts:
            signer = SSlibSigner(key_dict)
            envelope_obj.sign(signer)

        # Check for signatures of Envelope.
        self.assertEqual(len(self.key_dicts), len(envelope_obj.signatures))

        keys_list = []
        for (name, key_dict) in self.key_dicts:
            keys_list.append(
                (name, SSlibKey.from_securesystemslib_key(key_dict))
            )

        # Test for invalid threshold value for keys_list.
        with self.assertRaises(ValueError):
            envelope_obj.verify(keys_list, 0)

        # Test with invalid KeyList.
        with self.assertRaises(TypeError):
            envelope_obj.verify(self.key_dicts, len(keys_list))

        # Test with valid keylist and threshold.
        verified_keys = envelope_obj.verify(keys_list, len(keys_list))
        self.assertEqual(len(verified_keys), len(keys_list))

        # Test for unknown keys and threshold of 1.
        new_keys = [
            ("unknown_ecdsa", KEYS.generate_ecdsa_key()),
            ("unknown_ed25519", KEYS.generate_ed25519_key()),
            ("unknown_rsa", KEYS.generate_rsa_key()),
        ]
        new_keys_list = []
        for (name, key_dict) in new_keys:
            new_keys_list.append(
                (name, SSlibKey.from_securesystemslib_key(key_dict))
            )

        with self.assertRaises(SignatureVerificationError):
            envelope_obj.verify(new_keys_list, 1)


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()

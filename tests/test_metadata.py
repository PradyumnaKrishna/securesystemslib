#!/usr/bin/env python

"""Test cases for "metadata.py". """

import copy
import os
import unittest
import tempfile
import shutil
from typing import List

import securesystemslib.keys as KEYS
from securesystemslib.exceptions import (
    FormatError,
    SignatureVerificationError,
    UnsupportedAlgorithmError,
)
from securesystemslib.key import GPGKey, Key, SSlibKey
from securesystemslib.metadata import Envelope
from securesystemslib.signer import GPGSignature, GPGSigner, Signature, SSlibSigner

from tests.test_gpg import GPGTestUtils


class TestEnvelope(unittest.TestCase):
    """Test metadata interface provided by DSSE envelope."""

    @classmethod
    def setUpClass(cls):
        cls.key_dicts = [
            KEYS.generate_rsa_key(),
            KEYS.generate_ed25519_key(),
            KEYS.generate_ecdsa_key(),
        ]

        cls.signature_dict = {
            "keyid": "11fa391a0ed7a447",
            "sig": "30460221009342e4566528fcecf6a7a5",
        }
        cls.gpg_signature_dict = {
            "keyid": "f4f90403af58eef6",
            "signature": "c39f86e70e12e70e11d87eb7e3ab7d3b",
            "other_headers": "d8f8a89b5d71f07b842a",
        }
        cls.envelope_dict = {
            "payload": "aGVsbG8gd29ybGQ=",
            "payloadType": "http://example.com/HelloWorld",
            "signatures": [cls.signature_dict, cls.gpg_signature_dict],
        }
        cls.pae = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"

    def test_envelope_from_to_dict(self):
        """Test envelope to_dict and from_dict methods."""

        envelope_dict = copy.deepcopy(self.envelope_dict)

        # create envelope object from its dict.
        envelope_obj = Envelope.from_dict(envelope_dict)
        for signature in envelope_obj.signatures:
            self.assertIsInstance(signature, Signature)

        # Assert envelope dict created by to_dict will be equal.
        self.assertDictEqual(self.envelope_dict, envelope_obj.to_dict())

        # Assert TypeError on invalid signature.
        envelope_dict["signatures"] = [""]
        with self.assertRaises(FormatError):
            Envelope.from_dict(envelope_dict)

        # Assert GPGSignature formation.
        envelope_dict["signatures"] = [self.gpg_signature_dict]
        envelope_obj = Envelope.from_dict(envelope_dict)
        for signature in envelope_obj.signatures:
            self.assertIsInstance(signature, GPGSignature)

    def test_envelope_eq_(self):
        """Test envelope equality."""

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
        self.assertEqual(self.pae, envelope_obj.pae())

    def test_sign_and_verify(self):
        """Test for creating and verifying DSSE signatures."""

        # Create an Envelope with no signatures.
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)

        key_list = []
        for key_dict in self.key_dicts:
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

            # Create a List of "Key" from key_dict.
            key_list.append(SSlibKey.from_securesystemslib_key(key_dict))

        # Check for signatures of Envelope.
        self.assertEqual(len(self.key_dicts), len(envelope_obj.signatures))
        for signature in envelope_obj.signatures:
            self.assertIsInstance(signature, Signature)

        # Test for invalid threshold value for keys_list.
        # threshold is 0.
        with self.assertRaises(ValueError):
            envelope_obj.verify(key_list, 0)

        # threshold is greater than no of keys.
        with self.assertRaises(ValueError):
            envelope_obj.verify(key_list, 4)

        # Test with valid keylist and threshold.
        verified_keys = envelope_obj.verify(key_list, len(key_list))
        self.assertEqual(len(verified_keys), len(key_list))

        # Test for unknown keys and threshold of 1.
        new_key_dicts = [
            KEYS.generate_rsa_key(),
            KEYS.generate_ed25519_key(),
            KEYS.generate_ecdsa_key(),
        ]
        new_key_list = []
        for key_dict in new_key_dicts:
            new_key_list.append(SSlibKey.from_securesystemslib_key(key_dict))

        with self.assertRaises(SignatureVerificationError):
            envelope_obj.verify(new_key_list, 1)

        all_keys = key_list + new_key_list
        envelope_obj.verify(all_keys, 3)

        # Test with duplicate keys.
        duplicate_keys = key_list + key_list
        with self.assertRaises(SignatureVerificationError):
            envelope_obj.verify(duplicate_keys, 4)  # 3 unique keys, threshold 4.


class TestGPGEnvelope(unittest.TestCase):
    """Test for signing and verification of DSSE signatures with GPG."""

    @classmethod
    def setUpClass(cls):
        # Envelope dicts
        cls.envelope_dict = {
            "payload": "aGVsbG8gd29ybGQ=",
            "payloadType": "http://example.com/HelloWorld",
            "signatures": [],
        }
        cls.key_dict = KEYS.generate_rsa_key()

    def test_with_gpg_dsa(self):
        """Test sign and verify methods of DSSE with GPG DSA."""

        default_keyid = "C242A830DAAF1C2BEF604A9EF033A3A3E267B3B1"

        # Create directory to run the tests without having everything blow up.
        working_dir = os.getcwd()
        test_dir = os.path.realpath(tempfile.mkdtemp())
        gnupg_home = os.path.join(test_dir, "dsa")

        # Find demo files.
        gpg_keyring_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "dsa"
        )

        shutil.copytree(gpg_keyring_path, gnupg_home)
        os.chdir(test_dir)

        # Create a GPGSigner and SSlibSigner.
        gpg_signer = GPGSigner(homedir=gnupg_home)
        sslib_signer = SSlibSigner(self.key_dict)

        # Create the DSSE Envelope and sign.
        envelope = Envelope.from_dict(self.envelope_dict)
        gpg_signature = envelope.sign(gpg_signer)
        sslib_signature = envelope.sign(sslib_signer)

        # Assert Types of the generated signatures.
        self.assertIsInstance(sslib_signature, Signature)
        self.assertIsInstance(gpg_signature, GPGSignature)

        # Create GPGKey and SSlibKey.
        gpgkey = GPGKey.from_keyring(keyid=default_keyid, homedir=gnupg_home)
        sslibkey = SSlibKey.from_securesystemslib_key(self.key_dict)
        key_list: List[Key] = []

        # verify the signatures.
        key_list.append(gpgkey)
        envelope.verify(key_list, 1)

        key_list.append(sslibkey)
        envelope.verify(key_list, 2)

        os.chdir(working_dir)
        shutil.rmtree(test_dir)

    def test_with_gpg_eddsa(self):
        """Test sign and verify methods of DSSE with GPG EdDSA."""

        default_keyid = "4E630F84838BF6F7447B830B22692F5FEA9E2DD2"

        # Create directory to run the tests without having everything blow up.
        working_dir = os.getcwd()
        test_dir = os.path.realpath(tempfile.mkdtemp())
        gnupg_home = os.path.join(test_dir, "dsa")

        # Find demo files.
        gpg_keyring_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "eddsa"
        )

        shutil.copytree(gpg_keyring_path, gnupg_home)
        os.chdir(test_dir)

        # Create a GPGSigner and SSlibSigner.
        gpg_signer = GPGSigner(homedir=gnupg_home)
        sslib_signer = SSlibSigner(self.key_dict)

        # Create the DSSE Envelope and sign.
        envelope = Envelope.from_dict(self.envelope_dict)
        gpg_signature = envelope.sign(gpg_signer)
        sslib_signature = envelope.sign(sslib_signer)

        # Assert Types of the generated signatures.
        self.assertIsInstance(sslib_signature, Signature)
        self.assertIsInstance(gpg_signature, GPGSignature)

        # Create GPGKey and SSlibKey.
        gpgkey = GPGKey.from_keyring(keyid=default_keyid, homedir=gnupg_home)
        sslibkey = SSlibKey.from_securesystemslib_key(self.key_dict)
        key_list: List[Key] = []

        # verify the signatures.
        key_list.append(gpgkey)
        envelope.verify(key_list, 1)

        key_list.append(sslibkey)
        envelope.verify(key_list, 2)

        os.chdir(working_dir)
        shutil.rmtree(test_dir, onerror=GPGTestUtils.ignore_not_found_error)

    def test_with_gpg_rsa(self):
        """Test sign and verify methods of DSSE with GPG RSA."""

        default_keyid = "8465A1E2E0FB2B40ADB2478E18FB3F537E0C8A17"
        signing_subkey_keyid = "C5A0ABE6EC19D0D65F85E2C39BE9DF5131D924E9"

        # Create directory to run the tests without having everything blow up.
        working_dir = os.getcwd()
        test_dir = os.path.realpath(tempfile.mkdtemp())
        gnupg_home = os.path.join(test_dir, "rsa")

        # Find demo files.
        gpg_keyring_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "rsa"
        )

        shutil.copytree(gpg_keyring_path, gnupg_home)
        os.chdir(test_dir)

        # Create a GPGSigner and SSlibSigner.
        gpg_signer = GPGSigner(homedir=gnupg_home)
        sslib_signer = SSlibSigner(self.key_dict)

        # Create the DSSE Envelope and sign.
        envelope = Envelope.from_dict(self.envelope_dict)
        gpg_signature = envelope.sign(gpg_signer)
        sslib_signature = envelope.sign(sslib_signer)

        # Assert Types of the generated signatures.
        self.assertIsInstance(sslib_signature, Signature)
        self.assertIsInstance(gpg_signature, GPGSignature)

        # Create GPGKey and SSlibKey.
        # Tried both keyid: default and signing
        gpgkey = GPGKey.from_keyring(keyid=signing_subkey_keyid, homedir=gnupg_home)
        sslibkey = SSlibKey.from_securesystemslib_key(self.key_dict)
        key_list: List[Key] = []

        # verify the signatures.
        key_list.append(gpgkey)
        # FAILS ON THE LINE BELOW
        envelope.verify(key_list, 1)

        key_list.append(sslibkey)
        envelope.verify(key_list, 2)

        os.chdir(working_dir)
        shutil.rmtree(test_dir)


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()

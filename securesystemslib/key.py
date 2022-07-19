"""Key interface and example interface implementations."""

import abc
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from securesystemslib import keys
from securesystemslib.gpg import functions as gpg
from securesystemslib.signer import GPGSignature, Signature


class Key:
    """Key interface created to support multiple verify implementations."""

    __metaclass__ = abc.ABCMeta
    keyid: str

    @abc.abstractmethod
    def verify(self, signature: Signature, payload: bytes) -> bool:
        """Verifies a given payload by the key assigned to the Key instance.

        Arguments:
            signature: A "Signature" class instance.
            payload: The bytes to be verified.

        Returns:
            Boolean. True if the signature is valid, False otherwise.
        """
        raise NotImplementedError  # pragma: no cover


@dataclass
class SSlibKey(Key):
    """A container class representing the public portion of a Key.

    Provides a verify method to verify a cryptographic signature with a
    securesystemslib-style rsa, ed25519 or ecdsa public key on the instance.
    The signature scheme is determined by the key and must be one of:

    - rsa(ssa-pss|pkcs1v15)-(md5|sha1|sha224|sha256|sha384|sha512) (12 schemes)
    - ed25519
    - ecdsa-sha2-nistp256

    Attributes:
        keyid: Key identifier that is unique within the metadata it is used in.
            Keyid is not verified to be the hash of a specific representation
            of the key.
        keytype: Key type, e.g. "rsa", "ed25519" or "ecdsa-sha2-nistp256".
        keyval: Opaque key content.
        scheme: Signature scheme. For example:
            "rsassa-pss-sha256", "ed25519", and "ecdsa-sha2-nistp256".
        unrecognized_fields: Dictionary of all attributes that are not managed
            by securesystemslib.
    """

    keytype: str
    scheme: str
    keyval: Dict[str, str]
    keyid: str
    unrecognized_fields: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        public_key = self.keyval["public"]
        return hash((self.keytype, self.scheme, public_key))

    @classmethod
    def from_dict(cls, key_dict: Dict[str, Any], keyid: str) -> "SSlibKey":
        """Creates ``Key`` object from its json/dict representation.

        Raises:
            KeyError, TypeError: Invalid arguments.

        Side Effect:
            Destroys the key_dict passed by reference.

        """

        keytype = key_dict.pop("keytype")
        scheme = key_dict.pop("scheme")
        keyval = key_dict.pop("keyval")

        # All fields left in the key_dict are unrecognized.
        return cls(keytype, scheme, keyval, keyid, key_dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the dictionary representation of self."""

        return {
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
            **self.unrecognized_fields,
        }

    @classmethod
    def from_securesystemslib_key(cls, key_dict: Dict[str, Any]) -> "SSlibKey":
        """Creates a ``Key`` object from a securesystemlib key json/dict representation
        removing the private key from keyval.

        Args:
            key_dict: Key in securesystemlib dict representation.

        Raises:
            ValueError: ``key_dict`` value is not following the securesystemslib
                format.
        """
        key_meta = keys.format_keyval_to_metadata(
            key_dict["keytype"],
            key_dict["scheme"],
            key_dict["keyval"],
        )

        return cls(
            key_meta["keytype"],
            key_meta["scheme"],
            key_meta["keyval"],
            key_dict["keyid"],
        )

    def to_securesystemslib_key(self) -> Dict[str, Any]:
        """Returns a ``Securesystemslib`` compatible representation of self."""

        return {
            "keyid": self.keyid,
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": self.keyval,
        }

    def verify(self, signature: Signature, payload: bytes) -> bool:
        """Verifies a given payload by the key assigned to the SSlibKey instance.

        Arguments:
            signature: A "Signature" class instance.
            payload: The bytes to be verified.

        Returns:
            Boolean. True if the signature is valid, False otherwise.
        """

        return keys.verify_signature(
            self.to_securesystemslib_key(), signature.to_dict(), payload
        )


@dataclass
class GPGKey(Key):
    """A container class representing public key portion of a GPG key.

    Provides a verify method to verify a cryptographic signature with a
    gpg-style rsa, dsa or ecdsa public key on the instance.

    Attributes:
        type: Key type, e.g. "rsa", "dsa" or "ecdsa".
        method: GPG Key Scheme, For example:
            "pgp+rsa-pkcsv1.5", "pgp+dsa-fips-180-2", and "pgp+eddsa-ed25519".
        hashes: list of GPG Hash Algorithms, e.g. "pgp+SHA2".
        keyval: Opaque key content.
        keyid: Key identifier that is unique within the metadata it is used in.
            Keyid is not verified to be the hash of a specific representation
            of the key.
        creation_time: Unix timestamp when GPG key was created.
        validity_period: Validity of the GPG Keys in days.
        subkeys: A dictionary containing keyid and GPG subkey.
    """

    type: str
    method: str
    hashes: List[str]
    keyval: Dict[str, Dict]
    keyid: str
    creation_time: Optional[int] = None
    validity_period: Optional[int] = None
    subkeys: Optional[Dict[str, "GPGKey"]] = None

    def __hash__(self):
        public_key = json.dumps(self.keyval["public"], sort_keys=True)
        return hash((self.type, self.method, self.hashes[0], public_key))

    @classmethod
    def from_dict(cls, key_dict: Dict[str, Any]):
        """Creates ``GPGKey`` object from its json/dict representation.

        Raises:
            KeyError, TypeError: Invalid arguments.

        """
        subkeys_dict = key_dict.get("subkeys")

        gpg_subkeys = None
        if subkeys_dict:
            gpg_subkeys = {
                keyid: GPGKey.from_dict(subkey_dict)
                for (keyid, subkey_dict) in subkeys_dict.items()
            }

        return cls(
            key_dict["type"],
            key_dict["method"],
            key_dict["hashes"],
            key_dict["keyval"],
            key_dict["keyid"],
            key_dict.get("creation_time"),
            key_dict.get("validity_period"),
            gpg_subkeys,
        )

    def to_dict(self):
        """Returns the dictionary representation of self."""

        key_dict = {
            "method": self.method,
            "type": self.type,
            "hashes": self.hashes,
            "keyid": self.keyid,
            "keyval": self.keyval,
        }

        if self.creation_time:
            key_dict["creation_time"] = self.creation_time
        if self.validity_period:
            key_dict["validity_period"] = self.validity_period
        if self.subkeys:
            subkeys_dict = {
                keyid: subkey.to_dict()
                for (keyid, subkey) in self.subkeys.items()
            }
            key_dict["subkeys"] = subkeys_dict

        return key_dict

    @classmethod
    def from_keyring(cls, keyid, homedir=None):
        """Creates ``GPGKey`` object from GnuPG Keyring."""

        pubkey_dict = gpg.export_pubkey(keyid, homedir)
        return cls.from_dict(pubkey_dict)

    def verify(self, signature: GPGSignature, payload: bytes) -> bool:
        """Verifies a given payload by the key assigned to the GPGKey instance.

        Arguments:
            signature: A "GPGSignature" class instance.
            payload: The bytes to be verified.

        Returns:
            Boolean. True if the signature is valid, False otherwise.
        """

        return gpg.verify_signature(signature.to_dict(), self.to_dict(), payload)

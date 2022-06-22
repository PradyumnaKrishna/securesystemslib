"""Key interface and example interface implementations."""

import abc
from typing import Any, Dict, List, Optional, Tuple

from securesystemslib import keys
from securesystemslib.signer import Signature


class Key:
    """Key interface created to support multiple verify implementations."""

    __metaclass__ = abc.ABCMeta

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

    def __init__(
        self,
        keytype: str,
        scheme: str,
        keyval: Dict[str, str],
        keyid: Optional[str] = None,
        unrecognized_fields: Optional[Dict[str, Any]] = None,
    ):
        self.keytype = keytype
        self.scheme = scheme
        self.keyval = keyval
        self.keyid = keyid if keyid else None
        if unrecognized_fields is None:
            unrecognized_fields = {}

        self.unrecognized_fields = unrecognized_fields

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, SSlibKey):
            return False

        return (
            self.keyid == other.keyid
            and self.keytype == other.keytype
            and self.scheme == other.scheme
            and self.keyval == other.keyval
            and self.unrecognized_fields == other.unrecognized_fields
        )

    @classmethod
    def from_dict(cls, key_dict: Dict[str, Any], keyid: Optional[str] = None) -> "SSlibKey":
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
            "keyid": self.keyid if self.keyid else "",
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


KeyList = List[Tuple[str, SSlibKey]]

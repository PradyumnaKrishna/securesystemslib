"""Dead Simple Signing Envelope
"""

import logging
from typing import Any, List

from securesystemslib import exceptions, formats
from securesystemslib.key import Key, KeyList
from securesystemslib.signer import Signature, Signer
from securesystemslib.util import b64dec, b64enc

logger = logging.getLogger(__name__)


class Envelope:
    """
    DSSE Envelope to provide interface for signing arbitrary data.

    Attributes:
        payload: Arbitrary byte sequence of serialized body
        payload_type: string that identifies how to interpret payload
        signatures: List of Signature and GPG Signature

    Methods:
        from_dict(cls, data):
            Creates a Signature object from its JSON/dict representation.

        to_dict(self):
            Returns the JSON-serializable dictionary representation of self.

    """

    payload: bytes
    payload_type: str
    signatures: List[Signature]

    def __init__(self, payload, payload_type, signatures):
        self.payload = payload
        self.payload_type = payload_type
        self.signatures = signatures

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Envelope):
            return False

        return (
            self.payload == other.payload
            and self.payload_type == other.payload_type
            and self.signatures == other.signatures
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Envelope":
        """Creates a Signature object from its JSON/dict representation.

        Arguments:
            data: A dict containing a valid payload, payloadType and signatures

        Raises:
            KeyError: If any of the "payload", "payloadType" and "signatures"
                fields are missing from the "data".

            FormatError: If signature in "signatures" is incorrect.

        Returns:
            A "Envelope" instance.
        """

        payload = b64dec(data["payload"])
        payload_type = data["payloadType"]

        signatures = []
        for signature in data["signatures"]:
            if formats.GPG_SIGNATURE_SCHEMA.matches(signature):
                raise NotImplementedError

            if formats.SIGNATURE_SCHEMA.matches(signature):
                signatures.append(Signature.from_dict(signature))

            else:
                raise exceptions.FormatError("Wanted a 'Signature'.")

        return cls(payload, payload_type, signatures)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        return {
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "signatures": [signature.to_dict() for signature in self.signatures],
        }

    @property
    def pae(self) -> bytes:
        """Pre-Auth-Encoding byte sequence of self."""

        return b"DSSEv1 %d %b %d %b" % (
            len(self.payload_type),
            self.payload_type.encode("utf-8"),
            len(self.payload),
            self.payload,
        )

    def sign(self, signer: Signer) -> Signature:
        """Sign the payload and create the signature.

        Arguments:
            signer: A "Signer" class instance.

        Raises:
            TypeError: If "signer" is not an instance of the "Signer" class.

        Returns:
            A "Signature" instance.
        """

        if not isinstance(signer, Signer):
            raise TypeError(f"expected type 'Signer', got {type(signer).__name__}")

        signature = signer.sign(self.pae)
        self.signatures.append(signature)

        return signature

    def verify(self, keys: KeyList, threshold: int) -> List[str]:
        """Verify the payload with the provided Keys.

        Arguments:
            keys: A list of a "str" and "Key" class instance.
            threshold: Number of signatures needed to pass the verification.

        Raises:
            TypeError: If a key in "keys" is not an instance of the "Key" class.
            ValueError: If "threshold" is not valid.
            SignatureVerificationError: If the amount of "recognized_signers" is less
                than provided threshold.

        Returns:
            recognized_signers: list of key names for which verification succeeds.
        """

        recognized_signers = []
        used_keyids = []
        pae = self.pae

        # checks for threshold value.
        if len(keys) < threshold or threshold <= 0:
            raise ValueError(f"Threshold must be between 0 and {len(keys)}")

        for signature in self.signatures:
            for (name, key) in keys:
                if not isinstance(key, Key):
                    raise TypeError(f"expected type 'Key', got {type(key).__name__}")

                # If key and signature include keyIDs but do not match skip.
                if (
                    signature.keyid is not None
                    and key.keyid is not None
                    and signature.keyid != key.keyid
                ):
                    continue

                # If a key verifies the signature, we exit and use the result.
                if key.verify(signature, pae):
                    if key.keyid:
                        # If keyid has already been verified, skip.
                        if key.keyid in used_keyids:
                            logger.info(
                                "One subkey of the same main key has already verified"
                                " the signature, current signature will be skipped."
                            )
                            continue
                        used_keyids.append(key.keyid)

                    recognized_signers.append(name)
                    break

        if len(recognized_signers) < threshold:
            raise exceptions.SignatureVerificationError(
                "Accepted signatures do not match threshold,"
                f" Found: {len(recognized_signers)}, Expected {threshold}"
            )

        return recognized_signers

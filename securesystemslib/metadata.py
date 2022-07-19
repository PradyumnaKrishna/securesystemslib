"""Dead Simple Signing Envelope
"""

import logging
from typing import Any, List, Set

from securesystemslib import exceptions, formats
from securesystemslib.key import Key
from securesystemslib.signer import GPGSignature, Signature, Signer
from securesystemslib.util import b64dec, b64enc

logger = logging.getLogger(__name__)


class Envelope:
    """DSSE Envelope to provide interface for signing arbitrary data.

    Attributes:
        payload: Arbitrary byte sequence of serialized body.
        payload_type: string that identifies how to interpret payload.
        signatures: list of Signature and GPGSignature.

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
            formats.ANY_SIGNATURE_SCHEMA.check_match(signature)

            try:
                signatures.append(GPGSignature.from_dict(signature))
            except KeyError:
                signatures.append(Signature.from_dict(signature))

        return cls(payload, payload_type, signatures)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        return {
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "signatures": [signature.to_dict() for signature in self.signatures],
        }

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

        Returns:
            A "Signature" instance.
        """

        signature = signer.sign(self.pae())
        self.signatures.append(signature)

        return signature

    def verify(self, keys: List[Key], threshold: int) -> Set[Key]:
        """Verify the payload with the provided Keys.

        Arguments:
            keys: A list of "Key" class instance that is a public key to verify
                the signatures.
            threshold: Number of signatures needed to pass the verification.

        Raises:
            ValueError: If "threshold" is not valid.
            SignatureVerificationError: If the amount of "recognized_signers" is less
                than provided threshold.

        Returns:
            recognized_signers: A set of recognized public keys.
        """

        recognized_signers = set()
        pae = self.pae()

        # checks for threshold value.
        if threshold <= 0:
            raise ValueError("Threshold must be greater than 0")

        if threshold > len(keys):
            raise ValueError("Amount of keys must be greater than threshold")

        for signature in self.signatures:
            for key in keys:
                # If key and signature include keyIDs but do not match skip.
                if (
                    signature.keyid is not None
                    and key.keyid is not None
                    and signature.keyid != key.keyid
                ):
                    continue

                # If a key verifies the signature, we exit and use the result.
                if key.verify(signature, pae):
                    recognized_signers.add(key)
                    break

            # Break, if amount of recognized_signer are more than threshold.
            if len(recognized_signers) >= threshold:
                break

        if threshold > len(recognized_signers):
            raise exceptions.SignatureVerificationError(
                "Accepted signatures do not match threshold,"
                f" Found: {len(recognized_signers)}, Expected {threshold}"
            )

        return recognized_signers

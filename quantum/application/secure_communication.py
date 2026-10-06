"""Biomedical secure-communication application layer.

Two-endpoint QKD model: Hospital A holds the SENDER endpoint key, Hospital B
holds the RECEIVER endpoint key. Both come from the paired BB84 sift; the
receiver key is never copied from the sender key. This prototype implements
NO information reconciliation / error correction, so the endpoint keys may
differ (any QBER > 0). Encryption proceeds only on exact endpoint-key
equality; otherwise the session parks in KEY_RECONCILIATION_REQUIRED and no
packet is produced. No fake reconciliation is performed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from quantum.qkd.bb84_engine import BB84Engine, QKDRequest, QKDResult
from quantum.qkd.channel import ChannelConfiguration
from quantum.qkd.security import (
    SecurityAssessment,
    SecurityController,
    SecurityDecision,
    SecurityPolicy,
)

logger = logging.getLogger(__name__)

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - import guard
    InvalidTag = Exception  # type: ignore
    AESGCM = None  # type: ignore
    _CRYPTO_AVAILABLE = False


class MissingCryptoDependencyError(RuntimeError):
    """Raised when AES-GCM is requested but `cryptography` is missing."""


@dataclass(frozen=True)
class Hospital:
    hospital_id: str
    name: str


@dataclass(frozen=True)
class BiomedicalMessage:
    """Application data payload (never the QKD key)."""

    record: dict[str, Any]

    def to_bytes(self) -> bytes:
        return json.dumps(self.record, sort_keys=True).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> BiomedicalMessage:
        return cls(record=json.loads(raw.decode("utf-8")))


class SessionState(Enum):
    INITIALIZED = "INITIALIZED"
    QKD_IN_PROGRESS = "QKD_IN_PROGRESS"
    QKD_ACCEPTED = "QKD_ACCEPTED"
    QKD_MONITORED = "QKD_MONITORED"
    QKD_REJECTED = "QKD_REJECTED"
    KEY_RECONCILIATION_REQUIRED = "KEY_RECONCILIATION_REQUIRED"
    ENCRYPTED = "ENCRYPTED"
    DELIVERED = "DELIVERED"
    DECRYPTED = "DECRYPTED"
    FAILED = "FAILED"


_VALID_TRANSITIONS: dict[SessionState, set[SessionState]] = {
    SessionState.INITIALIZED: {SessionState.QKD_IN_PROGRESS,
                               SessionState.FAILED},
    SessionState.QKD_IN_PROGRESS: {SessionState.QKD_ACCEPTED,
                                   SessionState.QKD_MONITORED,
                                   SessionState.QKD_REJECTED,
                                   SessionState.KEY_RECONCILIATION_REQUIRED,
                                   SessionState.FAILED},
    SessionState.QKD_ACCEPTED: {SessionState.ENCRYPTED,
                                SessionState.FAILED},
    SessionState.QKD_MONITORED: {SessionState.FAILED},
    SessionState.QKD_REJECTED: {SessionState.FAILED},
    SessionState.KEY_RECONCILIATION_REQUIRED: {SessionState.FAILED},
    SessionState.ENCRYPTED: {SessionState.DELIVERED, SessionState.FAILED},
    SessionState.DELIVERED: {SessionState.DECRYPTED, SessionState.FAILED},
    SessionState.DECRYPTED: set(),
    SessionState.FAILED: set(),
}


@dataclass
class SecureSession:
    session_id: str
    source_hospital: Hospital
    destination_hospital: Hospital
    requested_key_size: int
    state: SessionState = SessionState.INITIALIZED
    qkd_result: QKDResult | None = None
    qber: float | None = None
    security_decision: SecurityDecision | None = None
    encryption_status: str = "NOT_STARTED"
    delivery_status: str = "NOT_STARTED"
    failure_reason: str | None = None

    def transition(self, new_state: SessionState) -> None:
        allowed = _VALID_TRANSITIONS[self.state]
        if new_state not in allowed:
            raise ValueError(
                f"invalid session transition {self.state.value} "
                f"-> {new_state.value}")
        self.state = new_state


@dataclass(frozen=True)
class SecurePacket:
    """Simulated secure network packet (no plaintext, no QKD key)."""

    session_id: str
    source: str
    destination: str
    nonce: bytes
    ciphertext: bytes
    key_fingerprint: str
    security_metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class SecureTransmissionResult:
    session: SecureSession
    packet: SecurePacket | None
    assessment: SecurityAssessment | None
    delivered_payload: BiomedicalMessage | None = None
    integrity_verified: bool = False


def _require_crypto() -> None:
    if not _CRYPTO_AVAILABLE:
        raise MissingCryptoDependencyError(
            "AES-GCM needs 'cryptography' package "
            "(pip install cryptography). No fallback cipher is used.")


def derive_aes_key(key_bytes: bytes, session_id: str) -> bytes:
    """Derive AES-256 key from QKD material via SHA-256 (prototype KDF).

    Prototype note: NOT production privacy amplification.
    """
    return hashlib.sha256(b"QKD-AES-GCM-v1|" + session_id.encode()
                          + b"|" + key_bytes).digest()

class SecureCommunicationService:
    """Hospital A -> QKD -> AES-GCM packet -> Hospital B."""

    def __init__(self, engine=None, controller=None) -> None:
        self.engine = engine or BB84Engine()
        self.controller = controller or SecurityController()

    def _run_qkd(self, session, channel_config, seed, threat_score=None):
        # threat_score: externally supplied ML threat score (float in
        # [0,1]) or None for QKD-only operation. It only reaches
        # SecurityController.evaluate — the endpoint-key gate below is
        # completely independent of it.
        session.transition(SessionState.QKD_IN_PROGRESS)
        qkd_result = self.engine.establish_key(
            QKDRequest(requested_key_bits=session.requested_key_size,
                       channel_configuration=channel_config, seed=seed))
        session.qkd_result = qkd_result
        session.qber = qkd_result.qber
        assessment = self.controller.evaluate(
            qber=qkd_result.qber, threat_score=threat_score,
            key_success=qkd_result.success,
            eavesdropping_indicated=channel_config.eavesdropper.enabled,
            noise_probability=channel_config.noise_probability)
        session.security_decision = assessment.decision
        # Endpoint-key gate: ACCEPT on QBER alone does NOT imply identical
        # endpoint keys. Without reconciliation, mismatched keys must park
        # in KEY_RECONCILIATION_REQUIRED and never encrypt. No fake
        # reconciliation is performed to force a match.
        if qkd_result.success and not qkd_result.endpoint_keys_match:
            session.transition(SessionState.KEY_RECONCILIATION_REQUIRED)
            session.failure_reason = (
                "endpoint keys differ (mismatches="
                f"{qkd_result.mismatches}); information reconciliation "
                "not implemented in this prototype; no usable shared key; "
                "request a new QKD session")
            return assessment
        if assessment.decision is SecurityDecision.ACCEPT:
            session.transition(SessionState.QKD_ACCEPTED)
        elif assessment.decision is SecurityDecision.MONITOR:
            session.transition(SessionState.QKD_MONITORED)
        else:
            session.transition(SessionState.QKD_REJECTED)
            session.failure_reason = "; ".join(assessment.reasons)
        return assessment

    def send_biomedical_data(self, source, destination, message,
                             channel_config=None, requested_key_bits=256,
                             seed=None, threat_score=None):
        """Run QKD + AES-GCM delivery. threat_score=None (default) keeps
        QKD-only behaviour; a float in [0,1] is the externally supplied
        ML threat score (see ml_bridge) fed to SecurityController only."""
        _require_crypto()
        channel_config = channel_config or ChannelConfiguration.normal()
        msg = (message if isinstance(message, BiomedicalMessage)
               else BiomedicalMessage(record=dict(message)))
        session = SecureSession(session_id=str(uuid.uuid4()),
                                source_hospital=source,
                                destination_hospital=destination,
                                requested_key_size=requested_key_bits)
        assessment = self._run_qkd(session, channel_config, seed,
                                   threat_score)
        if assessment.decision is not SecurityDecision.ACCEPT:
            note = ("MONITOR: held for review under project policy; "
                    "not silently treated as ACCEPT."
                    if assessment.decision is SecurityDecision.MONITOR
                    else "Rejected key never used; request a new session.")
            session.failure_reason = ((session.failure_reason + "; " + note)
                                      if session.failure_reason else note)
            return SecureTransmissionResult(session, None, assessment)
        # Faithful two-endpoint model: Hospital A encrypts with the SENDER
        # endpoint key; Hospital B must decrypt with its own RECEIVER
        # endpoint key. Encryption requires bit-identical endpoint keys.
        qr = session.qkd_result
        kb_send = qr.sender_key_bytes if qr else None
        kb_recv = qr.receiver_key_bytes if qr else None
        if not kb_send or not kb_recv or not qr.endpoint_keys_match:
            if session.state is SessionState.QKD_ACCEPTED:
                session.transition(SessionState.FAILED)
            session.failure_reason = (
                (session.failure_reason + "; ") if session.failure_reason
                else "") + ("endpoint keys do not match; no shared key "
                            "without reconciliation")
            return SecureTransmissionResult(session, None, assessment)
        aes_key = derive_aes_key(kb_send, session.session_id)
        nonce = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(nonce, msg.to_bytes(), None)
        session.transition(SessionState.ENCRYPTED)
        session.encryption_status = "ENCRYPTED_AES_GCM"
        fp = hashlib.sha256(kb_send).hexdigest()[:16]
        packet = SecurePacket(session_id=session.session_id,
                              source=source.hospital_id,
                              destination=destination.hospital_id,
                              nonce=nonce, ciphertext=ct,
                              key_fingerprint=fp,
                              security_metadata={
                                  "qber": session.qber,
                                  "decision": "ACCEPT",
                                  "algorithm": "AES-256-GCM",
                                  "channel": channel_config.mode.value})
        session.transition(SessionState.DELIVERED)
        session.delivery_status = "DELIVERED"
        return SecureTransmissionResult(session, packet, assessment)

    def receive_packet(self, packet, session):
        """Hospital B decrypts using ONLY its own receiver endpoint key.

        The sender key is never accepted here: the AES key is re-derived
        from session.qkd_result.receiver_key_bytes internally. Raises
        ValueError for non-accepted sessions, mismatched endpoint keys,
        missing receiver material, or failed integrity check.
        """
        _require_crypto()
        if session.security_decision is not SecurityDecision.ACCEPT:
            raise ValueError("non-accepted session key cannot decrypt")
        qr = session.qkd_result
        if qr is None or not qr.endpoint_keys_match:
            raise ValueError(
                "endpoint keys do not match; no shared key without "
                "information reconciliation")
        recv_bytes = qr.receiver_key_bytes
        if not recv_bytes:
            raise ValueError("receiver endpoint has no key material")
        aes_key = derive_aes_key(recv_bytes, session.session_id)
        try:
            raw = AESGCM(aes_key).decrypt(packet.nonce, packet.ciphertext,
                                          None)
        except InvalidTag as exc:
            session.transition(SessionState.FAILED)
            session.failure_reason = "integrity check failed (bad tag)"
            raise ValueError("packet integrity check failed") from exc
        message = BiomedicalMessage.from_bytes(raw)
        session.transition(SessionState.DECRYPTED)
        session.delivery_status = "DECRYPTED"
        return SecureTransmissionResult(session, packet, None, message, True)

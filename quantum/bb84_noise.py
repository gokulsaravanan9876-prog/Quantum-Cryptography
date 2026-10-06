import math
import random
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator


# ============================================================
# SECURITY POLICY
# ============================================================

ACCEPT_THRESHOLD = 0.03
MONITOR_THRESHOLD = 0.10

MAX_QKD_ROUNDS = 10

# BB84 keeps roughly half of the transmitted qubits after
# basis sifting, so we start with extra qubits.
SIFTING_OVERHEAD = 2.5


class SecurityDecision(Enum):
    ACCEPT = "ACCEPT"
    MONITOR = "MONITOR"
    REJECT = "REJECT"


# ============================================================
# BIOMEDICAL NETWORK ENTITIES
# ============================================================

@dataclass
class Hospital:
    hospital_id: str
    name: str


@dataclass
class KeyRequest:
    """
    Application-level request.

    Hospital A asks the QKD service for a shared key
    with Hospital B.

    Hospital A does NOT specify the number of qubits.
    """

    source: Hospital
    destination: Hospital
    key_size: int
    session_id: str


@dataclass
class QKDResult:

    request_id: str

    source: str
    destination: str

    status: str

    requested_key_size: int

    generated_key_size: int

    qber: Optional[float]

    decision: SecurityDecision

    rounds_used: int

    sifted_bits: int

    key: Optional[list]


# ============================================================
# SIMULATION ENVIRONMENT
# ============================================================

@dataclass
class ChannelSimulation:

    """
    These parameters belong to our experimental environment.

    A real hospital application does NOT provide these values.
    They simulate channel conditions for the hackathon.
    """

    noise_probability: float = 0.0

    eve_probability: float = 0.0


# ============================================================
# BB84 ENGINE
# ============================================================

class BB84Engine:

    def __init__(self):

        self.simulator = AerSimulator()


    # --------------------------------------------------------
    # Random bits
    # --------------------------------------------------------

    def generate_bits(self, count):

        return [
            random.randint(0, 1)
            for _ in range(count)
        ]


    # --------------------------------------------------------
    # Random bases
    #
    # 0 = Z
    # 1 = X
    # --------------------------------------------------------

    def generate_bases(self, count):

        return [
            random.randint(0, 1)
            for _ in range(count)
        ]


    # --------------------------------------------------------
    # Encode one qubit
    # --------------------------------------------------------

    def encode_qubit(self, bit, basis):

        circuit = QuantumCircuit(1, 1)

        # Z basis
        if basis == 0:

            if bit == 1:
                circuit.x(0)

        # X basis
        else:

            if bit == 1:
                circuit.x(0)

            circuit.h(0)

        return circuit


    # --------------------------------------------------------
    # Simulated channel noise
    # --------------------------------------------------------

    def apply_noise(
        self,
        circuit,
        probability
    ):

        if random.random() < probability:

            # Simplified channel disturbance
            circuit.x(0)

        return circuit


    # --------------------------------------------------------
    # Eve intercept-resend
    # --------------------------------------------------------

    def intercept_resend(
        self,
        circuit,
        eve_basis
    ):

        eve_bit = self.measure(
            circuit,
            eve_basis
        )

        # Eve prepares a replacement state.
        replacement = self.encode_qubit(
            eve_bit,
            eve_basis
        )

        return replacement


    # --------------------------------------------------------
    # Measure qubit
    # --------------------------------------------------------

    def measure(
        self,
        circuit,
        basis
    ):

        # Convert X basis to Z basis.
        if basis == 1:

            circuit.h(0)

        circuit.measure(0, 0)

        result = self.simulator.run(
            circuit,
            shots=1
        ).result()

        counts = result.get_counts()

        bit = int(next(iter(counts)))

        return bit


    # --------------------------------------------------------
    # Execute one BB84 transmission round
    # --------------------------------------------------------

    def execute_round(
        self,
        qubit_count,
        channel
    ):

        # ----------------------------------------------
        # Hospital A / sender
        # ----------------------------------------------

        sender_bits = self.generate_bits(
            qubit_count
        )

        sender_bases = self.generate_bases(
            qubit_count
        )

        # ----------------------------------------------
        # Hospital B / receiver
        # ----------------------------------------------

        receiver_bases = self.generate_bases(
            qubit_count
        )

        receiver_bits = []


        # ==================================================
        # QUANTUM TRANSMISSION
        # ==================================================

        for i in range(qubit_count):

            # Hospital A prepares quantum state.
            circuit = self.encode_qubit(
                sender_bits[i],
                sender_bases[i]
            )


            # ------------------------------------------
            # Physical channel disturbance
            # ------------------------------------------

            circuit = self.apply_noise(
                circuit,
                channel.noise_probability
            )


            # ------------------------------------------
            # Possible eavesdropping
            # ------------------------------------------

            if random.random() < channel.eve_probability:

                eve_basis = random.randint(0, 1)

                circuit = self.intercept_resend(
                    circuit,
                    eve_basis
                )


            # ------------------------------------------
            # Hospital B measures
            # ------------------------------------------

            bit = self.measure(
                circuit,
                receiver_bases[i]
            )

            receiver_bits.append(bit)


        # ==================================================
        # BASIS RECONCILIATION / SIFTING
        # ==================================================

        sender_key = []
        receiver_key = []

        for i in range(qubit_count):

            if sender_bases[i] == receiver_bases[i]:

                sender_key.append(
                    sender_bits[i]
                )

                receiver_key.append(
                    receiver_bits[i]
                )


        # ==================================================
        # QBER
        # ==================================================

        if not sender_key:

            qber = 1.0

        else:

            errors = sum(
                a != b
                for a, b in zip(
                    sender_key,
                    receiver_key
                )
            )

            qber = errors / len(sender_key)


        return {
            "sender_key": sender_key,
            "receiver_key": receiver_key,
            "qber": qber
        }


# ============================================================
# SECURITY POLICY
# ============================================================

class SecurityPolicy:

    @staticmethod
    def evaluate(qber):

        if qber <= ACCEPT_THRESHOLD:

            return SecurityDecision.ACCEPT

        if qber <= MONITOR_THRESHOLD:

            return SecurityDecision.MONITOR

        return SecurityDecision.REJECT


# ============================================================
# QKD CONTROLLER
# ============================================================

class QKDController:

    def __init__(self):

        self.bb84 = BB84Engine()

        self.policy = SecurityPolicy()


    # --------------------------------------------------------
    # Estimate initial qubit requirement
    # --------------------------------------------------------

    def estimate_qubits(
        self,
        target_key_size
    ):

        return math.ceil(
            target_key_size *
            SIFTING_OVERHEAD
        )


    # --------------------------------------------------------
    # Process hospital key request
    # --------------------------------------------------------

    def establish_key(
        self,
        request: KeyRequest,
        channel: ChannelSimulation
    ):

        print("\n==============================================")
        print("          BIOMEDICAL QKD SESSION")
        print("==============================================")

        print(
            f"Source       : {request.source.name}"
        )

        print(
            f"Destination  : {request.destination.name}"
        )

        print(
            f"Key request  : {request.key_size} bits"
        )

        print(
            f"Session      : {request.session_id}"
        )

        print("----------------------------------------------")


        collected_sender_key = []
        collected_receiver_key = []

        last_qber = None

        total_sifted = 0


        # ====================================================
        # QKD SESSION
        # ====================================================

        for round_number in range(
            1,
            MAX_QKD_ROUNDS + 1
        ):

            remaining = (
                request.key_size -
                len(collected_sender_key)
            )

            if remaining <= 0:

                break


            # ----------------------------------------------
            # Controller decides how many physical qubits
            # to generate.
            # ----------------------------------------------

            qubit_count = self.estimate_qubits(
                remaining
            )


            print(
                f"\nQKD round {round_number}"
            )

            print(
                f"Internal qubits : {qubit_count}"
            )


            # ----------------------------------------------
            # Run BB84
            # ----------------------------------------------

            result = self.bb84.execute_round(
                qubit_count,
                channel
            )


            qber = result["qber"]

            last_qber = qber

            sifted = len(
                result["sender_key"]
            )

            total_sifted += sifted


            # ----------------------------------------------
            # Security decision
            # ----------------------------------------------

            decision = self.policy.evaluate(
                qber
            )


            print(
                f"Sifted bits     : {sifted}"
            )

            print(
                f"QBER            : "
                f"{qber * 100:.2f}%"
            )

            print(
                f"Decision        : "
                f"{decision.value}"
            )


            # =================================================
            # REJECT
            # =================================================

            if decision == SecurityDecision.REJECT:

                print(
                    "→ Key material discarded."
                )

                print(
                    "→ Starting fresh QKD round."
                )

                continue


            # =================================================
            # MONITOR
            # =================================================

            if decision == SecurityDecision.MONITOR:

                print(
                    "→ Channel disturbance is elevated."
                )

                print(
                    "→ This round is not accepted."
                )

                print(
                    "→ Re-running QKD."
                )

                continue


            # =================================================
            # ACCEPT
            # =================================================

            if decision == SecurityDecision.ACCEPT:

                sender_key = result[
                    "sender_key"
                ]

                receiver_key = result[
                    "receiver_key"
                ]


                # ------------------------------------------
                # Important limitation:
                #
                # We don't have reconciliation/error
                # correction yet.
                #
                # Therefore we only keep material that
                # already agrees at both endpoints.
                # ------------------------------------------

                if sender_key != receiver_key:

                    print(
                        "→ QBER acceptable, but endpoint"
                        " keys differ."
                    )

                    print(
                        "→ Cannot establish a shared key"
                        " without reconciliation."
                    )

                    continue


                # ------------------------------------------
                # Collect agreed key material
                # ------------------------------------------

                remaining = (
                    request.key_size -
                    len(collected_sender_key)
                )

                collected_sender_key.extend(
                    sender_key[:remaining]
                )

                collected_receiver_key.extend(
                    receiver_key[:remaining]
                )


        # ====================================================
        # FINAL RESULT
        # ====================================================

        final_size = len(
            collected_sender_key
        )


        if final_size >= request.key_size:

            final_sender_key = (
                collected_sender_key[
                    :request.key_size
                ]
            )

            final_receiver_key = (
                collected_receiver_key[
                    :request.key_size
                ]
            )


            print("\n==============================================")
            print("             QKD SUCCESS")
            print("==============================================")

            print(
                f"Shared key : {final_size} bits"
            )

            print(
                f"Final QBER : "
                f"{last_qber * 100:.2f}%"
            )


            return QKDResult(
                request_id=request.session_id,

                source=request.source.hospital_id,

                destination=request.destination.hospital_id,

                status="SUCCESS",

                requested_key_size=request.key_size,

                generated_key_size=final_size,

                qber=last_qber,

                decision=SecurityDecision.ACCEPT,

                rounds_used=MAX_QKD_ROUNDS,

                sifted_bits=total_sifted,

                key=final_sender_key
            )


        # ====================================================
        # FAILURE
        # ====================================================

        print("\n==============================================")
        print("             QKD FAILED")
        print("==============================================")


        return QKDResult(
            request_id=request.session_id,

            source=request.source.hospital_id,

            destination=request.destination.hospital_id,

            status="FAILED",

            requested_key_size=request.key_size,

            generated_key_size=final_size,

            qber=last_qber,

            decision=SecurityDecision.REJECT,

            rounds_used=MAX_QKD_ROUNDS,

            sifted_bits=total_sifted,

            key=None
        )


# ============================================================
# HOSPITAL NETWORK DEMO
# ============================================================

def main():

    # --------------------------------------------------------
    # Actual biomedical-network entities
    # --------------------------------------------------------

    hospital_a = Hospital(
        hospital_id="HOSP-A",
        name="Hospital A"
    )

    hospital_b = Hospital(
        hospital_id="HOSP-B",
        name="Hospital B"
    )


    # --------------------------------------------------------
    # Hospital A requests a secure key for communication
    # --------------------------------------------------------

    request = KeyRequest(

        source=hospital_a,

        destination=hospital_b,

        key_size=256,

        session_id=str(
            uuid.uuid4()
        )
    )


    # --------------------------------------------------------
    # Simulated quantum-channel environment
    #
    # Hospital A does NOT provide these values.
    # They represent experimental conditions.
    # --------------------------------------------------------

    channel = ChannelSimulation(

        noise_probability=0.0,

        eve_probability=0.0
    )


    # --------------------------------------------------------
    # QKD service
    # --------------------------------------------------------

    controller = QKDController()


    result = controller.establish_key(
        request,
        channel
    )


    # --------------------------------------------------------
    # Application receives result
    # --------------------------------------------------------

    print("\n==============================================")
    print("          APPLICATION RESULT")
    print("==============================================")

    print(
        f"Status       : {result.status}"
    )

    print(
        f"Source       : {result.source}"
    )

    print(
        f"Destination  : {result.destination}"
    )

    print(
        f"Requested    : "
        f"{result.requested_key_size} bits"
    )

    print(
        f"Generated    : "
        f"{result.generated_key_size} bits"
    )

    print(
        f"QBER         : "
        f"{result.qber * 100:.2f}%"
        if result.qber is not None
        else "QBER         : N/A"
    )

    print(
        f"Decision     : "
        f"{result.decision.value}"
    )


if __name__ == "__main__":

    main()
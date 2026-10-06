import random

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator


# ============================================================
# BASIC BB84 FUNCTIONS
# ============================================================

def generate_bits(n):
    """Generate Alice's random classical bits."""
    return [random.randint(0, 1) for _ in range(n)]


def generate_bases(n):
    """
    Generate random bases.

    0 = Z basis
    1 = X basis
    """
    return [random.randint(0, 1) for _ in range(n)]


def encode_qubit(bit, basis):
    """
    Alice/Eve prepares a qubit.

    Z basis:
        0 -> |0>
        1 -> |1>

    X basis:
        0 -> |+>
        1 -> |->
    """

    circuit = QuantumCircuit(1, 1)

    if basis == 0:
        # Z basis
        if bit == 1:
            circuit.x(0)

    else:
        # X basis
        if bit == 1:
            circuit.x(0)

        circuit.h(0)

    return circuit


def measure_qubit(circuit, basis):
    """
    Measure a qubit using the requested basis.

    Z basis:
        Direct measurement.

    X basis:
        Apply H first, then measure.
    """

    if basis == 1:
        circuit.h(0)

    circuit.measure(0, 0)

    simulator = AerSimulator()

    result = simulator.run(
        circuit,
        shots=1
    ).result()

    counts = result.get_counts()

    return int(next(iter(counts)))


# ============================================================
# EVE
# ============================================================

def eve_intercept_resend(alice_circuit, eve_basis):
    """
    Eve intercepts Alice's qubit.

    Eve:
    1. Measures Alice's qubit using her randomly chosen basis.
    2. Gets a classical result.
    3. Creates a NEW replacement qubit based on her result.
    4. Sends that replacement qubit to Bob.

    Returns:
        replacement_circuit
        eve_measurement
    """

    # Eve measures Alice's original qubit
    eve_measurement = measure_qubit(
        alice_circuit,
        eve_basis
    )

    # Eve creates a NEW qubit based on what she measured
    replacement_circuit = encode_qubit(
        eve_measurement,
        eve_basis
    )

    return replacement_circuit, eve_measurement


# ============================================================
# SIFTING
# ============================================================

def sift_key(
    alice_bits,
    alice_bases,
    bob_bases,
    bob_results
):
    """
    Keep only positions where Alice and Bob
    used the same basis.
    """

    sifted_alice = []
    sifted_bob = []

    kept_positions = []
    discarded_positions = []

    for i in range(len(alice_bits)):

        if alice_bases[i] == bob_bases[i]:

            # Same basis -> KEEP
            sifted_alice.append(alice_bits[i])
            sifted_bob.append(bob_results[i])

            kept_positions.append(i)

        else:

            # Different basis -> DISCARD
            discarded_positions.append(i)

    return (
        sifted_alice,
        sifted_bob,
        kept_positions,
        discarded_positions
    )


# ============================================================
# QBER
# ============================================================

def calculate_qber(alice_key, bob_key):
    """
    QBER = number of mismatched bits / total compared bits
    """

    if len(alice_key) == 0:
        return None

    errors = sum(
        alice_bit != bob_bit
        for alice_bit, bob_bit in zip(alice_key, bob_key)
    )

    return errors / len(alice_key)


# ============================================================
# BB84 WITHOUT EVE
# ============================================================

def run_bb84_without_eve(n):
    """
    Normal BB84:
    Alice -> Bob

    No Eve.
    No noise.
    """

    alice_bits = generate_bits(n)
    alice_bases = generate_bases(n)
    bob_bases = generate_bases(n)

    bob_results = []

    for i in range(n):

        # Alice prepares the qubit
        circuit = encode_qubit(
            alice_bits[i],
            alice_bases[i]
        )

        # Bob directly receives it
        bob_result = measure_qubit(
            circuit,
            bob_bases[i]
        )

        bob_results.append(bob_result)

    (
        sifted_alice,
        sifted_bob,
        kept_positions,
        discarded_positions
    ) = sift_key(
        alice_bits,
        alice_bases,
        bob_bases,
        bob_results
    )

    qber = calculate_qber(
        sifted_alice,
        sifted_bob
    )

    return {
        "alice_bits": alice_bits,
        "alice_bases": alice_bases,
        "bob_bases": bob_bases,
        "bob_results": bob_results,
        "sifted_alice": sifted_alice,
        "sifted_bob": sifted_bob,
        "kept_positions": kept_positions,
        "discarded_positions": discarded_positions,
        "qber": qber
    }


# ============================================================
# BB84 WITH EVE
# ============================================================

def run_bb84_with_eve(n):
    """
    BB84 with intercept-resend Eve.

    Alice -> Eve -> Bob
    """

    alice_bits = generate_bits(n)
    alice_bases = generate_bases(n)

    # Eve independently chooses random bases
    eve_bases = generate_bases(n)

    # Bob independently chooses random bases
    bob_bases = generate_bases(n)

    eve_results = []
    bob_results = []

    for i in range(n):

        # ----------------------------------------------------
        # Alice prepares her qubit
        # ----------------------------------------------------

        alice_circuit = encode_qubit(
            alice_bits[i],
            alice_bases[i]
        )

        # ----------------------------------------------------
        # Eve intercepts the qubit
        # ----------------------------------------------------

        replacement_circuit, eve_result = eve_intercept_resend(
            alice_circuit,
            eve_bases[i]
        )

        eve_results.append(eve_result)

        # ----------------------------------------------------
        # Bob measures Eve's replacement qubit
        # ----------------------------------------------------

        bob_result = measure_qubit(
            replacement_circuit,
            bob_bases[i]
        )

        bob_results.append(bob_result)

    # --------------------------------------------------------
    # Sifting
    # --------------------------------------------------------

    (
        sifted_alice,
        sifted_bob,
        kept_positions,
        discarded_positions
    ) = sift_key(
        alice_bits,
        alice_bases,
        bob_bases,
        bob_results
    )

    # --------------------------------------------------------
    # QBER
    # --------------------------------------------------------

    qber = calculate_qber(
        sifted_alice,
        sifted_bob
    )

    return {
        "alice_bits": alice_bits,
        "alice_bases": alice_bases,
        "eve_bases": eve_bases,
        "eve_results": eve_results,
        "bob_bases": bob_bases,
        "bob_results": bob_results,
        "sifted_alice": sifted_alice,
        "sifted_bob": sifted_bob,
        "kept_positions": kept_positions,
        "discarded_positions": discarded_positions,
        "qber": qber
    }


# ============================================================
# MAIN EXPERIMENT
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # Small example so we can inspect what happened
    # --------------------------------------------------------

    N = 10000

    print("\n========================================")
    print("        BB84 WITHOUT EVE")
    print("========================================")

    normal = run_bb84_without_eve(N)

    print("Alice bits:       ", normal["alice_bits"])
    print("Alice bases:      ", normal["alice_bases"])
    print("Bob bases:        ", normal["bob_bases"])
    print("Bob measurements: ", normal["bob_results"])

    print("\nKept positions:   ", normal["kept_positions"])
    print("Discarded:        ", normal["discarded_positions"])

    print("\nAlice sifted key: ", normal["sifted_alice"])
    print("Bob sifted key:   ", normal["sifted_bob"])

    print(f"\nQBER: {normal['qber'] * 100:.2f}%")

    # --------------------------------------------------------
    # Eve experiment
    # --------------------------------------------------------

    print("\n========================================")
    print("       BB84 WITH EVE")
    print("========================================")

    eve = run_bb84_with_eve(N)

    print("Alice bits:       ", eve["alice_bits"])
    print("Alice bases:      ", eve["alice_bases"])
    print("Eve bases:        ", eve["eve_bases"])
    print("Eve measurements: ", eve["eve_results"])
    print("Bob bases:        ", eve["bob_bases"])
    print("Bob measurements: ", eve["bob_results"])

    print("\nKept positions:   ", eve["kept_positions"])
    print("Discarded:        ", eve["discarded_positions"])

    print("\nAlice sifted key: ", eve["sifted_alice"])
    print("Bob sifted key:   ", eve["sifted_bob"])

    print(f"\nQBER: {eve['qber'] * 100:.2f}%")

    print("\n========================================")
    print("             COMPARISON")
    print("========================================")

    print(
        f"No Eve : {normal['qber'] * 100:.2f}% QBER"
    )

    print(
        f"With Eve: {eve['qber'] * 100:.2f}% QBER"
    )

    print("\n")
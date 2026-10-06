import random

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator


# --------------------------------------------------
# 1. Generate random classical bits and bases
# --------------------------------------------------

def generate_bits(n):
    return [random.randint(0, 1) for _ in range(n)]


def generate_bases(n):
    # 0 = Z basis
    # 1 = X basis
    return [random.randint(0, 1) for _ in range(n)]


# --------------------------------------------------
# 2. Alice encodes one bit into a qubit
# --------------------------------------------------

def encode_qubit(bit, basis):
    circuit = QuantumCircuit(1, 1)

    if basis == 0:
        # Z basis
        # 0 -> |0>
        # 1 -> |1>
        if bit == 1:
            circuit.x(0)

    else:
        # X basis
        # 0 -> |+>
        # 1 -> |->
        if bit == 1:
            circuit.x(0)

        circuit.h(0)

    return circuit


# --------------------------------------------------
# 3. Bob measures the received qubit
# --------------------------------------------------

def measure_qubit(circuit, basis):

    if basis == 1:
        # Convert X-basis measurement
        # into a Z-basis measurement.
        circuit.h(0)

    circuit.measure(0, 0)

    simulator = AerSimulator()
    result = simulator.run(circuit, shots=1).result()

    counts = result.get_counts()

    return int(next(iter(counts)))


# --------------------------------------------------
# 4. BB84 protocol
# --------------------------------------------------

def run_bb84(n=20):

    # Alice's random information
    alice_bits = generate_bits(n)
    alice_bases = generate_bases(n)

    # Bob independently chooses random bases
    bob_bases = generate_bases(n)

    bob_results = []

    # ----------------------------------------------
    # Quantum transmission
    # ----------------------------------------------

    for i in range(n):

        # Alice prepares the qubit
        circuit = encode_qubit(
            alice_bits[i],
            alice_bases[i]
        )

        # Bob measures it
        result = measure_qubit(
            circuit,
            bob_bases[i]
        )

        bob_results.append(result)

    # ----------------------------------------------
    # Sifting
    # ----------------------------------------------

    sifted_alice = []
    sifted_bob = []
    kept_positions = []
    discarded_positions = []

    for i in range(n):

        if alice_bases[i] == bob_bases[i]:

            # Same basis → keep
            sifted_alice.append(alice_bits[i])
            sifted_bob.append(bob_results[i])
            kept_positions.append(i)

        else:

            # Different basis → discard
            discarded_positions.append(i)

    # ----------------------------------------------
    # QBER
    # ----------------------------------------------

    if len(sifted_alice) == 0:
        qber = None
    else:
        errors = sum(
            a != b
            for a, b in zip(sifted_alice, sifted_bob)
        )

        qber = errors / len(sifted_alice)

    return {
        "alice_bits": alice_bits,
        "alice_bases": alice_bases,
        "bob_bases": bob_bases,
        "bob_results": bob_results,
        "kept_positions": kept_positions,
        "discarded_positions": discarded_positions,
        "sifted_alice": sifted_alice,
        "sifted_bob": sifted_bob,
        "qber": qber,
    }


# --------------------------------------------------
# 5. Display results
# --------------------------------------------------

if __name__ == "__main__":

    data = run_bb84(20)

    print("\n========== BB84 SIMULATION ==========\n")

    print("Alice bits:       ", data["alice_bits"])
    print("Alice bases:      ", data["alice_bases"])
    print("Bob bases:        ", data["bob_bases"])
    print("Bob measurements: ", data["bob_results"])

    print("\nKept positions:   ", data["kept_positions"])
    print("Discarded:        ", data["discarded_positions"])

    print("\nAlice sifted key:  ", data["sifted_alice"])
    print("Bob sifted key:    ", data["sifted_bob"])

    if data["qber"] is not None:
        print(f"\nQBER: {data['qber'] * 100:.2f}%")

    print("\n=====================================\n")
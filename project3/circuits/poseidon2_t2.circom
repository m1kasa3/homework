pragma circom 2.0.0;
include "circomlib/poseidon.circom";

// Poseidon2 parameters: (n, t, d) = (256, 2, 5)
template Poseidon2Hash() {
    signal input x[2];        // private input: preimage
    signal input hash;        // public input: expected hash output

    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== x[0];
    poseidon.inputs[1] <== x[1];

    poseidon.output === hash;
}

component main = Poseidon2Hash();

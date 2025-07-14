PTAU_FILE=powersOfTau28_hez_final_10.ptau
CIRCUIT=circuits/poseidon2_t2.circom
BUILD=build

all: compile witness setup prove verify

compile:
	mkdir -p $(BUILD)
	circom $(CIRCUIT) --r1cs --wasm --sym -o $(BUILD)

witness:
	node $(BUILD)/poseidon2_t2_js/generate_witness.js $(BUILD)/poseidon2_t2_js/poseidon2_t2.wasm inputs/input.json $(BUILD)/witness.wtns

setup:
	snarkjs groth16 setup $(BUILD)/poseidon2_t2.r1cs $(PTAU_FILE) $(BUILD)/poseidon2.zkey
	snarkjs zkey export verificationkey $(BUILD)/poseidon2.zkey $(BUILD)/verification_key.json

prove:
	snarkjs groth16 prove $(BUILD)/poseidon2.zkey $(BUILD)/witness.wtns $(BUILD)/proof.json $(BUILD)/public.json

verify:
	snarkjs groth16 verify $(BUILD)/verification_key.json $(BUILD)/public.json $(BUILD)/proof.json

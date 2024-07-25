package main

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

func main() {
	// Scheme parameters
	var params hefloat.Parameters
	var err error

	if params, err = hefloat.NewParametersFromLiteral(
		hefloat.ParametersLiteral{
			LogN:            14,                                    // A ring degree of 2^{14}
			LogQ:            []int{55, 45, 45, 45, 45, 45, 45, 45}, // An initial prime of 55 bits and 7 primes of 45 bits
			LogP:            []int{61},                             // The log2 size of the key-switching prime
			LogDefaultScale: 45,                                    // The default log2 of the scaling factor
		}); err != nil {
		panic(err)
	}

	// Key Generation
	kgen := rlwe.NewKeyGenerator(params)

	// For now we will generate the following keys:
	//   - SecretKey: the secret from which all other keys are derived
	//   - PublicKey: an encryption of zero, which can be shared and enable anyone to encrypt plaintexts.
	//   - RelinearizationKey: an evaluation key which is used during ciphertext x ciphertext multiplication to ensure ciphertext compactness.
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk) // Note that we can generate any number of public keys associated to the same Secret Key.
	rlk := kgen.GenRelinearizationKeyNew(sk)

	// To store and manage the loading of evaluation keys, we instantiate a struct that complies to the `rlwe.EvaluationKeySetInterface` Interface.
	// The package `rlwe` provides a simple struct that complies to this interface, but a user can design its own struct compliant to the `rlwe.EvaluationKeySetInterface`
	// for example to manage the loading/saving/persistence of the keys in the memory.
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	rot := 1
	galEls := []uint64{
		// The galois element for the cyclic rotations by 5 positions to the left.
		params.GaloisElement(rot),
		// The galois element for the complex conjugatation.
		params.GaloisElementForComplexConjugation(),
	}

	// Encryptor and Decryptor
	encryptor := hefloat.NewEncryptor(params, pk)
	decryptor := hefloat.NewDecryptor(params, sk)

	// Encoder
	encoder := hefloat.NewEncoder(params)

	// Evaluator
	evaluator := hefloat.NewEvaluator(params, evk)
	evaluator = evaluator.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galEls, sk)...))

	Mat := [][]float64{{1, 2, 3, 4, 5}, {1, 2, 3, 4, 5}, {1, 2, 3, 4, 5}}
	vect := []float64{1, 2, 3, 4, 5}

	k := len(Mat)
	flatMatrix := flatten2DArray(Mat)
	repeatedVect := repeatArray(vect, k)

	fmt.Printf("%v\n", flatMatrix)
	fmt.Printf("%v\n", repeatedVect)

	plaintextMat := rlwe.NewPlaintext(params.Parameters, params.MaxLevel())
	testval := []complex128{complex(1.0, 0.0)}
	encoder.Encode(testval, plaintextMat)
	resenc := make([]complex128, params.MaxSlots())
	if err := encoder.Decode(plaintextMat, resenc); err != nil {
		panic(err)
	}
	fmt.Printf("%v\n", resenc)

	ciphertextMat, err := encryptor.EncryptNew(plaintextMat)
	if err != nil {
		panic(err)
	}
	plaintextVect := rlwe.NewPlaintext(params.Parameters, params.MaxLevel())
	encoder.Encode(repeatedVect, plaintextVect)
	ciphertextVect, err := encryptor.EncryptNew(plaintextVect)
	if err != nil {
		panic(err)
	}
	evaluator.MulRelin(ciphertextVect, ciphertextMat, ciphertextVect)

	// Rescale to bring the ciphertext back to the same scale
	evaluator.Rescale(ciphertextVect, ciphertextVect)

	// evaluator.InnerSum(ciphertextVect, 1, 2, ciphertextVect)

	// Decrypt and Decode
	decrypted := decryptor.DecryptNew(ciphertextVect)
	res := make([]float64, params.MaxSlots())
	if err := encoder.Decode(decrypted, res); err != nil {
		panic(err)
	}
	// Output the result
	for i := range res {
		if math.Abs(res[i]) < 1000 {
			fmt.Printf("[%d] = %.1f ", i, res[i])
			if i%5 == 4 {
				fmt.Printf("\n")
			}
		}
	}
}

func flatten2DArray(arr [][]float64) []float64 {
	var result []float64
	for _, row := range arr {
		result = append(result, row...)
	}
	return result
}

func repeatArray(arr []float64, k int) []float64 {
	n := len(arr)
	result := make([]float64, n*k)
	for i := 0; i < k; i++ {
		copy(result[i*n:(i+1)*n], arr)
	}
	return result
}

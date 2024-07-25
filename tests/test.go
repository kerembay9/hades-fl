package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func main() {
	// Parameters for CKKS scheme
	params, err := ckks.NewParametersFromLiteral(ckks.PN13QP218)
	if err != nil {
		panic(err)
	}

	// Generate a new key pair
	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	rlk := kgen.GenRelinearizationKey(sk, 1)

	// Encryptor, Decryptor, and Evaluator
	encryptor := ckks.NewEncryptor(params, pk)
	decryptor := ckks.NewDecryptor(params, sk)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})

	// Create a new encoder
	encoder := ckks.NewEncoder(params)

	// Plaintext values
	values1 := []float64{2}
	values2 := []float64{3}
	values3 := []float64{4, 5, 6}

	// Encode the values into plaintexts
	plaintext1 := rlwe.NewPlaintext(params.Parameters, params.MaxLevel())
	plaintext2 := rlwe.NewPlaintext(params.Parameters, params.MaxLevel())
	plaintext3 := rlwe.NewPlaintext(params.Parameters, params.MaxLevel())
	encoder.Encode(values1, plaintext1, params.LogSlots())
	encoder.Encode(values2, plaintext2, params.LogSlots())
	encoder.Encode(values3, plaintext3, params.LogSlots())

	// Encrypt the plaintexts
	ciphertext1 := encryptor.EncryptNew(plaintext1)
	ciphertext2 := encryptor.EncryptNew(plaintext2)
	ciphertext3 := encryptor.EncryptNew(plaintext3)

	// Homomorphically multiply the ciphertexts
	evaluator.MulRelin(ciphertext1, ciphertext2, ciphertext1)

	// Rescale after the first multiplication
	evaluator.Rescale(ciphertext1, params.DefaultScale(), ciphertext1)

	// Homomorphically multiply the result with the third ciphertext
	evaluator.Mul(ciphertext1, ciphertext3, ciphertext1)

	// Rescale after the second multiplication
	// evaluator.Rescale(ciphertext1, params.DefaultScale(), ciphertext1)

	// Decrypt the result
	decryptedPlaintext := decryptor.DecryptNew(ciphertext1)

	// Decode the decrypted values
	decodedValues := encoder.Decode(decryptedPlaintext, params.LogSlots())

	// Print the results
	fmt.Printf("Original values: %v, %v, and %v\n", values1[0], values2[0], values3)
	fmt.Printf("Decrypted product: %.2f\n", real(decodedValues[0]))
	length := len(decodedValues)
	fmt.Printf("Length of the vector: %d\n", length)

	// Print the real part of each element in the vector
	fmt.Println("Real parts of the vector elements:")
	for _, num := range decodedValues {
		if real(num) > 0.1 || real(num) < -0.1 {
			fmt.Printf("%.2f, ", real(num))
		}
	}
}

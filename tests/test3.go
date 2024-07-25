package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func main() {
	// Scheme parameters
	params, err := ckks.NewParametersFromLiteral(ckks.PN14QP438)
	if err != nil {
		panic(err)
	}
	fmt.Printf("params: %v\n", params)
	// Key Generation
	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	rlk := kgen.GenRelinearizationKey(sk, 1)

	// Encryptor and Decryptor
	encryptor := ckks.NewEncryptor(params, pk)
	decryptor := ckks.NewDecryptor(params, sk)

	// Encoder
	encoder := ckks.NewEncoder(params)

	// Evaluator
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})

	// Message
	values := []complex128{complex(2.0, 0), complex(3.0, 0), complex(4.0, 0), complex(5.0, 0)}
	plaintext := rlwe.NewPlaintext(params.Parameters, params.MaxLevel())
	encoder.Encode(values, plaintext, params.LogSlots())

	// Encrypt
	ciphertext := encryptor.EncryptNew(plaintext)

	// vector2 value
	vector2 := []complex128{complex(2.0, 0), complex(3.0, 0), complex(4.0, 0), complex(5.0, 0)}

	// Multiplication
	plaintextvector2 := rlwe.NewPlaintext(params.Parameters, params.MaxLevel())
	encoder.Encode(vector2, plaintextvector2, params.LogSlots())
	evaluator.MulRelin(ciphertext, plaintextvector2, ciphertext)

	// Rescale to bring the ciphertext back to the same scale
	evaluator.Rescale(ciphertext, params.DefaultScale(), ciphertext)

	// Decrypt and Decode
	decrypted := decryptor.DecryptNew(ciphertext)
	decoded := encoder.Decode(decrypted, params.LogSlots())

	// Output the result
	for i := range decoded {
		if real(decoded[i]) > 0.1 {
			fmt.Printf("Result[%d] = %.1f\n", i, real(decoded[i]))
		}
	}
	Mat := [][]float64{{1, 2, 3, 4, 5}, {1, 2, 3, 4, 5}, {1, 2, 3, 4, 5}}
	vect := []float64{1, 2, 3, 4, 5}

	k := len(Mat)
	flatMatrix := flatten2DArray(Mat)
	repeatedVect := repeatArray(vect, k)

	plaintextMat := rlwe.NewPlaintext(params.Parameters, params.MaxLevel())
	encoder.Encode(flatMatrix, plaintextMat, params.LogSlots())
	ciphertextMat := encryptor.EncryptNew(plaintextMat)

	plaintextVect := rlwe.NewPlaintext(params.Parameters, params.MaxLevel())
	encoder.Encode(repeatedVect, plaintextVect, params.LogSlots())
	ciphertexVect := encryptor.EncryptNew(plaintextVect)

	evaluator.MulRelin(ciphertexVect, ciphertextMat, ciphertexVect)

	// Rescale to bring the ciphertext back to the same scale
	evaluator.Rescale(ciphertext, params.DefaultScale(), ciphertext)

	// Decrypt and Decode
	decryptedtwo := decryptor.DecryptNew(ciphertexVect)
	decodedtwo := encoder.Decode(decryptedtwo, params.LogSlots())

	// Output the result
	for i := range decodedtwo {
		if real(decodedtwo[i]) > 0.1 {
			fmt.Printf("[%d] = %.1f ", i, real(decodedtwo[i]))
			if i%5 == 4 {
				fmt.Printf("\n")
			}
		}
	}

	// matVectMul(Mat, vect)
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

// func matVectMul(Mat [][]float64, vect []float64) []float64 {

// 	Mul :=
// 	return vect
// }

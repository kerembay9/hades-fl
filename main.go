package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

func main() {
	// Scheme parameters
	var err error
	var params hefloat.Parameters

	// 128-bit secure parameters enabling depth-7 circuits.
	// LogN:14, LogQP: 431.
	if params, err = hefloat.NewParametersFromLiteral(
		hefloat.ParametersLiteral{
			LogN:            14,                                    // log2(ring degree)
			LogQ:            []int{55, 45, 45, 45, 45, 45, 45, 45}, // log2(primes Q) (ciphertext modulus)
			LogP:            []int{61},                             // log2(primes P) (auxiliary modulus)
			LogDefaultScale: 45,                                    // log2(scale)
		}); err != nil {
		panic(err)
	}

	// Key Generator
	kgen := rlwe.NewKeyGenerator(params)

	// Secret Key
	sk := kgen.GenSecretKeyNew()

	// Encoder
	ecd := hefloat.NewEncoder(params)

	// Encryptor
	enc := rlwe.NewEncryptor(params, sk)

	// Decryptor
	dec := rlwe.NewDecryptor(params, sk)

	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	eval := hefloat.NewEvaluator(params, evk)

	rot := 1
	galEls := []uint64{
		// The galois element for the cyclic rotations by 5 positions to the left.
		params.GaloisElement(rot),
		// The galois element for the complex conjugatation.
		params.GaloisElementForComplexConjugation(),
	}

	// We then generate the `rlwe.GaloisKey`s element that corresponds to these galois elements.
	// And we update the evaluator's `rlwe.EvaluationKeySet` with the new keys.
	eval = eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galEls, sk)...))

	Mat := [][]float64{{0, 1, 2, 3}, {4, 5, 6, 7}, {8, 9, 10, 11}, {12, 13, 14, 15}}
	vect := []float64{1, 2, 3, 4}

	k := len(Mat)
	flatMatrix := flatten2DArrayCol(Mat)
	repeatedVect := repeatArray(vect, k)

	fmt.Printf("Vector: %v\n", vect)
	fmt.Printf("Matrix: %v\n", Mat)

	ptMat := hefloat.NewPlaintext(params, params.MaxLevel())
	ptVect := hefloat.NewPlaintext(params, params.MaxLevel())

	// Encodes the vector of plaintext values
	if err = ecd.Encode(flatMatrix, ptMat); err != nil {
		panic(err)
	}
	// Encodes the vector of plaintext values
	if err = ecd.Encode(repeatedVect, ptVect); err != nil {
		panic(err)
	}

	// Encrypts the vector of plaintext values
	var ctMat *rlwe.Ciphertext
	if ctMat, err = enc.EncryptNew(ptMat); err != nil {
		panic(err)
	}

	// Encrypts the vector of plaintext values
	var ctVect *rlwe.Ciphertext
	if ctVect, err = enc.EncryptNew(ptVect); err != nil {
		panic(err)
	}

	ct, err := eval.MulRelinNew(ctVect, ctMat)
	if err != nil {
		panic(err)
	}

	ct2, err := eval.RotateNew(ct, rot)
	if err != nil {
		panic(err)
	}

	ct3, err := eval.RotateNew(ct2, rot)
	if err != nil {
		panic(err)
	}

	ct4, err := eval.RotateNew(ct3, rot)
	if err != nil {
		panic(err)
	}

	eval.Add(ct, ct2, ct)
	eval.Add(ct, ct3, ct)
	eval.Add(ct, ct4, ct)

	// // Decrypts the vector of plaintext values
	ptdec := dec.DecryptNew(ct)
	// // Decrypts the vector of plaintext values
	// ptDecVect := dec.DecryptNew(ctVect)

	// Decodes the plaintext
	have := make([]float64, params.MaxSlots())
	if err = ecd.Decode(ptdec, have); err != nil {
		panic(err)
	}

	// Pretty prints some values
	fmt.Printf("Result: ")
	for i := 0; i < 13; i += 4 {
		fmt.Printf("%.2f ", have[i])
	}
}

func flatten2DArrayRow(arr [][]float64) []float64 {
	var result []float64
	for _, row := range arr {
		result = append(result, row...)
	}
	return result
}

func flatten2DArrayCol(arr [][]float64) []float64 {
	if len(arr) == 0 {
		return []float64{}
	}

	rows := len(arr)
	cols := len(arr[0])
	result := make([]float64, 0, rows*cols)

	for col := 0; col < cols; col++ {
		for row := 0; row < rows; row++ {
			result = append(result, arr[row][col])
		}
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

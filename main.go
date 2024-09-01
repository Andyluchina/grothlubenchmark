// this represent the basic groth and lu zk verifiable shuffle
package main

import (
	"ZKproof/elgamal"
	"ZKproof/safeprime"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"time"
)

// isCoprime uses the Euclidean algorithm to check if a and b are coprime.
func isCoprime(a, b *big.Int) bool {
	return new(big.Int).GCD(nil, nil, a, b).Cmp(big.NewInt(1)) == 0
}

func EncryptSegments(h []byte, segments [][]byte) ([][]byte, error) {
	encrypted_segments := make([][]byte, len(segments))
	for i := 0; i < len(segments); i++ {
		encrypted, err := elgamal.Encrypt(h, segments[i])
		if err != nil {
			return nil, err
		}
		encrypted_segments[i] = encrypted
	}
	return encrypted_segments, nil
}

// generatePermutationMatrix generates a permutation matrix of size n using cryptographically secure randomness.
func generatePermutationMatrix(n int) [][]int {
	// Initialize the matrix with zeros.
	matrix := make([][]int, n)
	for i := range matrix {
		matrix[i] = make([]int, n)
	}

	// Generate a cryptographically secure permutation of 0 to n-1.
	perm := securePerm(n)

	// Fill the matrix with 1s according to the permutation.
	for i, val := range perm {
		matrix[i][val] = 1
	}

	return matrix
}

// securePerm generates a cryptographically secure permutation of n integers.
func securePerm(n int) []int {
	perm := make([]int, n)
	for i := 0; i < n; i++ {
		perm[i] = i
	}

	for i := 1; i < n; i++ {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		perm[i], perm[j.Int64()] = perm[j.Int64()], perm[i]
	}

	return perm
}

// printMatrix prints the matrix.
func printMatrix(matrix [][]int) {
	for _, row := range matrix {
		for _, val := range row {
			fmt.Printf("%d ", val)
		}
		fmt.Println()
	}
}

// permuteByteSlicesWithMatrix takes a permutation matrix and an array of byte slices,
// then permutes the array according to the matrix.
func permuteByteSlicesWithMatrix(matrix [][]int, byteSlices [][][]byte) ([][][]byte, error) {
	// Check if the matrix is square and matches the length of the byte slices array
	if len(matrix) == 0 || len(matrix) != len(byteSlices) {
		return nil, fmt.Errorf("matrix and byte slices array size mismatch or empty matrix")
	}

	n := len(matrix)
	for _, row := range matrix {
		if len(row) != n {
			return nil, fmt.Errorf("non-square matrix")
		}
	}

	// Initialize the permuted array of byte slices
	permutedByteSlices := make([][][]byte, n)

	// Apply the permutation described by the matrix to the byte slices
	for i, row := range matrix {
		for j, val := range row {
			if val == 1 {
				if i >= n || j >= n {
					return nil, fmt.Errorf("index out of range in permutation matrix")
				}
				permutedByteSlices[i] = byteSlices[j]
				break
			}
		}
	}

	return permutedByteSlices, nil
}

func generateDatabase(n int, pieces int, curve ecdh.Curve) [][][]byte {
	database := make([][][]byte, n)

	for i := 0; i < n; i++ {
		rows := make([][]byte, pieces)
		for i := range rows {
			rows[i] = elgamal.Generate_msg_bytes(curve)
		}
		database[i] = rows
	}

	return database
}

func generateRandomizers(n int, curve ecdh.Curve) [][]byte {
	rows := make([][]byte, n)
	for i := range rows {
		rows[i] = elgamal.Generate_Random_Dice_seed(curve)
	}
	return rows
}

// func randomizeSingleEntryWithRandomizer(entry []byte, randomizer []byte, pubkey []byte) ([]byte, error) {
//  shared_secret, _ := elgamal.ECDH_bytes(pubkey, randomizer)
//  return elgamal.Encrypt(shared_secret, entry)

// }
func randomizeEncryptEntriesWithRandomizers(database [][][]byte, randomizers [][]byte, pubkey []byte) ([][][]byte, error) {
	if len(database) != len(randomizers) {
		return nil, fmt.Errorf("database and randomizers array size mismatch")
	}

	n := len(database)
	randomizedDatabase := make([][][]byte, n)

	for i := 0; i < n; i++ {
		shared_secret, _ := elgamal.ECDH_bytes(pubkey, randomizers[i])
		randomizedDatabase[i], _ = EncryptSegments(shared_secret, database[i])
	}

	return randomizedDatabase, nil
}

// inversePermutationMatrix computes the inverse of a permutation matrix.
func inversePermutationMatrix(matrix [][]int) ([][]int, error) {
	n := len(matrix)
	// Initialize the inverse matrix with zeros
	inverseMatrix := make([][]int, n)
	for i := 0; i < n; i++ {
		inverseMatrix[i] = make([]int, n)
	}

	// Fill in the inverse matrix
	for rowIndex, row := range matrix {
		found := false
		for colIndex, val := range row {
			if val == 1 {
				if found { // Ensure there's only one '1' per row
					return nil, fmt.Errorf("invalid permutation matrix: multiple 1s in row")
				}
				if inverseMatrix[colIndex][rowIndex] == 1 {
					return nil, fmt.Errorf("invalid permutation matrix: multiple 1s in column")
				}
				inverseMatrix[colIndex][rowIndex] = 1
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("invalid permutation matrix: no 1 found in row")
		}
	}

	return inverseMatrix, nil
}

func ForwardMapping(index int, matrix [][]int) (int, error) {
	row := matrix[index]
	for i, val := range row {
		if val == 1 {
			return i, nil
		}
	}
	return -1, fmt.Errorf("no 1 found in row")
}

func BackwardMapping(index int, matrix [][]int) (int, error) {
	invm, _ := inversePermutationMatrix(matrix)
	row := invm[index]
	for i, val := range row {
		if val == 1 {
			return i, nil
		}
	}
	return -1, fmt.Errorf("no 1 found in row")
}

// generateSecureRandomBits generates a slice of bytes of the specified bit length.
// Note: The bit length n must be divisible by 8, as it returns a slice of bytes.
func generateSecureRandomBits(n int) ([]byte, error) {
	if n%8 != 0 {
		return nil, fmt.Errorf("bit length must be divisible by 8")
	}
	numOfBytes := n / 8
	b := make([]byte, numOfBytes)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func isGenerator(g *big.Int, p *big.Int, q *big.Int) bool {
	group_order := new(big.Int).Mul(p, q)
	if !isCoprime(g, group_order) {
		return false
	}
	if new(big.Int).Exp(g, q, group_order).Cmp(big.NewInt(1)) != 0 && new(big.Int).Exp(g, p, group_order).Cmp(big.NewInt(1)) != 0 {
		return true
	}
	return false
}

// randomBigInt samples a random big.Int in the interval [a, b].
func randomBigInt(a, b *big.Int) (*big.Int, error) {
	// Ensure a <= b
	if a.Cmp(b) > 0 {
		return nil, fmt.Errorf("invalid interval: a must be less than or equal to b")
	}

	// Calculate the difference d = b - a
	d := new(big.Int).Sub(b, a)

	// Generate a random big.Int, r, in the interval [0, d]
	r, err := rand.Int(rand.Reader, new(big.Int).Add(d, big.NewInt(1))) // rand.Int samples in [0, n), so we add 1 to include b
	if err != nil {
		return nil, err
	}

	// Shift r to the interval [a, b] by adding a, resulting in a + r
	return r.Add(r, a), nil
}

func sampleAGenerator(p *big.Int, q *big.Int) *big.Int {
	for {
		g, err := randomBigInt(big.NewInt(2), new(big.Int).Mul(p, q))
		if err != nil {
			return nil
		}
		if isGenerator(g, p, q) {
			return g
		}
	}
}

func sampleNGenerators(p *big.Int, q *big.Int, g_needed int) []*big.Int {
	generators := make([]*big.Int, 0) // Fix: Change the type of generator to []*big.Int
	for i := 0; i < g_needed; i++ {
		generator := sampleAGenerator(p, q)
		generators = append(generators, generator) // Fix: Change the append statement to append a pointer to the generator slice
	}
	return generators // Fix: Change the return statement to return generator instead of &generator
}

// setBigIntWithBytes sets a big.Int value using a slice of bytes and returns the big.Int.
func setBigIntWithBytes(b []byte) *big.Int {
	var num big.Int
	num.SetBytes(b) // Interpret b as a big-endian unsigned integer
	return &num
}

func generate_commitment(gs []*big.Int, ms []*big.Int, d_needed *big.Int, r []byte, N *big.Int) *big.Int {
	r_int := setBigIntWithBytes(r)
	commitment := big.NewInt(1)
	for j := 0; j < len(ms); j++ {
		m := ms[j]
		commitment = new(big.Int).Mul(commitment, new(big.Int).Exp(gs[j], m, N)) // Fix: Add m as the second argument to Mul
	}
	commitment = new(big.Int).Mul(commitment, new(big.Int).Exp(gs[len(ms)], d_needed, N))
	commitment = new(big.Int).Mul(commitment, new(big.Int).Exp(gs[len(ms)+1], r_int, N))
	commitment = new(big.Int).Mod(commitment, N)
	return commitment // Fix: Add return statement
}

func IntToBigInt(n []int) []*big.Int {
	bigInts := make([]*big.Int, len(n))
	for i, val := range n {
		bigInts[i] = big.NewInt(int64(val))
	}
	return bigInts
}

// flattenBytes takes a 2D slice of bytes and flattens it into a 1D slice.
func flattenBytes(twoD [][]byte) []byte {
	var oneD []byte
	for _, slice := range twoD {
		// Append each sub-slice to the new slice.
		oneD = append(oneD, slice...)
	}
	return oneD
}

func NoninteractiveChallengeGeneration(
	ds []*big.Int,
	dj *big.Int,
	dn *big.Int,
	commitments []*big.Int,
	database [][][]byte,
	permutedRandomizedDatabase [][][]byte,
	R_R []byte,
	E_Rs [][]byte,
	pubkeyBytes []byte,
	n int) [][]byte {
	c := [][]byte{}
	for i := 0; i < len(database); i++ {
		params1 := flattenBytes(database[i])
		params2 := flattenBytes(permutedRandomizedDatabase[i])
		params3 := flattenBytes(E_Rs)
		params4 := ds[i].Bytes()
		params5 := commitments[i].Bytes()
		params6 := dj.Bytes()
		params7 := dn.Bytes()
		params8 := R_R
		params9 := pubkeyBytes

		combined := append([]byte{}, params1...)
		combined = append(combined, params2...)
		combined = append(combined, params3...)
		combined = append(combined, params4...)
		combined = append(combined, params5...)
		combined = append(combined, params6...)
		combined = append(combined, params7...)
		combined = append(combined, params8...)
		combined = append(combined, params9...)

		hasher := sha256.New()
		hasher.Write(combined)
		hash := hasher.Sum(nil)
		c = append(c, hash)
	}
	return c
}

func main() {

	// security parameters

	number_of_clients := []int{20, 40, 60, 80, 100}
	// Generate a permutation matrix of size 5.
	l_t := 80
	l_s := 16 // a small security parameter
	pieces := 9
	oddprimes := safeprime.GeneratePrimesWithout2(1 << 15)
	p, q, p_prime, q_prime, _ := safeprime.GenerateGroupSubgroup(160, 15, 140, oddprimes)
	fmt.Println(p, q, p_prime, q_prime)
	fmt.Println("Found the group and subgroup primes.")
	N := new(big.Int).Mul(p, q)
	fmt.Println(N)
	order_of_g := new(big.Int).Mul(p_prime, q_prime)
	l_r := order_of_g.BitLen() // the order of the unique subgroup can be huge so IDK what to put here
	fmt.Println("Security parameter l_r", order_of_g.BitLen())
	l_s_plus_l_r := l_s + l_r
	curve := ecdh.P256()
	fmt.Print("security parameter l_s: ", l_s)
	fmt.Println("security parameter l_s_plus_l_r: ", l_s_plus_l_r)
	// find generators for q'p'

	for _, n := range number_of_clients {

		fmt.Println("Number of clients: ", n)
		// Print the generated matrix.
		privkey, err := curve.GenerateKey(rand.Reader)
		pubkeyBytes := privkey.PublicKey().Bytes()
		if err != nil {
			panic(err)
		}
		gs := sampleNGenerators(p_prime, q_prime, n+2)
		// generate a database with 5 entries eliptic curve points
		database := generateDatabase(n, pieces, curve)

		start := time.Now()
		// fmt.Println("Generators:")
		// fmt.Println(gs)
		// database manipulation

		// // matrix generation
		matrix := generatePermutationMatrix(n)
		inv_matrix, _ := inversePermutationMatrix(matrix)

		// generating ds
		ds := make([]*big.Int, n)
		dj := big.NewInt(0)
		dn := big.NewInt(0)
		for i := 0; i < n; i++ {
			if i == n-1 {
				ds[i] = dn
			} else {
				d, _ := generateSecureRandomBits(l_t + 8)
				ds[i] = setBigIntWithBytes(d)
				dn = new(big.Int).Add(dn, new(big.Int).Neg(ds[i]))
			}

			dj = new(big.Int).Add(dj, new(big.Int).Mul(ds[i], ds[i]))
		}

		// generate commitments
		commitments := make([]*big.Int, n+1)
		rs := make([]*big.Int, 0)
		for i := 0; i <= n; i++ {
			if i == n {
				new_r, err := generateSecureRandomBits(l_t + l_s_plus_l_r)
				if err != nil {
					panic(err)
				}
				commitments[i] = generate_commitment(gs, ds, dj, new_r, N)
				rs = append(rs, setBigIntWithBytes(new_r))
			} else {
				new_r, err := generateSecureRandomBits(l_r)
				if err != nil {
					panic(err)
				}
				backward_index, _ := BackwardMapping(i, matrix)
				d_needed := ds[backward_index]
				d_needed = new(big.Int).Mul(d_needed, big.NewInt(2))
				commitments[i] = generate_commitment(gs, IntToBigInt(inv_matrix[i]), d_needed, new_r, N) // Fix: Add N as the last argument
				rs = append(rs, setBigIntWithBytes(new_r))                                               // Fix: Assign the result of append to rs
			}
		}

		// R_R
		R_R, err := generateSecureRandomBits(256)
		if err != nil {
			panic(err)
		}
		// fmt.Println(R_R)
		// printMatrix(matrix)
		// negate R_R

		// fmt.Println(database)

		// generating set of randomizers
		randomizers := generateRandomizers(n, curve)

		// randomize the entry with the randomizers, permuatation first, randomziation second
		permutedDatabase, _ := permuteByteSlicesWithMatrix(matrix, database)

		permutedRandomizedDatabase, _ := randomizeEncryptEntriesWithRandomizers(permutedDatabase, randomizers, pubkeyBytes)

		// randomize the entry with the randomizers, randomziation first, permuatation second
		// randomizedDatabase, _ := randomizeEncryptEntriesWithRandomizers(database, randomizers, pubkeyBytes)

		// permutedRandomizedDatabase, _ := permuteByteSlicesWithMatrix(matrix, randomizedDatabase)
		// fmt.Println("Original array of byte slices:")
		// for _, slice := range database {
		// 	fmt.Println(slice)
		// }

		// fmt.Println("Randomized and permuted array of byte slices:")
		// for _, slice := range permutedRandomizedDatabase {
		// 	fmt.Println(slice)
		// }

		// // generate Er
		// in the case where there are 9 pieces, we need to generate 9 Ers
		E_R_pos, err := elgamal.ECDH_bytes(pubkeyBytes, R_R) /// encrypting the zero element
		if err != nil {
			panic(err)
		}
		E_R, err := elgamal.ReturnNegative(E_R_pos)
		if err != nil {
			panic(err)
		}

		E_Rs := make([][]byte, pieces)

		for piece := 0; piece < pieces; piece++ {
			E_Rs[piece] = make([]byte, len(E_R))
			copy(E_Rs[piece], E_R)
			for i := 0; i < n; i++ {
				E_i_d_i, err := elgamal.ECDH_bytes(permutedRandomizedDatabase[i][piece], elgamal.PadTo32Bytes(ds[i].Bytes()))
				if err != nil {
					panic(err)
				}
				if ds[i].Cmp(big.NewInt(0)) < 0 {
					// fmt.Println("detected negative ds[i]")
					E_i_d_i, err = elgamal.ReturnNegative(E_i_d_i)
					if err != nil {
						panic(err)
					}
				}
				// fmt.Println("ER", E_Rs[piece])
				E_Rs[piece], err = elgamal.Encrypt(E_Rs[piece], E_i_d_i)
				if err != nil {
					panic(err)
				}
			}

		}

		/// generate challenges ts

		ts := NoninteractiveChallengeGeneration(ds, dj, dn, commitments, database, permutedRandomizedDatabase, R_R, E_Rs, pubkeyBytes, n)

		// generate answers
		fs := make([]*big.Int, n)
		for i := 0; i < n; i++ {
			t_pi_j, _ := ForwardMapping(i, matrix)
			fs[i] = new(big.Int).Add(setBigIntWithBytes(ts[t_pi_j]), ds[i])
		}

		small_z := big.NewInt(0)
		for i := 0; i < n; i++ {
			small_z = new(big.Int).Add(small_z, new(big.Int).Mul(setBigIntWithBytes(ts[i]), rs[i]))
		}
		small_z = new(big.Int).Add(small_z, rs[n])

		// generate big Z Big_Z
		Big_Z := new(big.Int).Set(setBigIntWithBytes(R_R))
		for i := 0; i < n; i++ {
			t_pi_i, _ := ForwardMapping(i, matrix)
			Big_Z = new(big.Int).Add(Big_Z, new(big.Int).Mul(setBigIntWithBytes(randomizers[i]), setBigIntWithBytes(ts[t_pi_i])))
		}

		elapsed := time.Since(start)
		fmt.Println("Time elapsed for shuffle: ", elapsed.Milliseconds())
		////// verification

		proof_start := time.Now()
		/// first check
		/// sum up fs and check if it is equal to sum of ts
		sum := big.NewInt(0)
		for _, f := range fs {
			sum.Add(sum, f)
		}
		sum_ts := big.NewInt(0)
		for _, t := range ts {
			sum_ts.Add(sum_ts, setBigIntWithBytes(t))
		}
		// fmt.Println("Sum of fs:", sum)
		// fmt.Println("Sum of ts:", sum_ts)
		if sum.Cmp(sum_ts) == 0 {
			// fmt.Println("First Test PASSED!!!!!!!!!Sum of fs is equal to sum of ts")
		} else {
			fmt.Println("Sum of fs is not equal to sum of ts")
		}

		// calculate f_delta
		f_delta := big.NewInt(0)
		// sum of f squared
		for _, f := range fs {
			f_delta.Add(f_delta, new(big.Int).Mul(f, f))
		}
		// minus sum of ts squared
		for _, t := range ts {
			f_delta.Sub(f_delta, new(big.Int).Mul(setBigIntWithBytes(t), setBigIntWithBytes(t)))
		}

		/// conducting second check
		second_condition_right_hand_side := generate_commitment(gs, fs, f_delta, small_z.Bytes(), N)

		second_condition_left_hand_side := new(big.Int).Set(commitments[n])
		for i := 0; i < n; i++ {
			second_condition_left_hand_side = new(big.Int).Mul(second_condition_left_hand_side, new(big.Int).Exp(commitments[i], setBigIntWithBytes(ts[i]), N))
		}
		second_condition_left_hand_side = new(big.Int).Mod(second_condition_left_hand_side, N)

		// compare the two sides
		if second_condition_left_hand_side.Cmp(second_condition_right_hand_side) == 0 {
			// fmt.Println("Second Test PASSED!!!!!!!!!")
		} else {
			fmt.Println("they are not equal! Failed???????")
		}

		/// conducting third check
		for piece := 0; piece < pieces; piece++ {
			third_condition_left_hand_side := elgamal.ReturnInfinityPoint()
			if err != nil {
				panic(err)
			}
			for i := 0; i < n; i++ {
				E_i_f_i, err := elgamal.ECDH_bytes(permutedRandomizedDatabase[i][piece], elgamal.PadTo32Bytes(fs[i].Bytes()))
				if err != nil {
					panic(err)
				}
				// check if fs[i] is negative
				if fs[i].Cmp(big.NewInt(0)) < 0 {
					fmt.Println("detected negative fs[i]")
					E_i_f_i, err = elgamal.ReturnNegative(E_i_f_i)
					if err != nil {
						panic(err)
					}
				}
				third_condition_left_hand_side, err = elgamal.Encrypt(third_condition_left_hand_side, E_i_f_i)
				if err != nil {
					panic(err)
				}
			}

			third_condition_right_hand_side, err := elgamal.ECDH_bytes(pubkeyBytes, elgamal.PadTo32Bytes(Big_Z.Bytes()))
			if err != nil {
				panic(err)
			}
			third_condition_right_hand_side, err = elgamal.Encrypt(third_condition_right_hand_side, E_Rs[piece])
			if err != nil {
				panic(err)
			}
			for i := 0; i < n; i++ {
				e_i_t_i, err := elgamal.ECDH_bytes(database[i][piece], ts[i])
				if err != nil {
					panic(err)
				}
				third_condition_right_hand_side, err = elgamal.Encrypt(third_condition_right_hand_side, e_i_t_i)
				if err != nil {
					panic(err)
				}
			}

			if bytes.Equal(third_condition_left_hand_side, third_condition_right_hand_side) {
				// fmt.Println("Third Test PASSED!!!!!!!!!")
			} else {
				fmt.Println("Third Test not equal! Failed???????")
			}
		}
		proof_end := time.Since(proof_start)
		fmt.Println("Time elapsed for proof: ", proof_end.Milliseconds())
		fmt.Println("\n")
	}

}

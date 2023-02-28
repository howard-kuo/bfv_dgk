#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include "seal/seal.h"
#include "rand.h"
#include "info.h"
#include "benchmark.h"
#include "example.h"


using namespace std;
using namespace seal;

uint64_t val_a = 1123;
uint64_t val_b = 10234;



int main()
{
	EncryptionParameters parms(scheme_type::BFV);

	size_t poly_modulus_degree = 2048;
	size_t plain_modulus = PlainModulus::Batching(poly_modulus_degree, 16).value();
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(plain_modulus);

	cout << "Plain modulus is " << plain_modulus << endl;

	auto context = SEALContext::Create(parms);

	KeyGenerator keygen(context);
	PublicKey pk = keygen.public_key();
	SecretKey sk = keygen.secret_key();

	Encryptor encryptor(context, pk, sk);
	Decryptor decryptor(context, sk);
	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);

	Plaintext P(10);
	for (size_t i = 0; i < 10; i++) {
		P[i] = i;
	}
	batch_encoder.encode(P);
	Ciphertext C;
	encryptor.encrypt(P, C);

	chrono::high_resolution_clock::time_point time_start, time_end;
	chrono::microseconds time_diff;

	

	cout << "Waiting..." << endl;
	size_t iters = 1000;

	time_start = chrono::high_resolution_clock::now();

	for (size_t i = 0; i < iters; i++) {
		//evaluator.multiply_plain_inplace(C, P);
		benchmark(val_b, val_a, context, encryptor, decryptor, evaluator, batch_encoder);
	}
		
	time_end = chrono::high_resolution_clock::now();


	time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
	
	cout << "Repeat " << iters << " times for benchmark." << endl;
	cout << "Done [" << time_diff.count() << " microseconds]" << endl;
	cout << "---Key Gen:\t [" << setw(10) << keygen_diff.count() << " microseconds]" << endl;
	cout << "---Encrypt:\t [" << setw(10) << encrypt_diff.count() << " microseconds]" << endl;
	cout << "---Decrypt:\t [" << setw(10) << decrypt_diff.count() << " microseconds]" << endl;
	cout << "---Rotate :\t [" << setw(10) << rotate_diff.count() << " microseconds]" << endl;
	cout << "---Random :\t [" << setw(10) << rand_diff.count() << " microseconds]" << endl;
	cout << "---Mul    :\t [" << setw(10) << multiply_diff.count() << " microseconds]" << endl;
	cout << "---Ntt193 :\t [" << setw(10) << ntt193::ntt193_diff.count() << " microseconds]" << endl;

	
	system("pause");
}


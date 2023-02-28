#pragma once
#include <iostream>
#include <vector>
#include "seal/seal.h"
#include "rand.h"
#include "info.h"
#include "example.h"

using namespace std;
using namespace seal;

chrono::microseconds keygen_diff;
chrono::microseconds encrypt_diff;
chrono::microseconds decrypt_diff;
chrono::microseconds multiply_diff;
chrono::microseconds rotate_diff;


void encode(uint64_t val, vector<uint64_t> &pod_matrix);

void benchmark(uint64_t val_a, uint64_t val_b, shared_ptr<SEALContext> context,
	Encryptor& encryptor, Decryptor& decryptor, Evaluator& evaluator, BatchEncoder& batch_encoder)
{
	// Goal: securely compute (a >= b)?

	// Set Parameters

	
	size_t poly_modulus_degree = 2048;
	size_t plain_modulus = PlainModulus::Batching(poly_modulus_degree, 14).value();

	size_t slot_count = batch_encoder.slot_count();
	size_t row_size = slot_count / 2;


	vector<uint64_t> pod_a(2048), pod_b(2048), pod_info(2048), pod_rand(2048), pod_rand_2(2048);
	vector<uint64_t> v_1, v_2, v_3, v_4;
	Plaintext plain_a, plain_b, plain_info, plain_rand;
	Plaintext p_1, p_2, p_3, p_4, p_5, p_6;
	Ciphertext c_1, c_2, c_3, c_4, c_5, c_6;
	Ciphertext c_zero;

	shared_ptr<UniformRandomGenerator> rng_b;
	rng_b = BlakePRNGFactory().create();

	encode(val_a, pod_a);
	encode(val_b, pod_b);

	//************************************************************************************
	//*																					*
	//*		Round 1: Alice encrypted a and send it to Bob								*
	//*																					*
	//************************************************************************************

	// Alice encrypt val_a;
	batch_encoder.encode(pod_a, plain_a);
	encryptor.encrypt_symmetric(plain_a, c_1);


	//************************************************************************************
	//*																					*
	//*		Round 2: Bob get Enc(a), computes (a-b)^2 and sends to Alice				*
	//*																					*
	//************************************************************************************


	// Bob get c_1
	batch_encoder.encode(pod_b, plain_b);
	evaluator.multiply_plain(c_1, plain_b, c_2);
	evaluator.add_plain(c_1, plain_b, c_3);
	evaluator.sub_inplace(c_3, c_2);
	evaluator.sub_inplace(c_3, c_2);


	// Add some random


	uniform_poly(&pod_rand[0], 64, plain_modulus, rng_b);

	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_3, c_zero);


	batch_encoder.encode(pod_rand, plain_rand);
	evaluator.add_plain_inplace(c_3, plain_rand);


	//************************************************************************************
	//*																					*
	//*		Round 3: Alice decrypted the cipher and compute	summation					*
	//*					 of the shifts	(which is masked by Bob generated random)		*
	//*																					*
	//************************************************************************************


	// Alice recieved the random polynomial
	decryptor.decrypt(c_3, p_1);
	batch_encoder.decode(p_1, v_1);
	v_1.resize(64);
	v_2.resize(64);
	std::copy(v_1.begin() + 1, v_1.begin() + 64, v_2.begin());

	// compute 1 - (a-b)^2
	for (int i = 0; i < 64; i++) {
		v_1[i] = (1 + plain_modulus - v_1[i]) % plain_modulus;
	}

	// 6 is log 64
	for (int i = 0; i < 6; i++) {
		int step = 1 << i;
		for (int j = 0; j < 64 - step; j++) {
			v_2[j] += v_2[j + step];
			v_2[i] = v_2[i] % plain_modulus;
		}
	}


	v_3.resize(2048);
	for (size_t i = 0; i < 64; i++) {
		v_3[i] = v_1[i] + v_2[i] * 2 + pod_a[i] + 1;
		v_3[i] = v_3[i] % plain_modulus;
	}

	batch_encoder.encode(v_3, p_2);
	encryptor.encrypt_symmetric(p_2, c_4);

	//************************************************************************************
	//*																					*
	//*		Round 4: Using the value of Alice compute to compute a vector				*
	//*					 which contains zero (unique) <=> b > a							*
	//*				 Bob sends it back to Alice (masked by some random number)			*
	//*																					*
	//************************************************************************************

	// bob recieved c_4

	// compute correspond random
	pod_rand.resize(64);
	pod_rand_2.resize(64);

	std::copy(pod_rand.begin() + 1, pod_rand.begin() + 64, pod_rand_2.begin());

	// compute 1 - (a-b)^2
	for (int i = 0; i < 64; i++) {
		pod_rand[i] = (plain_modulus - pod_rand[i]) % plain_modulus;
	}

	// 6 is log 64
	for (int i = 0; i < 6; i++) {
		int step = 1 << i;
		for (int j = 0; j < 64 - step; j++) {
			pod_rand_2[j] += pod_rand_2[j + step];
		}
	}


	vector<uint64_t> pod_rand_3(2048);

	for (size_t i = 0; i < 64; i++) {
		pod_rand_3[i] = pod_rand[i] + pod_rand_2[i] * 2 + pod_b[i];
		pod_rand_3[i] = pod_rand_3[i] % plain_modulus;
	}

	batch_encoder.encode(pod_rand_3, p_3);

	evaluator.sub_plain_inplace(c_4, p_3);

	pod_rand.resize(2048);
	uniform_poly_nz(&pod_rand[0], 64, plain_modulus, rng_b);
	batch_encoder.encode(pod_rand, plain_rand);
	evaluator.multiply_plain_inplace(c_4, plain_rand);


	uniform_poly(&pod_rand[0], 64, plain_modulus, rng_b);
	batch_encoder.encode(pod_rand, plain_rand);

	evaluator.add_plain_inplace(c_4, plain_rand);

	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_4, c_zero);



	//************************************************************************************
	//*																					*
	//*		Round 5: Alice transform it into polynomail mode							*
	//*					 which is for Bob to permute									*
	//*																					*
	//************************************************************************************

	// Alice recieved masking c_4
	decryptor.decrypt(c_4, p_4);
	batch_encoder.decode(p_4, v_4);

	p_5.resize(64);
	for (size_t i = 0; i < 64; i++) {
		p_5[i] = v_4[i];
	}
	encryptor.encrypt_symmetric(p_5, c_5);

	//************************************************************************************
	//*																					*
	//*		Round 6: Bob uses this to random permute and sends 							*
	//*					 it back to Alice												*
	//*																					*
	//************************************************************************************

	// Sends it to Bob
	plain_rand.resize(2048);
	for (size_t i = 0; i < 64; i++) {
		plain_rand[i] = pod_rand[i];
	}
	uniform_poly_nz(&plain_rand[64], 2048 - 64, plain_modulus, rng_b);
	evaluator.sub_plain_inplace(c_5, plain_rand);

	Plaintext plain_shift;
	plain_shift.resize(2048);
	uint64_t rand_index;
	uniform_poly(&rand_index, 1, 2048, rng_b);
	plain_shift[rand_index] = 1;
	evaluator.multiply_plain_inplace(c_5, plain_shift);

	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_5, c_zero);


	//************************************************************************************
	//*																					*
	//*		Final: Decrypt and get the result				 							*
	//*																					*
	//************************************************************************************


	// Sends it back to Alice
	decryptor.decrypt(c_5, p_6);
	uint64_t zero_count = 0;
	for (size_t i = 0; i < p_6.coeff_count(); i++) {
		if (p_6[i] == 0) {
			zero_count++;
		}
	}

}


void benchmark(uint64_t val_a, uint64_t val_b, shared_ptr<SEALContext> context)

{
	KeyGenerator keygen(context);
	PublicKey pk = keygen.public_key();
	SecretKey sk = keygen.secret_key();

	Encryptor encryptor(context, pk, sk); 
	Decryptor decryptor(context, sk);
	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);

	benchmark(val_a, val_b, context, encryptor, decryptor, evaluator, batch_encoder);
}

void benchmark(uint64_t val_a, uint64_t val_b)
{
	EncryptionParameters parms(scheme_type::BFV);

	size_t poly_modulus_degree = 2048;
	size_t plain_modulus = PlainModulus::Batching(poly_modulus_degree, 14).value();
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(plain_modulus);

	auto context = SEALContext::Create(parms);

	benchmark(val_a, val_b, context);
}


//**************************************************************************************

void benchmark32(uint32_t val_a, uint32_t val_b, shared_ptr<SEALContext> context)
{
	// Goal: securely compute (a >= b)?
	chrono::high_resolution_clock::time_point time_start, time_end;


	size_t poly_modulus_degree = 1024;
	size_t plain_modulus = 193;

	time_start = chrono::high_resolution_clock::now();

	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();
	Encryptor encryptor(context, public_key, secret_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	time_end = chrono::high_resolution_clock::now();
	keygen_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

	vector<uint32_t> pod_a(32), pod_b(32), pod_info(32), pod_rand(32), pod_rand_2(32);
	vector<uint32_t> tmp;
	vector<uint32_t> v_1(32), v_2(32), v_3(32), v_4(32);
	Plaintext plain_a, plain_b, plain_info, plain_rand;
	Plaintext p_1, p_2, p_3, p_4, p_5, p_6;
	Ciphertext c_1, c_2, c_3, c_4, c_5, c_6;
	Ciphertext c_zero;

	//encode(val_a, pod_a);
	//encode(val_b, pod_b);
	for (size_t i = 0; i < 32; i++) {
		pod_a[i] = (val_a >> i) & 0x01;
	}
	for (size_t i = 0; i < 32; i++) {
		pod_b[i] = (val_b >> i) & 0x01;
	}

	//************************************************************************************
	//*																					*
	//*		Round 1: Alice encrypted a and send it to Bob								*
	//*																					*
	//************************************************************************************

	// Alice encrypt val_a;
	encode(pod_a, plain_a);
	
	time_start = chrono::high_resolution_clock::now();
	

	encryptor.encrypt_symmetric(plain_a, c_1);

	time_end = chrono::high_resolution_clock::now();
	encrypt_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

	//************************************************************************************
	//*																					*
	//*		Round 2: Bob get Enc(a), computes (a-b)^2 and sends to Alice				*
	//*																					*
	//************************************************************************************


	// Bob get c_1
	encode(pod_b, plain_b);

	time_start = chrono::high_resolution_clock::now();

	evaluator.multiply_plain(c_1, plain_b, c_2);

	time_end = chrono::high_resolution_clock::now();
	multiply_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

	evaluator.add_plain(c_1, plain_b, c_3);
	evaluator.sub_inplace(c_3, c_2);
	evaluator.sub_inplace(c_3, c_2);

	time_start = chrono::high_resolution_clock::now();

	encryptor.encrypt_zero(c_zero);

	time_end = chrono::high_resolution_clock::now();
	encrypt_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

	evaluator.add_inplace(c_3, c_zero);

	//************************************************************************************
	//*																					*
	//*		Round 3: Alice decrypted the cipher and compute	summation					*
	//*					 of the shifts	(which is masked by Bob generated random)		*
	//*																					*
	//************************************************************************************

	// Alice recieved the random polynomial
	time_start = chrono::high_resolution_clock::now();

	decryptor.decrypt(c_3, p_1);

	time_end = chrono::high_resolution_clock::now();
	decrypt_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);


	decode(p_1, v_1);

	time_start = chrono::high_resolution_clock::now();

	v_1.resize(32);
	v_2.resize(32);
	std::copy(v_1.begin() + 1, v_1.begin() + 32, v_2.begin());
	// compute 1 - (a-b)^2
	for (int i = 0; i < 32; i++) {
		v_1[i] = (1 + plain_modulus - v_1[i]) % plain_modulus;
	}

	// 5 is log 32
	for (int i = 0; i < 5; i++) {
		int step = 1 << i;
		for (int j = 0; j < 32 - step; j++) {
			v_2[j] += v_2[j + step];
			v_2[i] = (v_2[i] % plain_modulus);
		}
	}


	for (size_t i = 0; i < 32; i++) {
		v_3[i] = v_1[i] + v_2[i] * 2 + pod_a[i] + 1;
		v_3[i] = v_3[i] % plain_modulus;
	}

	time_end = chrono::high_resolution_clock::now();
	rotate_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

	encode(v_3, p_2);

	time_start = chrono::high_resolution_clock::now();

	encryptor.encrypt_symmetric(p_2, c_4);

	time_end = chrono::high_resolution_clock::now();
	encrypt_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);


	//************************************************************************************
	//*																					*
	//*		Round 4: Using the value of Alice compute to compute a vector				*
	//*					 which contains zero (unique) <=> b > a							*
	//*				 Bob sends it back to Alice (masked by some random number)			*
	//*																					*
	//************************************************************************************


	// bob recieved c_4

	time_start = chrono::high_resolution_clock::now();

	// compute correspond random
	pod_rand.resize(32);
	pod_rand_2.resize(32);

	std::copy(pod_rand.begin() + 1, pod_rand.begin() + 32, pod_rand_2.begin());

	// compute 1 - (a-b)^2
	for (int i = 0; i < 32; i++) {
		pod_rand[i] = (plain_modulus - pod_rand[i]) % plain_modulus;
	}

	// 5 is log 32
	for (int i = 0; i < 5; i++) {
		int step = 1 << i;
		for (int j = 0; j < 32 - step; j++) {
			pod_rand_2[j] += pod_rand_2[j + step];
		}
	}


	vector<uint32_t> pod_rand_3(32);

	for (size_t i = 0; i < 32; i++) {
		pod_rand_3[i] = pod_rand[i] + pod_rand_2[i] * 2 + pod_b[i];
		pod_rand_3[i] = pod_rand_3[i] % plain_modulus;
	}

	time_end = chrono::high_resolution_clock::now();
	rotate_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

	encode(pod_rand_3, p_3);

	evaluator.sub_plain_inplace(c_4, p_3);

	pod_rand.resize(32);
	uniform_poly_nz(&pod_rand[0], 32, plain_modulus);
	encode(pod_rand, plain_rand);

	time_start = chrono::high_resolution_clock::now();

	evaluator.multiply_plain_inplace(c_4, plain_rand);

	time_end = chrono::high_resolution_clock::now();
	encrypt_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

	uniform_poly(&pod_rand[0], 32, plain_modulus);
	encode(pod_rand, plain_rand);

	evaluator.add_plain_inplace(c_4, plain_rand);


	time_start = chrono::high_resolution_clock::now();

	encryptor.encrypt_zero(c_zero);

	time_end = chrono::high_resolution_clock::now();
	encrypt_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

	evaluator.add_inplace(c_4, c_zero);

	//************************************************************************************
	//*																					*
	//*		Round 5: Alice transform it into polynomail mode							*
	//*					 which is for Bob to permute									*
	//*																					*
	//************************************************************************************

	// Alice recieved masking c_4
	time_start = chrono::high_resolution_clock::now();

	decryptor.decrypt(c_4, p_4);

	time_end = chrono::high_resolution_clock::now();
	decrypt_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

	decode(p_4, v_4);

	p_5.resize(32);
	for (size_t i = 0; i < 32; i++) {
		p_5[i] = v_4[i];
	}

	time_start = chrono::high_resolution_clock::now();

	encryptor.encrypt_symmetric(p_5, c_5);

	time_end = chrono::high_resolution_clock::now();
	encrypt_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);


	//************************************************************************************
	//*																					*
	//*		Round 6: Bob uses this to random permute and sends 							*
	//*					 it back to Alice												*
	//*																					*
	//************************************************************************************

	// Sends it to Bob
	plain_rand.resize(1024);
	for (size_t i = 0; i < 32; i++) {
		plain_rand[i] = pod_rand[i];
	}
	uniform_poly_nz(&plain_rand[32], 1024 - 32, plain_modulus);
	evaluator.sub_plain_inplace(c_5, plain_rand);

	Plaintext plain_shift;
	plain_shift.resize(1024);
	uint64_t rand_index;
	uniform_poly(&rand_index, 1, 1024);
	plain_shift[rand_index] = 1;

	time_start = chrono::high_resolution_clock::now();

	evaluator.multiply_plain_inplace(c_5, plain_shift);

	time_end = chrono::high_resolution_clock::now();
	multiply_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);


	time_start = chrono::high_resolution_clock::now();

	encryptor.encrypt_zero(c_zero);

	time_end = chrono::high_resolution_clock::now();
	encrypt_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

	evaluator.add_inplace(c_5, c_zero);


	//************************************************************************************
	//*																					*
	//*		Final: Decrypt and get the result				 							*
	//*																					*
	//************************************************************************************

	// Sends it back to Alice
	time_start = chrono::high_resolution_clock::now();

	decryptor.decrypt(c_5, p_6);

	time_end = chrono::high_resolution_clock::now();
	decrypt_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

	uint64_t zero_count = 0;
	for (size_t i = 0; i < p_6.coeff_count(); i++) {
		if (p_6[i] == 0) {
			zero_count++;
		}
	}
	zero_count += (1024 - int(p_6.coeff_count()));
	
	if (zero_count == 0) {
		if (val_a >= val_b) {
			;
		}
		else {
			cout << val_a << " " << val_b << endl;
			cout << zero_count << endl;
			cout << " Wrong..." << endl;
			system("pause");
		}
	}
	else if (zero_count == 1) {
		if (val_a < val_b) {
			;
		}
		else {
			cout << val_a << " " << val_b << endl;
			cout << zero_count << endl;
			cout << " Wrong..." << endl;
			system("pause");
		}
	}
	else {
		cout << " bug?" << endl;
		system("pause");
	}
	
}

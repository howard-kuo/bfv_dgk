#pragma once
#include <iostream>
#include <vector>
#include "seal/seal.h"
#include "rand.h"
#include "info.h"
#include "ntt.h"

// #define NRAND

using namespace std;
using namespace seal;


void cipher_info(Ciphertext & encrypted, vector<uint64_t> &pod_matrix,
	size_t row_size, uint64_t plain_modulus,
	BatchEncoder &batch_encoder, Decryptor &decryptor)
{
	Plaintext plain;
	decryptor.decrypt(encrypted, plain);
	batch_encoder.decode(plain, pod_matrix);
	print_matrix_signed(pod_matrix, row_size, plain_modulus);
	cout << "    + Noise budget in fresh encryption: "
		<< decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
	cout << endl;
}

void example(uint64_t val_a, uint64_t val_b)
{
	// Goal: securely compute (a >= b)?

	// Set Parameters

	EncryptionParameters parms(scheme_type::BFV);

	size_t poly_modulus_degree = 2048;
	size_t plain_modulus = PlainModulus::Batching(poly_modulus_degree, 14).value();
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(plain_modulus);

	auto context = SEALContext::Create(parms);

	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();
	Encryptor encryptor(context, public_key, secret_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	BatchEncoder batch_encoder(context);
	size_t slot_count = batch_encoder.slot_count();
	size_t row_size = slot_count / 2;

	print_example_banner("Secure Comparison Start");
	print_parameters(context);

	vector<uint64_t> pod_a(2048), pod_b(2048), pod_info(2048), pod_rand(2048), pod_rand_2(2048);
	vector<uint64_t> v_1, v_2, v_3, v_4;
	Plaintext plain_a, plain_b, plain_info, plain_rand;
	Plaintext p_1, p_2, p_3, p_4, p_5, p_6;
	Ciphertext c_1, c_2, c_3, c_4, c_5, c_6;
	Ciphertext c_zero;

	encode(val_a, pod_a);
	encode(val_b, pod_b);
	
	print_example_banner("Private input");
	cout << endl;
	cout << "   Alice: " << val_a << endl;
	print_matrix_signed(pod_a, row_size, plain_modulus);
	cout << "   Bob:   " << val_b << endl;
	print_matrix_signed(pod_b, row_size, plain_modulus);
	cout << endl;

	//************************************************************************************
	//*																					*
	//*		Round 1: Alice encrypted a and send it to Bob								*
	//*																					*
	//************************************************************************************

	print_example_banner("ROUND 1: Alice's turn");
	cout << endl;

	// Alice encrypt val_a;
	batch_encoder.encode(pod_a, plain_a);
	encryptor.encrypt_symmetric(plain_a, c_1);

	cout << " c_1 <- Enc(plain_a)" << endl;
	cipher_info(c_1, pod_info, row_size, plain_modulus, batch_encoder, decryptor);

	//************************************************************************************
	//*																					*
	//*		Round 2: Bob get Enc(a), computes (a-b)^2 and sends to Alice				*
	//*																					*
	//************************************************************************************

	print_example_banner("ROUND 1: Bob's turn  ");
	cout << endl;

	// Bob get c_1
	batch_encoder.encode(pod_b, plain_b);
	evaluator.multiply_plain(c_1, plain_b, c_2);
	evaluator.add_plain(c_1, plain_b, c_3);
	evaluator.sub_inplace(c_3, c_2);
	evaluator.sub_inplace(c_3, c_2);

	cout << " c_3 <- c_1 + plain_b - 2 * c_1 * plain_b" << endl;
	cipher_info(c_3, pod_info, row_size, plain_modulus, batch_encoder, decryptor);

	// Add some random

	cout << " c_3 <- c_3 + r" << endl;

#ifndef NRAND
	uniform_poly(&pod_rand[0], 64, plain_modulus);
#endif
	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_3, c_zero);


	batch_encoder.encode(pod_rand, plain_rand);
	evaluator.add_plain_inplace(c_3, plain_rand);
	cipher_info(c_3, pod_info, row_size, plain_modulus, batch_encoder, decryptor);
	cout << " where random poly is:" << endl;
	print_matrix_signed(pod_rand, row_size, plain_modulus);


	//************************************************************************************
	//*																					*
	//*		Round 3: Alice decrypted the cipher and compute	summation					*
	//*					 of the shifts	(which is masked by Bob generated random)		*
	//*																					*
	//************************************************************************************

	print_example_banner("ROUND 3: Alice's turn");
	cout << endl;

	// Alice recieved the random polynomial
	cout << " p_1 <- Dec(c_3)" << endl;
	decryptor.decrypt(c_3, p_1);
	batch_encoder.decode(p_1, v_1);
	cout << " get decode matrix" << endl;
	print_matrix_signed(v_1, row_size, plain_modulus);
	v_1.resize(64);
	v_2.resize(64);
	std::copy(v_1.begin() + 1, v_1.begin() + 64, v_2.begin());

	// compute 1 - (a-b)^2
	for (int i = 0; i < 64; i++) {
		v_1[i] = util::barrett_reduce_63(1 - v_1[i] + plain_modulus, plain_modulus);
	}

	// 6 is log 64
	for (int i = 0; i < 6; i++) {
		int step = 1 << i;
		for (int j = 0; j < 64 - step; j++) {
			v_2[j] += v_2[j + step];
			v_2[i] = util::barrett_reduce_63(v_2[i], plain_modulus);
		}
	}

	cout << " Evaluate 1 - (a-b)^2. \n" << endl;
	for (int i = 0; i < 12; i++)
		cout << "   " << v_1[i];
	cout << "\n" << endl;

	cout << " Evaluate r-1((a-b)^2 ) + ...\n" << endl;
	for (int i = 0; i < 12; i++)
		cout << "   " << v_2[i];
	cout << "\n" << endl;

	cout << " Recall Alice input\n" << endl;
	for (int i = 0; i < 12; i++)
		cout  << "   " << pod_a[i];
	cout << endl;

	v_3.resize(2048);
	for (size_t i = 0; i < 64; i++) {
		v_3[i] = v_1[i] + v_2[i] * 2 + pod_a[i] + 1;
		v_3[i] = v_3[i] % plain_modulus;
	}

	cout << " Alice final encrypt: \n" << endl;
	for (size_t i = 0; i < 12; i++) {
		cout << "   " << v_3[i];
	}
	cout << "\n" << endl;

	batch_encoder.encode(v_3, p_2);
	encryptor.encrypt_symmetric(p_2, c_4);

	//************************************************************************************
	//*																					*
	//*		Round 4: Using the value of Alice compute to compute a vector				*
	//*					 which contains zero (unique) <=> b > a							*
	//*				 Bob sends it back to Alice (masked by some random number)			*
	//*																					*
	//************************************************************************************

	print_example_banner("ROUND 4: Bob's turn  ");
	cout << endl;

	// bob recieved c_4
	cout << " Bob recieved c_4: \n" << endl;

	// compute correspond random
	pod_rand.resize(64);
	pod_rand_2.resize(64);

	std::copy(pod_rand.begin() + 1, pod_rand.begin() + 64, pod_rand_2.begin());

	// compute 1 - (a-b)^2
	for (int i = 0; i < 64; i++) {
		pod_rand[i] = util::barrett_reduce_63(plain_modulus - pod_rand[i], plain_modulus);
	}

	// 6 is log 64
	for (int i = 0; i < 6; i++) {
		int step = 1 << i;
		for (int j = 0; j < 64 - step; j++) {
			pod_rand_2[j] += pod_rand_2[j + step];
		}
	}

	cout << " Correspond random. \n" << endl;

	cout << " Evaluate 1 - (a-b)^2. \n" << endl;
	for (int i = 0; i < 12; i++)
		cout << "   " << pod_rand[i];
	cout << "\n" << endl;

	cout << " Evaluate r-1((a-b)^2 ) + ...\n" << endl;
	for (int i = 0; i < 12; i++)
		cout << "   " << pod_rand_2[i];
	cout << "\n" << endl;

	cout << " Print pod_b.\n" << endl;
	for (int i = 0; i < 12; i++)
		cout << "   " << pod_b[i];
	cout << "\n" << endl;


	vector<uint64_t> pod_rand_3(2048);

	for (size_t i = 0; i < 64; i++) {
		pod_rand_3[i] = pod_rand[i] + pod_rand_2[i] * 2 + pod_b[i];
		pod_rand_3[i] = pod_rand_3[i] % plain_modulus;
	}

	cout << " Print pod_rand_3.\n" << endl;
	for (int i = 0; i < 12; i++)
		cout << "   " << pod_rand_3[i];
	cout << "\n" << endl;

	batch_encoder.encode(pod_rand_3, p_3);

	evaluator.sub_plain_inplace(c_4, p_3);
	cout << " Contains zero <=> a < b. \n" << endl;
	cipher_info(c_4, pod_info, row_size, plain_modulus, batch_encoder, decryptor);
	cout << " Multiply a non-zero random polynomial.\n" << endl;

	pod_rand.resize(2048);
	uniform_poly_nz(&pod_rand[0], 64, plain_modulus);
	batch_encoder.encode(pod_rand, plain_rand);
	cout << " The random is..." << endl;
	print_matrix_signed(pod_rand, row_size, plain_modulus);
	evaluator.multiply_plain_inplace(c_4, plain_rand);

	cout << " Multiply random." << endl;
	cipher_info(c_4, pod_info, row_size, plain_modulus, batch_encoder, decryptor);

	uniform_poly(&pod_rand[0], 64, plain_modulus);
	batch_encoder.encode(pod_rand, plain_rand);

	evaluator.add_plain_inplace(c_4, plain_rand);
	cout << " Mask it by adding random (plain_rand)." << endl;

	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_4, c_zero);
	cipher_info(c_4, pod_info, row_size, plain_modulus, batch_encoder, decryptor);

	

	//************************************************************************************
	//*																					*
	//*		Round 5: Alice transform it into polynomail mode							*
	//*					 which is for Bob to permute									*
	//*																					*
	//************************************************************************************

	print_example_banner("ROUND 5: Alice's turn");
	cout << endl;

	// Alice recieved masking c_4
	cout << " Alice recieved c_4 and decrypt. " << endl;
	decryptor.decrypt(c_4, p_4);
	batch_encoder.decode(p_4, v_4);
	print_matrix_signed(v_4, row_size, plain_modulus);


	cout << " Put them into time domain. " << endl;
	cout << " p_5 <- decode(Dec(c_4)" << endl;
	cout << " c_5 <- Enc(p_5)" << endl;
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

	print_example_banner("ROUND 6: Bob's turn  ");
	cout << endl;

	// Sends it to Bob
	cout << " Add non zero random at [64, 2048), shuffle then send it back to Alice." << endl;
	plain_rand.resize(2048);
	for (size_t i = 0; i < 64; i++) {
		plain_rand[i] = pod_rand[i];
	}
	uniform_poly_nz(&plain_rand[64], 2048 - 64, plain_modulus);
	evaluator.sub_plain_inplace(c_5, plain_rand);

	Plaintext plain_shift;
	plain_shift.resize(2048);
	uint64_t rand_index;
	uniform_poly(&rand_index, 1, 2048);
	cout << " Random shift " << rand_index << endl;
	plain_shift[rand_index] = 1;
	evaluator.multiply_plain_inplace(c_5, plain_shift);

	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_5, c_zero);
	cipher_info(c_5, pod_info, row_size, plain_modulus, batch_encoder, decryptor);


	//************************************************************************************
	//*																					*
	//*		Final: Decrypt and get the result				 							*
	//*																					*
	//************************************************************************************

	print_example_banner("Final  : Alice decrypt and publish the result");
	cout << endl;

	// Sends it back to Alice
	cout << " Final result: " << endl;
	decryptor.decrypt(c_5, p_6);
	uint64_t zero_count = 0;
	for (size_t i = 0; i < 2048; i++) {
		if (p_6[i] == 0) {
			zero_count++;
		}
	}
	cout << " zero count: " << zero_count << "   (notice zero count is 1 if b > a, and is 0 if a >= b)" <<  endl;
	cout << endl;
	if (zero_count == 0) {
		if (val_a >= val_b) {
			cout << " Correct..." << endl;
		}
		else {
			cout << val_a << " " << val_b << endl;
			cout << " Wrong..." << endl;
		}
	}
	else if (zero_count == 1) {
		if (val_a < val_b) {
			cout << " Correct..." << endl;
		}
		else {
			cout << val_a << " " << val_b << endl;
			cout << " Wrong..." << endl;
		}
	}
	else {
		cout << " bug?" << endl;
	}
	cout  << endl;
}

// ********************************************************************************************************************
void encode(vector<uint32_t>& pod, Plaintext& plain)
{
	vector<uint32_t> tmp(32);
	plain.resize(1024);
	ntt193::encode(pod, tmp);
	for (size_t i = 0; i < 32; i++) {
		plain[32 * i] = tmp[i];
	}
}
void decode(Plaintext& plain, vector<uint32_t>& pod)
{
	vector<uint32_t> tmp(32);
	plain.resize(1024);
	for (size_t i = 0; i < 32; i++) {
		tmp[i] = plain[32 * i];
	}
	ntt193::decode(tmp, pod);
}
void cipher_info(Ciphertext& encrypted, Decryptor& decryptor)
{
	Plaintext plain;
	vector<uint32_t> tmp(32);
	decryptor.decrypt(encrypted, plain);
	plain.resize(1024);
	decode(plain, tmp);
	print32(tmp);
	cout << "    + Noise budget in fresh encryption: "
		<< decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
	cout << endl;
}

void example32(uint32_t val_a, uint32_t val_b)
{
	// Goal: securely compute (a >= b)?

	// Set Parameters

	EncryptionParameters parms(scheme_type::BFV);

	size_t poly_modulus_degree = 1024;
	size_t plain_modulus = 193;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(plain_modulus);

	auto context = SEALContext::Create(parms);

	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();
	Encryptor encryptor(context, public_key, secret_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);


	print_example_banner("Secure Comparison Start");
	print_parameters(context);

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
	print_example_banner("Private input");
	cout << endl;
	cout << "   Alice: " << val_a << endl;
	print32(pod_a);
	cout << "   Bob:   " << val_b << endl;
	print32(pod_b);
	cout << endl;

	//************************************************************************************
	//*																					*
	//*		Round 1: Alice encrypted a and send it to Bob								*
	//*																					*
	//************************************************************************************

	print_example_banner("ROUND 1: Alice's turn");
	cout << endl;

	// Alice encrypt val_a;
	encode(pod_a, plain_a);
	encryptor.encrypt_symmetric(plain_a, c_1);

	cout << " c_1 <- Enc(plain_a)" << endl;
	cipher_info(c_1, decryptor);


	//************************************************************************************
	//*																					*
	//*		Round 2: Bob get Enc(a), computes (a-b)^2 and sends to Alice				*
	//*																					*
	//************************************************************************************

	print_example_banner("ROUND 2: Bob's turn  ");
	cout << endl;

	// Bob get c_1
	encode(pod_b, plain_b);
	evaluator.multiply_plain(c_1, plain_b, c_2);
	evaluator.add_plain(c_1, plain_b, c_3);
	evaluator.sub_inplace(c_3, c_2);
	evaluator.sub_inplace(c_3, c_2);

#ifndef NRAND
	uniform_poly(&pod_rand[0], 32, plain_modulus);
#endif
	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_3, c_zero);


	encode(pod_rand, plain_rand);
	evaluator.add_plain_inplace(c_3, plain_rand);
	cipher_info(c_3, decryptor);
	cout << " where random poly is:" << endl;
	print32(pod_rand);

	cout << " c_3 <- c_1 + plain_b - 2 * c_1 * plain_b (encrypt of (a-b)^2)" << endl;
	cipher_info(c_3, decryptor);

	//************************************************************************************
	//*																					*
	//*		Round 3: Alice decrypted the cipher and compute	summation					*
	//*					 of the shifts	(which is masked by Bob generated random)		*
	//*																					*
	//************************************************************************************

	print_example_banner("ROUND 3: Alice's turn");
	cout << endl;

	// Alice recieved the random polynomial
	cout << " p_1 <- Dec(c_3)" << endl;
	decryptor.decrypt(c_3, p_1);
	decode(p_1, v_1);
	cout << " get decode matrix" << endl;
	print32(v_1);
	v_1.resize(32);
	v_2.resize(32);
	std::copy(v_1.begin() + 1, v_1.begin() + 32, v_2.begin());
	// compute 1 - (a-b)^2
	for (int i = 0; i < 32; i++) {
		v_1[i] = util::barrett_reduce_63(1 + plain_modulus - v_1[i], plain_modulus);
	}

	// 5 is log 32
	for (int i = 0; i < 5; i++) {
		int step = 1 << i;
		for (int j = 0; j < 32 - step; j++) {
			v_2[j] += v_2[j + step];
			v_2[j] = util::barrett_reduce_63(v_2[j], plain_modulus);
		}
	}

	cout << " Evaluate 1 - (a-b)^2. \n" << endl;
	print32(v_1);

	cout << " Evaluate r-1((a-b)^2 ) + ...\n" << endl;
	print32(v_2);

	cout << " Recall Alice input\n" << endl;
	print32(pod_a);

	for (size_t i = 0; i < 32; i++) {
		v_3[i] = v_1[i] + v_2[i] * 2 + pod_a[i] + 1;
		v_3[i] = v_3[i] % plain_modulus;
	}

	cout << " Alice final encrypt: \n" << endl;
	print32(v_3);

	encode(v_3, p_2);
	encryptor.encrypt_symmetric(p_2, c_4);

	//************************************************************************************
	//*																					*
	//*		Round 4: Using the value of Alice compute to compute a vector				*
	//*					 which contains zero (unique) <=> b > a							*
	//*				 Bob sends it back to Alice (masked by some random number)			*
	//*																					*
	//************************************************************************************

	print_example_banner("ROUND 4: Bob's turn  ");
	cout << endl;

	// bob recieved c_4
	cout << " Bob recieved c_4: \n" << endl;

	// compute correspond random
	pod_rand.resize(32);
	pod_rand_2.resize(32);

	std::copy(pod_rand.begin() + 1, pod_rand.begin() + 32, pod_rand_2.begin());

	// compute 1 - (a-b)^2
	for (int i = 0; i < 32; i++) {
		pod_rand[i] = util::barrett_reduce_63(plain_modulus - pod_rand[i], plain_modulus);
	}

	// 5 is log 32
	for (int i = 0; i < 5; i++) {
		int step = 1 << i;
		for (int j = 0; j < 32 - step; j++) {
			pod_rand_2[j] += pod_rand_2[j + step];
		}
	}

	cout << " Correspond random. \n" << endl;

	cout << " Evaluate 1 - (a-b)^2. \n" << endl;
	print32(pod_rand);

	cout << " Evaluate r-1((a-b)^2 ) + ...\n" << endl;
	print32(pod_rand_2);

	cout << " Print pod_b.\n" << endl;
	print32(pod_b);


	vector<uint32_t> pod_rand_3(32);

	for (size_t i = 0; i < 32; i++) {
		pod_rand_3[i] = pod_rand[i] + pod_rand_2[i] * 2 + pod_b[i];
		pod_rand_3[i] = pod_rand_3[i] % plain_modulus;
	}

	cout << " Print pod_rand_3.\n" << endl;
	print32(pod_rand_3);

	encode(pod_rand_3, p_3);

	evaluator.sub_plain_inplace(c_4, p_3);
	cout << " Contains zero <=> a < b. \n" << endl;
	cipher_info(c_4, decryptor);
	cout << " Multiply a non-zero random polynomial.\n" << endl;

	pod_rand.resize(32);
	uniform_poly_nz(&pod_rand[0], 32, plain_modulus);
	encode(pod_rand, plain_rand);
	cout << " The random is..." << endl;
	print32(pod_rand);
	evaluator.multiply_plain_inplace(c_4, plain_rand);

	cout << " Multiply random." << endl;
	cipher_info(c_4, decryptor);

	uniform_poly(&pod_rand[0], 32, plain_modulus);
	encode(pod_rand, plain_rand);

	evaluator.add_plain_inplace(c_4, plain_rand);
	cout << " Mask it by adding random (plain_rand)." << endl;

	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_4, c_zero);
	cipher_info(c_4, decryptor);

	//************************************************************************************
	//*																					*
	//*		Round 5: Alice transform it into polynomail mode							*
	//*					 which is for Bob to permute									*
	//*																					*
	//************************************************************************************

	print_example_banner("ROUND 5: Alice's turn");
	cout << endl;

	// Alice recieved masking c_4
	cout << " Alice recieved c_4 and decrypt. " << endl;
	decryptor.decrypt(c_4, p_4);
	decode(p_4, v_4);
	print32(v_4);


	cout << " Put them into time domain. " << endl;
	cout << " p_5 <- decode(Dec(c_4)" << endl;
	cout << " c_5 <- Enc(p_5)" << endl;
	p_5.resize(32);
	for (size_t i = 0; i < 32; i++) {
		p_5[i] = v_4[i];
	}
	encryptor.encrypt_symmetric(p_5, c_5);

	//************************************************************************************
	//*																					*
	//*		Round 6: Bob uses this to random permute and sends 							*
	//*					 it back to Alice												*
	//*																					*
	//************************************************************************************

	print_example_banner("ROUND 6: Bob's turn  ");
	cout << endl;

	// Sends it to Bob
	cout << " Add non zero random at [32, 1024), shuffle then send it back to Alice." << endl;
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
	cout << " Random shift " << rand_index << endl;
	plain_shift[rand_index] = 1;
	evaluator.multiply_plain_inplace(c_5, plain_shift);

	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_5, c_zero);
	cipher_info(c_5, decryptor);


	//************************************************************************************
	//*																					*
	//*		Final: Decrypt and get the result				 							*
	//*																					*
	//************************************************************************************

	print_example_banner("Final  : Alice decrypt and publish the result");
	cout << endl;

	// Sends it back to Alice
	cout << " Final result: " << endl;
	decryptor.decrypt(c_5, p_6);
	uint64_t zero_count = 0;
	for (size_t i = 0; i < p_6.coeff_count(); i++) {
		if (p_6[i] == 0) {
			zero_count++;
		}
	}
	zero_count += (1024 - int(p_6.coeff_count()));
	cout << " zero count: " << zero_count << "   (notice zero count is 1 if b > a, and is 0 if a >= b)" << endl;
	cout << endl;
	if (zero_count == 0) {
		if (val_a >= val_b) {
			cout << " Correct..." << endl;
		}
		else {
			cout << val_a << " " << val_b << endl;
			cout << " Wrong..." << endl;
			system("pause");
		}
	}
	else if (zero_count == 1) {
		if (val_a < val_b) {
			cout << " Correct..." << endl;
		}
		else {
			cout << val_a << " " << val_b << endl;
			cout << " Wrong..." << endl;
			system("pause");
		}
	}
	else {
		cout << " bug?" << endl;
	}
	cout << endl;

}

void example323(uint32_t val_a, uint32_t val_b)
{
	// Goal: securely compute (a >= b)?

	// Set Parameters

	EncryptionParameters parms(scheme_type::BFV);

	size_t poly_modulus_degree = 1024;
	size_t plain_modulus = 193;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(plain_modulus);

	auto context = SEALContext::Create(parms);

	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();
	Encryptor encryptor(context, public_key, secret_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);


	//print_example_banner("Secure Comparison Start");
	//print_parameters(context);

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
	//print_example_banner("Private input");
	//cout << endl;
	//cout << "   Alice: " << val_a << endl;
	//print32(pod_a);
	//cout << "   Bob:   " << val_b << endl;
	//print32(pod_b);
	//cout << endl;

	//************************************************************************************
	//*																					*
	//*		Round 1: Alice encrypted a and send it to Bob								*
	//*																					*
	//************************************************************************************

	//print_example_banner("ROUND 1: Alice's turn");
	//cout << endl;

	// Alice encrypt val_a;
	encode(pod_a, plain_a);
	encryptor.encrypt_symmetric(plain_a, c_1);

	//cout << " c_1 <- Enc(plain_a)" << endl;
	//cipher_info(c_1, decryptor);


	//************************************************************************************
	//*																					*
	//*		Round 2: Bob get Enc(a), computes (a-b)^2 and sends to Alice				*
	//*																					*
	//************************************************************************************

	//print_example_banner("ROUND 2: Bob's turn  ");
	//cout << endl;

	// Bob get c_1
	encode(pod_b, plain_b);
	evaluator.multiply_plain(c_1, plain_b, c_2);
	evaluator.add_plain(c_1, plain_b, c_3);
	evaluator.sub_inplace(c_3, c_2);
	evaluator.sub_inplace(c_3, c_2);

#ifndef NRAND
	uniform_poly(&pod_rand[0], 32, plain_modulus);
#endif
	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_3, c_zero);


	encode(pod_rand, plain_rand);
	evaluator.add_plain_inplace(c_3, plain_rand);
	//cipher_info(c_3, decryptor);
	//cout << " where random poly is:" << endl;
	//print32(pod_rand);

	//cout << " c_3 <- c_1 + plain_b - 2 * c_1 * plain_b (encrypt of (a-b)^2)" << endl;
	//cipher_info(c_3, decryptor);

	//************************************************************************************
	//*																					*
	//*		Round 3: Alice decrypted the cipher and compute	summation					*
	//*					 of the shifts	(which is masked by Bob generated random)		*
	//*																					*
	//************************************************************************************

	//print_example_banner("ROUND 3: Alice's turn");
	//cout << endl;

	// Alice recieved the random polynomial
	//cout << " p_1 <- Dec(c_3)" << endl;
	decryptor.decrypt(c_3, p_1);
	decode(p_1, v_1);
	//cout << " get decode matrix" << endl;
	//print32(v_1);
	v_1.resize(32);
	v_2.resize(32);
	std::copy(v_1.begin() + 1, v_1.begin() + 32, v_2.begin());
	// compute 1 - (a-b)^2
	for (int i = 0; i < 32; i++) {
		v_1[i] = util::barrett_reduce_63(1 + plain_modulus - v_1[i], plain_modulus);
	}

	// 5 is log 32
	for (int i = 0; i < 5; i++) {
		int step = 1 << i;
		for (int j = 0; j < 32 - step; j++) {
			v_2[j] += v_2[j + step];
			v_2[j] = util::barrett_reduce_63(v_2[j], plain_modulus);
		}
	}

	//cout << " Evaluate 1 - (a-b)^2. \n" << endl;
	//print32(v_1);

	//cout << " Evaluate r-1((a-b)^2 ) + ...\n" << endl;
	//print32(v_2);

	//cout << " Recall Alice input\n" << endl;
	//print32(pod_a);

	for (size_t i = 0; i < 32; i++) {
		v_3[i] = v_1[i] + v_2[i] * 2 + pod_a[i] + 1;
		v_3[i] = v_3[i] % plain_modulus;
	}

	//cout << " Alice final encrypt: \n" << endl;
	//print32(v_3);

	encode(v_3, p_2);
	encryptor.encrypt_symmetric(p_2, c_4);

	//************************************************************************************
	//*																					*
	//*		Round 4: Using the value of Alice compute to compute a vector				*
	//*					 which contains zero (unique) <=> b > a							*
	//*				 Bob sends it back to Alice (masked by some random number)			*
	//*																					*
	//************************************************************************************

	//print_example_banner("ROUND 4: Bob's turn  ");
	//cout << endl;

	// bob recieved c_4
	//cout << " Bob recieved c_4: \n" << endl;

	// compute correspond random
	pod_rand.resize(32);
	pod_rand_2.resize(32);

	std::copy(pod_rand.begin() + 1, pod_rand.begin() + 32, pod_rand_2.begin());

	// compute 1 - (a-b)^2
	for (int i = 0; i < 32; i++) {
		pod_rand[i] = util::barrett_reduce_63(plain_modulus - pod_rand[i], plain_modulus);
	}

	// 5 is log 32
	for (int i = 0; i < 5; i++) {
		int step = 1 << i;
		for (int j = 0; j < 32 - step; j++) {
			pod_rand_2[j] += pod_rand_2[j + step];
		}
	}

	//cout << " Correspond random. \n" << endl;

	//cout << " Evaluate 1 - (a-b)^2. \n" << endl;
	//print32(pod_rand);

	//cout << " Evaluate r-1((a-b)^2 ) + ...\n" << endl;
	//print32(pod_rand_2);

	//cout << " Print pod_b.\n" << endl;
	//print32(pod_b);


	vector<uint32_t> pod_rand_3(32);

	for (size_t i = 0; i < 32; i++) {
		pod_rand_3[i] = pod_rand[i] + pod_rand_2[i] * 2 + pod_b[i];
		pod_rand_3[i] = pod_rand_3[i] % plain_modulus;
	}

	//cout << " Print pod_rand_3.\n" << endl;
	//print32(pod_rand_3);

	encode(pod_rand_3, p_3);

	evaluator.sub_plain_inplace(c_4, p_3);
	//cout << " Contains zero <=> a < b. \n" << endl;
	//cipher_info(c_4, decryptor);
	//cout << " Multiply a non-zero random polynomial.\n" << endl;

	pod_rand.resize(32);
	uniform_poly_nz(&pod_rand[0], 32, plain_modulus);
	encode(pod_rand, plain_rand);
	//cout << " The random is..." << endl;
	//print32(pod_rand);
	evaluator.multiply_plain_inplace(c_4, plain_rand);

	//cout << " Multiply random." << endl;
	//cipher_info(c_4, decryptor);

	uniform_poly(&pod_rand[0], 32, plain_modulus);
	encode(pod_rand, plain_rand);

	evaluator.add_plain_inplace(c_4, plain_rand);
	//cout << " Mask it by adding random (plain_rand)." << endl;

	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_4, c_zero);
	//cipher_info(c_4, decryptor);

	//************************************************************************************
	//*																					*
	//*		Round 5: Alice transform it into polynomail mode							*
	//*					 which is for Bob to permute									*
	//*																					*
	//************************************************************************************

	//print_example_banner("ROUND 5: Alice's turn");
	//cout << endl;

	// Alice recieved masking c_4
	//cout << " Alice recieved c_4 and decrypt. " << endl;
	decryptor.decrypt(c_4, p_4);
	decode(p_4, v_4);
	//print32(v_4);


	//cout << " Put them into time domain. " << endl;
	//cout << " p_5 <- decode(Dec(c_4)" << endl;
	//cout << " c_5 <- Enc(p_5)" << endl;
	p_5.resize(32);
	for (size_t i = 0; i < 32; i++) {
		p_5[i] = v_4[i];
	}
	encryptor.encrypt_symmetric(p_5, c_5);

	//************************************************************************************
	//*																					*
	//*		Round 6: Bob uses this to random permute and sends 							*
	//*					 it back to Alice												*
	//*																					*
	//************************************************************************************

	//print_example_banner("ROUND 6: Bob's turn  ");
	//cout << endl;

	// Sends it to Bob
	//cout << " Add non zero random at [32, 1024), shuffle then send it back to Alice." << endl;
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
	//cout << " Random shift " << rand_index << endl;
	plain_shift[rand_index] = 1;
	evaluator.multiply_plain_inplace(c_5, plain_shift);

	encryptor.encrypt_zero(c_zero);
	evaluator.add_inplace(c_5, c_zero);
	//cipher_info(c_5, decryptor);


	//************************************************************************************
	//*																					*
	//*		Final: Decrypt and get the result				 							*
	//*																					*
	//************************************************************************************

	//print_example_banner("Final  : Alice decrypt and publish the result");
	//cout << endl;

	// Sends it back to Alice
	//cout << " Final result: " << endl;
	decryptor.decrypt(c_5, p_6);
	uint64_t zero_count = 0;
	for (size_t i = 0; i < p_6.coeff_count(); i++) {
		if (p_6[i] == 0) {
			zero_count++;
		}
	}
	zero_count += (1024 - int(p_6.coeff_count()));

	//cout << " zero count: " << zero_count << "   (notice zero count is 1 if b > a, and is 0 if a >= b)" << endl;
	//cout << endl;

	if (zero_count == 0) {
		if (val_a >= val_b) {
			// cout << " Correct..." << endl;
		}
		else {
			cout << val_a << " " << val_b << endl;
			cout << " Wrong..." << endl;
			system("pause");
		}
	}
	else if (zero_count == 1) {
		if (val_a < val_b) {
			// cout << " Correct..." << endl;
		}
		else {
			cout << val_a << " " << val_b << endl;
			cout << " Wrong..." << endl;
			system("pause");

		}
	}
	else {
		cout << " bug?" << endl;
		system("pause");

	}
}
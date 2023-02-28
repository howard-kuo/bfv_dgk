#pragma once
#include <iostream>
#include <iomanip>
#include <vector>
#include "seal/seal.h"
#include "encryption_schemes.h"
#include "info.h"
#include "ntt.h"
#include "random_generator.h"
#include "setparms.h"


namespace dgk_ordinary
{
	using namespace std;
	using namespace seal;

	class Alice
	{
	public:
		Alice(shared_ptr<SEALContext> context, PublicKey& pk, SecretKey& sk, vector<Ciphertext>& ciphertexts, uint32_t val_a) :
			shared_ciphertexts(ciphertexts),
			shared_pk(pk),
			encryptor(context, sk),
			decryptor(context, sk),
			val(val_a)
		{
			
		}
		vector<Ciphertext>& shared_ciphertexts;
		PublicKey& shared_pk;
		Encryptor encryptor;
		Decryptor decryptor;
		uint32_t val;
		bool is_a_bigger_than_b;
	};

	class Bob
	{
	public:
		Bob(shared_ptr<SEALContext> ct, PublicKey& pk, vector<Ciphertext>& ciphertexts, uint32_t val_b) :
			shared_ciphertexts(ciphertexts),
			shared_pk(pk),
			val(val_b),
			context(ct)
		{
			auto& context_data = *ct->key_context_data();
			coeff_modulus = context_data.parms().coeff_modulus()[0].value();
		}
		shared_ptr<SEALContext> context;
		vector<Ciphertext>& shared_ciphertexts;
		PublicKey& shared_pk;
		uint32_t val;
		uint64_t coeff_modulus;
	};

	void flip(Ciphertext& encrypted, uint64_t coeff_modulus) {
		uint64_t one = coeff_modulus + 1;

		for (size_t i = 0; i < 1024; i++) {
			encrypted.data(0)[i] = one - encrypted.data(0)[i];
			encrypted.data(1)[i] = one - encrypted.data(1)[i];
		}
	}

	void shift(Ciphertext& encrypted, int shift_count, uint64_t coeff_modulus) {
		if (shift_count == 0)
			return;
		
		vector<uint64_t> tmp(2048);

		for (size_t i = 0; i < 1024 - shift_count; i++) {
			tmp[i + shift_count] = encrypted.data(0)[i];
			tmp[i + shift_count + 1024] = encrypted.data(1)[i];
		}
		for (size_t i = 1024 - shift_count; i < 1024; i++) {
			tmp[i + shift_count - 1024] = coeff_modulus - encrypted.data(0)[i];
			tmp[i + shift_count] = coeff_modulus - encrypted.data(1)[i];
		}

		for (size_t i = 0; i < 1024; i++) {
			encrypted.data(0)[i] = tmp[i];
			encrypted.data(1)[i] = tmp[i + 1024];
		}
	}
	void mul_scalar(Ciphertext& encrypted, uint64_t scalar, SmallModulus modulus) {
		for (size_t i = 0; i < 1024; i++) {
			encrypted.data(0)[i] *= scalar;
			encrypted.data(0)[i] = util::barrett_reduce_63(encrypted.data(0)[i], modulus);
			encrypted.data(1)[i] *= scalar;
			encrypted.data(1)[i] = util::barrett_reduce_63(encrypted.data(1)[i], modulus);
		}
	}

	void round_1(Alice& alice) {
		/**
		 * Encrypt any thing and sends it to Bob
		 */
		Plaintext plain(1);
		Ciphertext encrypted;
		alice.shared_ciphertexts.clear();

		for (size_t i = 0; i < 32; i++) {
			plain[0] = (alice.val >> i) & 0x01;
			alice.encryptor.encrypt_symmetric(plain, encrypted);
			alice.shared_ciphertexts.push_back(encrypted);
		}
		alice.encryptor.encrypt_zero_symmetric(encrypted);
		alice.shared_ciphertexts.push_back(encrypted);
	}

	void round_2(Bob& bob, Decryptor &decryptor) {

		/**
		 * Compute non zero vector in encryption domain
		 */
		Encryptor encryptor(bob.context, bob.shared_pk);
		Evaluator evaluator(bob.context);

		vector<bool> bits_of_b(32);
		for (size_t i = 0; i < 32; i++) {
			bits_of_b[i] = (bob.val >> i) & 0x01;
		}
		
		auto vec_ciphertexts(bob.shared_ciphertexts);
		Plaintext plain(1);

		// compute a - b
		for (size_t i = 0; i < 32; i++) {
			plain[0] = bits_of_b[i];
			evaluator.sub_plain_inplace(vec_ciphertexts[i], plain);
		}

		Ciphertext sum_of_xor(bob.shared_ciphertexts[32]);
		plain[0] = 1;
		evaluator.add_plain_inplace(sum_of_xor, plain);

		for (size_t i = 0; i < 32; i++) {
			evaluator.add_inplace(vec_ciphertexts[31 - i], sum_of_xor);
			if (bits_of_b[31 - i] == 1) {
				evaluator.add_plain_inplace(sum_of_xor, plain);
				evaluator.sub_inplace(sum_of_xor, bob.shared_ciphertexts[31 - i]);
			}
			else {
				evaluator.add_inplace(sum_of_xor, bob.shared_ciphertexts[31 - i]);
			}
		}

		/**
		 * Multiply random and random shifting
		 */

		auto rng = BlakePRNGFactory().create();
		vector<uint64_t> rand_vec(32);

		random_generator::uniform32_nz(&rand_vec[0], 32, rng, SmallModulus(193));
		SmallModulus modulus(bob.coeff_modulus);

		uint64_t u;
		random_generator::uniform32(&u, 1, rng, SmallModulus(32));

		for (size_t i = 0; i < 32; i++) {
			
			mul_scalar(vec_ciphertexts[i], rand_vec[i], modulus);
			shift(vec_ciphertexts[i], (i + u) % 32, bob.coeff_modulus);
		}

		bob.shared_ciphertexts.resize(1);
		evaluator.add_many(vec_ciphertexts, bob.shared_ciphertexts[0]);

		Ciphertext encrypted_zero;
		encryptor.encrypt_zero(encrypted_zero);
		evaluator.add_inplace(bob.shared_ciphertexts[0], encrypted_zero);
	}

	void round_final(Alice& alice) {
		Plaintext plain;
		alice.decryptor.decrypt(alice.shared_ciphertexts[0], plain);
		uint64_t nz_count = 0;
		size_t i = 0;
		while (i < plain.coeff_count()) {
			if (plain[i]) {
				nz_count++;
			}
			i++;
		}
		/*
		if (nz_count == 32) {
			alice.is_a_bigger_than_b = true;
		}
		else if (nz_count == 31) {
			alice.is_a_bigger_than_b = false;
		}
		else {
			cout << "error, nz count is " << nz_count << endl;
			getchar();
		}
		*/
	}

	void protocol(uint64_t val_a = 11, uint64_t val_b = 17)
	{
		auto context = SEALContext::Create(setparms(1024, 193));
		vector<Ciphertext> ciphers;
		KeyGenerator keygen(context);
		PublicKey pk = keygen.public_key();
		SecretKey sk = keygen.secret_key();

		Alice alice(context, pk, sk, ciphers, val_a);
		Bob bob(context, pk, ciphers, val_b);

		round_1(alice);
		round_2(bob, alice.decryptor);
		round_final(alice);

		if (alice.is_a_bigger_than_b != (alice.val >= bob.val)) {
			cout << "answer is wrong." << endl;
			cout << alice.val << " " << bob.val << endl;
			cout << "our answer: " << alice.is_a_bigger_than_b << endl;
			getchar();
		}
	}
	void protocol(std::shared_ptr<SEALContext> context, uint64_t val_a = 11, uint64_t val_b = 17)
	{
		vector<Ciphertext> ciphers;
		KeyGenerator keygen(context);
		PublicKey pk = keygen.public_key();
		SecretKey sk = keygen.secret_key();

		Alice alice(context, pk, sk, ciphers, val_a);
		Bob bob(context, pk, ciphers, val_b);

		round_1(alice);
		round_2(bob, alice.decryptor);
		round_final(alice);
		/*
		if (alice.is_a_bigger_than_b != (alice.val >= bob.val)) {
			cout << "answer is wrong." << endl;
			cout << alice.val << " " << bob.val << endl;
			cout << "our answer: " << alice.is_a_bigger_than_b << endl;
			getchar();
		}
		*/
	}
	void protocol(Alice& alice, Bob& bob)
	{
		

		round_1(alice);
		round_2(bob, alice.decryptor);
		round_final(alice);
		/*
		if (alice.is_a_bigger_than_b != (alice.val >= bob.val)) {
			cout << "answer is wrong." << endl;
			cout << alice.val << " " << bob.val << endl;
			cout << "our answer: " << alice.is_a_bigger_than_b << endl;
			getchar();
		}
		*/
	}
}
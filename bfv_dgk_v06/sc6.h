#pragma once
#include "seal/seal.h"
#include "encryption_schemes.h"
#include "info.h"
#include "ntt.h"
#include "random_generator.h"
#include "setparms.h"

namespace sc6
{
	using namespace std;
	using namespace seal;


	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	class Alice {
	public:
		Alice(shared_ptr<SEALContext> context, Ciphertext &cipher, 
			int64_t val_a = 17) :
			keygen(context),
			encryptor(context, keygen.secret_key()),
			decryptor(context, keygen.secret_key()),
			shared_cipher(cipher),
			val(val_a),
			modulus(context->key_context_data()->parms().plain_modulus())
		{
			rng = BlakePRNGFactory().create();
			pool = MemoryManager::GetPool();
		};
		PublicKey get_pk() {
			return keygen.public_key();
		}
		KeyGeneratorClass keygen;
		EncryptorClass encryptor;
		DecryptorClass decryptor;
		Ciphertext& shared_cipher;
		uint64_t val;
		Plaintext plain_a;
		vector<uint32_t> pod_a;
		SmallModulus modulus;
		shared_ptr<UniformRandomGenerator> rng;
		MemoryPoolHandle pool;
		bool is_a_bigger_than_b;
	};

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	class Bob {
	public:
		Bob(shared_ptr<SEALContext> context, PublicKey pk, Ciphertext& cipher, uint64_t val_b = 11) :
			encryptor(context, pk),
			evaluator(context),
			shared_cipher(cipher),
			val(val_b),
			pod_rand(32),
			modulus(context->key_context_data()->parms().plain_modulus())
		{
			rng = BlakePRNGFactory().create();
			pool = MemoryManager::GetPool();
		}
		EncryptorClass encryptor;
		EvaluatorClass evaluator;
		Ciphertext& shared_cipher;
		uint64_t val;
		Plaintext plain_b;
		vector<uint32_t> pod_b;
		vector<uint32_t> pod_rand;
		SmallModulus modulus;
		shared_ptr<UniformRandomGenerator> rng;
		MemoryPoolHandle pool;
	};

	void protocol_example(size_t val_a = 17, size_t val_b = 11);
	void protocol(size_t val_a = 17, size_t val_b = 11);
	void protocol(shared_ptr<SEALContext> context, size_t val_a = 17, size_t val_b = 11);
	
	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_1(Alice<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& alice);

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_2(Bob<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& bob);

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_3(Alice<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& alice);

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_4(Bob<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& bob);

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_5(Alice<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& alice);

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_6(Bob<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& bob);

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_final(Alice<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& alice);


	/**
		Provide 32-bits secure comparison protocol
	*/
	template <typename T>
	void i_to_vec32(uint64_t val, vector<T>& vec) {
		vec.resize(32);
		for (size_t i = 0; i < 32; i++) {
			vec[i] = (val >> i) & 0x01;
		}
	}
	template <typename T>
	vector<T> i_to_vec32(uint64_t val) {
		vector<T> vec(32);
		for (size_t i = 0; i < 32; i++) {
			vec[i] = (val >> i) & 0x01;
		}
		return vec;
	}
}
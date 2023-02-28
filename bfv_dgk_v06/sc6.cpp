#include "sc6.h"

namespace sc6
{
	void protocol_example(size_t val_a, size_t val_b)
	{
		size_t degree = 1024;
		SmallModulus plain_modulus = 193;
		Ciphertext shared_cipher;

		auto parms = setparms(1024, plain_modulus);
		auto context = SEALContext::Create(parms);

		info::print_banner("6 Round Secure Comparison Protocol");
		info::print_parms(context);

		/**
		 * Round 1
		 *
		 * Alice generate public key and secret key,
		 * sends public key and encrypted val_a to Bob
		 */

		Alice<KeyGenerator, Encryptor, Evaluator, Decryptor> 
			alice(context, shared_cipher, val_a);

		info::print_banner("round 1");
		info::print_banner(" Alice sends c_a <- Enc(a) to Bob.");
		cout << "\n value of a: " << alice.val << "\n" << endl;

		round_1(alice);

		cout << " Alice sends c1 to Bob." << endl;
		cout << "    which is encrypted of val_a." << endl;
		info::print_cipher_packed(alice.shared_cipher, alice.decryptor, 1024);

		/**
		 * Round 2
		 *
		 * Bob recieved encrypted val_a and public key,
		 * computes z = (val_a - val_b)^2 in encryption domain.
		 *
		 * Finally, Bob sends Enc(z + some_random_1) to Alice.
		 *
		 * Notice both val_a, val_b are in batching mode, so 
		 * ((val_a - val_b)^2)_i = ((val_a)_i - (val_b)_i)^2
		 * 
		 */

		Bob<KeyGenerator, Encryptor, Evaluator, Decryptor> 
			bob(context, alice.get_pk(), shared_cipher, val_b);

		info::print_banner("round 2");
		info::print_banner("Bob computes Enc((a-b)^2+r) and sends it to Alice.");
		cout << "\n Value of b: " << bob.val << "\n" << endl;

		round_2(bob);

		cout << " Bob's input: " << endl;
		info::print_vec32(bob.pod_b);
		cout << " Bob sends c2 to Alice." << endl;
		cout << "    which is encrypted of (a-b)^2" << endl;
		info::print_cipher_packed(alice.shared_cipher, alice.decryptor, 1024);

		/**
		 * Round 3
		 *
		 * Alice compute Enc(non_zero_except_msb + val_a + some_random_1),
		 * and sends it back to Bob.
		 *
		 */

		info::print_banner("round 3");
		info::print_banner
		(" Alice computes c_3 <- Enc(almost_nz + a + 1).");
		cout << "\n (the only one non zero element of almost_nz is msb.)" << endl;
		cout << "\n Alice recieved c2." << endl;

		round_3(alice);

		cout << " Alice sends c3 to Bob." << endl;
		info::print_cipher_packed(alice.shared_cipher, alice.decryptor, 1024);


		/**
		 * Round 4
		 *
		 * Bob compute z = non_zero_except_msb + a - b in encryption domain,
		 * notice z containts zero iff b > a.
		 * Bob sends Enc(r * z + another_random_2) to Alice
		 *
		 */

		info::print_banner("round 4");
		info::print_banner("Bob computed r * (c_3 - b).");

		round_4(bob);

		cout << "\n Bob sends c4 to Alice." << endl;
		info::print_cipher_packed(alice.shared_cipher, alice.decryptor, 1024);

		/**
		 * Round 5
		 *
		 * Alice recieved r * z + another_random_2,
		 * Put it into polynomial mode (which is 
		 *     sum_i (r * z + another_random_2)_i X^i 
		 * )
		 * and sends it back to Bob.
		 *
		 */

		info::print_banner("round 5");
		info::print_banner("Alice put the vector into polynomial term.");
		cout << "\n Alice recieve c4." << endl;

		round_5(alice);

		info::print_cipher_some(alice.shared_cipher, alice.decryptor, 32);
		cout << " Alice sends c5 to Bob." << endl;

		/**
		 * Round 6
		 * 
		 * Bob shifting it by multiplying X^u and sends it back to Alice.
		 *
		 */

		info::print_banner("round 6");
		info::print_banner("Bob recieved c5. Random shifting and sends it back.");

		round_6(bob);

		cout << "\n Bob sends c6 to Alice." << endl;

		/**
		 * Round Final
		 *
		 * Decrypt and check if there is a zero in it.
		 *
		 */

		round_final(alice);

		cout << setw(18) << "answer: ";
		if (alice.is_a_bigger_than_b) {
			cout << "a >= b" << endl;
		}
		else {
			cout << "a < b" << endl;
		}

		cout << setw(18) << "true answer: ";
		cout << string((val_a < val_b) ? "a < b" : "a >= b") << endl;
	}

	void protocol(size_t val_a, size_t val_b)
	{
		// What we do in each round is written in 
		//		protocol_example

		size_t degree = 1024;
		SmallModulus plain_modulus = 193;
		Ciphertext shared_cipher;

		auto parms = setparms(1024, plain_modulus);
		auto context = SEALContext::Create(parms);

		protocol(context, val_a, val_b);
	}

	void protocol(shared_ptr<SEALContext> context, size_t val_a, size_t val_b)
	{
		Ciphertext shared_cipher;

		Alice<KeyGenerator, Encryptor_supervisor, Evaluator_supervisor, Decryptor_supervisor>
			alice (context, shared_cipher, val_a);

		round_1(alice);


		Bob<KeyGenerator, Encryptor_supervisor, Evaluator_supervisor, Decryptor>
			bob(context, alice.get_pk(), shared_cipher, val_b);

		round_2(bob);

		round_3(alice);

		round_4(bob);

		round_5(alice);

		round_6(bob);

		round_final(alice);

		if (alice.is_a_bigger_than_b != (val_a >= val_b)) {
			cout << "answer is wrong." << endl;
			cout << val_a << " " << val_b << endl;
			cout << "our answer: " << alice.is_a_bigger_than_b << endl;
			getchar();
		}

		
	}
	void protocol(Alice<KeyGenerator, Encryptor_supervisor, Evaluator_supervisor, Decryptor_supervisor>& alice,
		Bob<KeyGenerator, Encryptor_supervisor, Evaluator_supervisor, Decryptor>& bob)
	{

		round_1(alice);


		round_2(bob);

		round_3(alice);

		round_4(bob);

		round_5(alice);

		round_6(bob);

		round_final(alice);



	}
	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_1(Alice<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>&alice) {
		i_to_vec32(alice.val, alice.pod_a);
		ntt193::nega_encode(alice.pod_a, alice.plain_a, 1024);
		alice.encryptor.encrypt_symmetric(alice.plain_a, alice.shared_cipher, alice.pool);
	}

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_2(Bob<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& bob) {
		i_to_vec32(bob.val, bob.pod_b);
		ntt193::nega_encode(bob.pod_b, bob.plain_b, 1024);
		Ciphertext cipher_tmp;
		bob.evaluator.multiply_plain(bob.shared_cipher, bob.plain_b, cipher_tmp, bob.pool);
		
		// compute a + b - 2*a*b
		bob.evaluator.add_plain_inplace(bob.shared_cipher, bob.plain_b);
		bob.evaluator.sub_inplace(bob.shared_cipher, cipher_tmp);
		bob.evaluator.sub_inplace(bob.shared_cipher, cipher_tmp);

		/**
		 * Adding the random number
		 */
		random_generator::uniform32(&bob.pod_rand[0], 32, bob.rng, bob.modulus);
		Plaintext plain_rand;
		ntt193::nega_encode(bob.pod_rand, plain_rand, 1024);
		bob.evaluator.add_plain_inplace(bob.shared_cipher, plain_rand);

		/**
		 * Adding encrypted zero
		 */
		Ciphertext encrypted_zero;
		bob.encryptor.encrypt_zero(encrypted_zero, bob.pool);
		bob.evaluator.add_inplace(bob.shared_cipher, encrypted_zero);
	}  

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_3(Alice<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& alice) {

		Plaintext plain_tmp;
		vector<uint32_t> vec_tmp;
		alice.decryptor.decrypt(alice.shared_cipher, plain_tmp);

		ntt193::nega_decode(plain_tmp, vec_tmp, 1024);
		vector<uint32_t> vec_tmp2(vec_tmp);

		for (size_t i = 0; i < 31; i++) {
			//cout << i << "\t" << vec_tmp[31 - i] << endl;
			vec_tmp[30 - i] += vec_tmp[31 - i];
			vec_tmp[30 - i] %= 193;
		}
		for (size_t i = 0; i < 32; i++) {
			vec_tmp[i] += alice.pod_a[i] + 194 - vec_tmp2[i];
			vec_tmp[i] %= 193;
		}
		ntt193::nega_encode(vec_tmp, plain_tmp, 1024);
		alice.encryptor.encrypt_symmetric(plain_tmp, alice.shared_cipher, alice.pool);
	}

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_4(Bob<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& bob) {
		/**
		 * Compute the correspond random
		 */
		vector<uint32_t> vec_rand(bob.pod_rand);
		for (size_t i = 0; i < 31; i++) {
			//cout << i << "\t" << vec_tmp[31 - i] << endl;
			bob.pod_rand[30 - i] += bob.pod_rand[31 - i];
			bob.pod_rand[30 - i] %= 193;
		}
		for (size_t i = 0; i < 32; i++) {
			bob.pod_rand[i] += 193 - vec_rand[i];
			bob.pod_rand[i] %= 193;
		}
		Plaintext plain_rand;
		ntt193::nega_encode(bob.pod_rand, plain_rand, 1024);
		bob.evaluator.sub_plain_inplace(bob.shared_cipher, plain_rand);
	
		/**
		 * Compute almost_nz + a - b in encryption domain
		 */
		bob.evaluator.sub_plain_inplace(bob.shared_cipher, bob.plain_b);
		random_generator::uniform32_nz(&bob.pod_rand[0], 32, bob.rng, bob.modulus);
		Plaintext plain_rand2;
		ntt193::nega_encode(bob.pod_rand, plain_rand2, 1024);
		bob.evaluator.multiply_plain_inplace(bob.shared_cipher, plain_rand2, bob.pool);


		/**
		 *	Adding random number plaintext
		 */

		random_generator::uniform32(&bob.pod_rand[0], 32, bob.rng, bob.modulus);
		Plaintext plain_rand3;
		ntt193::nega_encode(bob.pod_rand, plain_rand3, 1024);
		bob.evaluator.add_plain_inplace(bob.shared_cipher, plain_rand3);

		/**
		 * Adding encrypted zero
		 */
		Ciphertext encrypted_zero;
	
		bob.encryptor.encrypt_zero(encrypted_zero, bob.pool);
		bob.evaluator.add_inplace(bob.shared_cipher, encrypted_zero);
	}

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_5(Alice<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& alice) {
		Plaintext plain_tmp;
		Plaintext plain_tmp2;
		vector<uint32_t> vec_tmp;
		alice.decryptor.decrypt(alice.shared_cipher, plain_tmp);
		ntt193::nega_decode(plain_tmp, vec_tmp, 1024);
		plain_tmp2.resize(32);
		for (size_t i = 0; i < 32; i++) {
			plain_tmp2[i] = vec_tmp[i];
		}
		alice.encryptor.encrypt_symmetric(plain_tmp2, alice.shared_cipher, alice.pool);
	}


	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_6(Bob<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& bob) {
		/**
		 *	Subtract the correspond random number
		 */
		Plaintext plain_rand(32);
		for (size_t i = 0; i < 32; i++)
			plain_rand[i] = bob.pod_rand[i];
		bob.evaluator.sub_plain_inplace(bob.shared_cipher, plain_rand);

		Plaintext plain_tmp(1024);

		random_generator::uniform32_nz
		(&plain_tmp[32], 1024 - 32, bob.rng, bob.modulus);

		bob.evaluator.add_plain_inplace(bob.shared_cipher, plain_tmp);
		Plaintext plain_tmp2(1024);
		size_t nshift = random_generator::get(bob.rng) % 1024;
		plain_tmp2[nshift] = 1;
		bob.evaluator.multiply_plain_inplace(bob.shared_cipher, plain_tmp2, bob.pool);

		/**
		 * Adding encrypted zero
		 */
		Ciphertext encrypted_zero;
		bob.encryptor.encrypt_zero(encrypted_zero, bob.pool);
		bob.evaluator.add_inplace(bob.shared_cipher, encrypted_zero);
	}

	template <typename KeyGeneratorClass, typename EncryptorClass, typename EvaluatorClass, typename DecryptorClass>
	void round_final(Alice<KeyGeneratorClass, EncryptorClass, EvaluatorClass, DecryptorClass>& alice) {
		Plaintext result;
		alice.decryptor.decrypt(alice.shared_cipher, result);
		size_t nz_count = 0;
		for (size_t i = 0; i < result.coeff_count(); i++) {
			if (result[i] != 0)
				nz_count++;
		}

		if (nz_count == 1024) {
			alice.is_a_bigger_than_b = true;
		}
		else if (nz_count == 1023) {
			alice.is_a_bigger_than_b = false;
		}
		else {
			throw logic_error("zero count >= 2");
		}
	}

}
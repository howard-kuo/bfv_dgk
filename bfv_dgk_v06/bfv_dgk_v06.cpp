#include <iostream>
#include <chrono>
#include "encryption_schemes.h"
#include "info.h"
#include "ntt.h"
#include "ordinary_dgk.h"
#include "setparms.h"
#include "sc6.h"
#include "ntt.cpp"
// #include "random_generator.cpp"

using namespace std;
using namespace seal;
  


int main()
{
	string a;
	chrono::high_resolution_clock::time_point time_start, time_end;
	chrono::microseconds time_diff;
	size_t times = 1000;

	size_t degree = 1024;
	SmallModulus plain_modulus = 193;

	auto parms = setparms(degree, plain_modulus);
	auto context = SEALContext::Create(parms);

	KeyGenerator keygen(context);

	Encryptor encryptor(context, keygen.public_key(), keygen.secret_key());
	Evaluator evaluator(context);
	Decryptor decryptor(context, keygen.secret_key());

	Plaintext plain;
	Ciphertext encrypted;

	
	auto& context_data = *context->key_context_data();
	
	cout << "Running..." << endl;

	
	vector<Ciphertext> ciphers;
	PublicKey pk = keygen.public_key();
	SecretKey sk = keygen.secret_key();
	Ciphertext shared_cipher;

	dgk_ordinary::Alice alice(context, pk, sk, ciphers, 11);
	dgk_ordinary::Bob bob(context, pk, ciphers, 17);
	/*
	sc6::Alice<KeyGenerator, Encryptor_supervisor, Evaluator_supervisor, Decryptor_supervisor>
		alice2(context, shared_cipher, 14);
	sc6::Bob<KeyGenerator, Encryptor_supervisor, Evaluator_supervisor, Decryptor>
		bob2(context, alice.get_pk(), shared_cipher, 22);
	*/

	for(size_t j = 0; j < 3; j++){

	time_start = chrono::high_resolution_clock::now();
	for (size_t i = 0; i < times; i++) {
		//cout << i << " iters" << endl;
		//dgk_ordinary::protocol(alice, bob);
		sc6::protocol(context, 131, 166);
		//getchar();
		//random_generator::uniform32(&vec_b[0], 3 * 1024 * 0, rng_b, modulus);
	}

	time_end = chrono::high_resolution_clock::now();
	time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
	
	cout << endl;
	cout << "   " << times << " has been done." << endl;
	cout << setw(10)  << "Done [" << setw(10)
		<< time_diff.count() << " microseconds]" << endl;
	
	//Encryptor_supervisor::print_info();
	//Evaluator_supervisor::print_info();
	//Decryptor_supervisor::print_info();
	//random_generator::Record::print_info();
	}
}


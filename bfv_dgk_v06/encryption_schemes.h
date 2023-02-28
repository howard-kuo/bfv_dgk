#pragma once
#include <iostream>
#include <iomanip>
#include <chrono>
#include "info.h"
#include "seal/seal.h"

class Encryptor_supervisor
{
public:
	Encryptor_supervisor(std::shared_ptr<seal::SEALContext> context, seal::PublicKey pk) :
		encryptor_(context, pk)
	{

	}
	Encryptor_supervisor(std::shared_ptr<seal::SEALContext> context, seal::SecretKey sk) :
		encryptor_(context, sk)
	{

	}
	Encryptor_supervisor(std::shared_ptr<seal::SEALContext> context, seal::PublicKey pk, seal::SecretKey sk) :
		encryptor_(context, pk, sk)
	{

	}
	inline void encrypt_zero(seal::Ciphertext& cipher, 
		seal::MemoryPoolHandle pool = MemoryManager::GetPool()
	) {
		n_enc_zero++;
		auto time_start = std::chrono::high_resolution_clock::now();
		encryptor_.encrypt_zero(cipher, pool);
		auto time_end = std::chrono::high_resolution_clock::now();
		time_diff_enc_zero += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
	}
	inline void encrypt_symmetric(seal::Plaintext &plain, seal::Ciphertext& cipher,
		seal::MemoryPoolHandle pool = MemoryManager::GetPool()) {

		n_enc_sym++;
		auto time_start = std::chrono::high_resolution_clock::now();
		encryptor_.encrypt_symmetric(plain, cipher, pool);
		auto time_end = std::chrono::high_resolution_clock::now();
		time_diff_enc_sym += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
	}
	inline void encrypt(seal::Plaintext& plain, seal::Ciphertext& cipher,
		seal::MemoryPoolHandle pool = MemoryManager::GetPool()) {

		n_enc++;
		auto time_start = std::chrono::high_resolution_clock::now();
		encryptor_.encrypt(plain, cipher, pool);
		auto time_end = std::chrono::high_resolution_clock::now();
		time_diff_enc += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
	}
	static void print_info() {
		info::print_banner("Encryptor Performance");
		std::cout << "/" << std::endl;
		std::cout << "|  Total execution time [" << std::setw(10)
			<< time_diff_enc.count() + time_diff_enc_zero.count() + time_diff_enc_sym.count() 
			<< " microseconds]\n|" << std::endl;
		std::cout << "|  secret key encryption: " << std::endl;
		std::cout << "|     enc_sym has been called " << n_enc_sym << " times" << std::endl;
		std::cout << "|     which cost [" << std::setw(10) << time_diff_enc_sym.count()
			<< " microseconds]\n|" << std::endl;
		std::cout << "|  public key encryption: " << std::endl;
		std::cout << "|     enc_zero has been called " << n_enc_zero << " times" << std::endl;
		std::cout << "|     which cost [" << std::setw(10) << time_diff_enc_zero.count()
			<< " microseconds]" << std::endl;
		std::cout << "\\" << std::endl;
		std::cout << std::endl;
	}
private:
	seal::Encryptor encryptor_;
	static std::chrono::microseconds time_diff_enc_zero, time_diff_enc_sym, time_diff_enc;
	static int n_enc_zero, n_enc_sym, n_enc;
};

class Evaluator_supervisor
{
public:
	Evaluator_supervisor(std::shared_ptr<seal::SEALContext> context) : evaluator_(context)
	{

	}
	inline void multiply_plain_inplace(seal::Ciphertext& cipher, const seal::Plaintext& plain,
		seal::MemoryPoolHandle pool = MemoryManager::GetPool()) {

		n_mul++;
		auto time_start = std::chrono::high_resolution_clock::now();
		evaluator_.multiply_plain_inplace(cipher, plain, pool);
		auto time_end = std::chrono::high_resolution_clock::now();
		time_diff_mul += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

	}

	inline void multiply_plain(const seal::Ciphertext& cipher, const seal::Plaintext& plain,
		seal::Ciphertext& destination, seal::MemoryPoolHandle pool = MemoryManager::GetPool()) {

		n_mul++;
		auto time_start = std::chrono::high_resolution_clock::now();
		evaluator_.multiply_plain(cipher, plain, destination, pool);
		auto time_end = std::chrono::high_resolution_clock::now();
		time_diff_mul += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

	}

	inline void add_plain_inplace(seal::Ciphertext& cipher, const seal::Plaintext& plain) {

		n_add++;
		auto time_start = std::chrono::high_resolution_clock::now();
		evaluator_.add_plain_inplace(cipher, plain);
		auto time_end = std::chrono::high_resolution_clock::now();
		time_diff_add += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

	}
	inline void sub_plain_inplace(seal::Ciphertext& cipher, const seal::Plaintext& plain) {
		n_add++;
		auto time_start = std::chrono::high_resolution_clock::now();
		evaluator_.sub_plain_inplace(cipher, plain);
		auto time_end = std::chrono::high_resolution_clock::now();
		time_diff_add += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

	}
	inline void add_inplace(seal::Ciphertext& destination, const seal::Ciphertext& cipher) {
		n_add++;
		auto time_start = std::chrono::high_resolution_clock::now();
		evaluator_.add_inplace(destination, cipher);
		auto time_end = std::chrono::high_resolution_clock::now();
		time_diff_add += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

	}
	inline void sub_inplace(seal::Ciphertext& destination, const seal::Ciphertext& cipher) {
		n_add++;
		auto time_start = std::chrono::high_resolution_clock::now();
		evaluator_.sub_inplace(destination, cipher);
		auto time_end = std::chrono::high_resolution_clock::now();
		time_diff_add += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

	}

	static void print_info() {
		info::print_banner("Evaluator Performance");
		std::cout << "/" << std::endl;
		std::cout << "|  Total execution time [" << std::setw(10)
			<< time_diff_add.count() + time_diff_mul.count()
			<< " microseconds]\n|" << std::endl;
		std::cout << "|  addition has been called " << n_add << " times" << std::endl;
		std::cout << "|     which cost [" << std::setw(10) << time_diff_add.count()
			<< " microseconds]\n|" << std::endl;
		std::cout << "|  multiplication has been called " << n_mul << " times" << std::endl;
		std::cout << "|     which cost [" << std::setw(10) << time_diff_mul.count()
			<< " microseconds]\n|" << std::endl;
		std::cout << "\\" << std::endl;
		std::cout << std::endl;
	}
private:
	seal::Evaluator evaluator_;
	static std::chrono::microseconds time_diff_add, time_diff_mul;
	static int n_add, n_mul;
};

class Decryptor_supervisor
{
public:
	Decryptor_supervisor(std::shared_ptr<seal::SEALContext> context, seal::SecretKey sk) :
		decryptor_(context, sk)
	{

	}
	void decrypt(const seal::Ciphertext& cipher, seal::Plaintext& destination) {
		n_dec++;
		auto time_start = std::chrono::high_resolution_clock::now();
		decryptor_.decrypt(cipher, destination);
		auto time_end = std::chrono::high_resolution_clock::now();
		time_diff_dec += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

	}
	auto invariant_noise_budget(const seal::Ciphertext& cipher) {
		return decryptor_.invariant_noise_budget(cipher);
	}

	static void print_info() {
		info::print_banner("Decryptor Performance");
		std::cout << "/" << std::endl;
		std::cout << "|  Total execution time [" << std::setw(10)
			<< time_diff_dec.count()
			<< " microseconds]\n|" << std::endl;
		std::cout << "|  dec has been called " << n_dec
			<< " times, " << std::endl;
		std::cout << "|     which costs " << "[" << std::setw(10)
			<< time_diff_dec.count() << " microseconds]\n|" << std::endl;
		std::cout << "\\" << std::endl;
		std::cout << std::endl;
		
	}
private:
	seal::Decryptor decryptor_;
	static std::chrono::microseconds time_diff_dec;
	static int n_dec;
};
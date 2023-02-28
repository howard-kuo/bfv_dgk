#pragma once
#include <iostream>
#include <iomanip>
#include <chrono>
#include "info.h"
#include "seal/seal.h"


namespace random_generator
{
	using namespace std;
	using namespace seal;

	class Record {
	public:
		static chrono::microseconds time_diff_uniform_random;
		static uint64_t sample_count;
		static void print_info() {
			info::print_banner("Random Sampler Performance");
			std::cout << "/" << std::endl;
			std::cout << "|  Total execution time [" << std::setw(10)
				<< time_diff_uniform_random.count() 
				<< " microseconds]" << std::endl;
			// std::cout << "|     " << sample_count << " are sampled." << std::endl;
			std::cout << "\\" << std::endl;
			std::cout << std::endl;
		}
	};

	static uint32_t get(shared_ptr<UniformRandomGenerator> rng) {
		return rng->generate();
	}
	template <typename T>
	void uniform32(T* destination, size_t count, 
		shared_ptr<UniformRandomGenerator> rng,	SmallModulus modulus) {

		Record::sample_count += count;
		auto time_start = std::chrono::high_resolution_clock::now();

		RandomToStandardAdapter engine(rng);
		constexpr uint32_t max_random = static_cast<uint32_t>(0xFFFFFFFFULL);
		uint32_t max_multiple = max_random - util::barrett_reduce_63(max_random, modulus) - 1;
		for (size_t i = 0; i < count; i++)
		{
			// This ensures uniform distribution.
			uint32_t rand;
			do
			{
				rand = engine();
			} while (rand >= max_multiple);
			destination[i] = util::barrett_reduce_63(rand, modulus);
		}
		auto time_end = std::chrono::high_resolution_clock::now();
		Record::time_diff_uniform_random += 
			std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
	}

	template <typename T>
	void uniform32_nz(T* destination, size_t count,
		shared_ptr<UniformRandomGenerator> rng, SmallModulus modulus) {
		SmallModulus modulus_m(modulus.value() - 1);
		uniform32(destination, count, rng, modulus_m);
		for (size_t i = 0; i < count; i++) {
			destination[i] += 1;
		}
	}
}


#pragma once
#include <iostream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

chrono::microseconds rand_diff;

template <typename T>
void uniform_poly(T* destination, size_t coeff_count, size_t modulus, shared_ptr<UniformRandomGenerator> &rng)
{
	chrono::high_resolution_clock::time_point time_start, time_end;
	time_start = chrono::high_resolution_clock::now();


	SmallModulus sm(modulus);

	// Set up source of randomness that produces 32 bit random things.
	// We sample numbers up to 2^63-1 to use barrett_reduce_63
	constexpr uint64_t max_random = static_cast<uint64_t>(0xFFFFFFFFULL);

	uint64_t max_multiple = max_random - util::barrett_reduce_63(max_random, sm) - 1;
	for (size_t i = 0; i < coeff_count; i++)
	{
		// This ensures uniform distribution.
		uint64_t rand;
		do
		{
			rand = rng->generate();
		} while (rand >= max_multiple);
		destination[i] = util::barrett_reduce_63(rand, sm);
	}

	time_end = chrono::high_resolution_clock::now();
	rand_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
}



template <typename T>
void uniform_poly(T* destination, size_t coeff_count, size_t modulus)
{
	chrono::high_resolution_clock::time_point time_start, time_end;
	time_start = chrono::high_resolution_clock::now();

	shared_ptr<UniformRandomGenerator> rng;
	rng = BlakePRNGFactory().create();

	SmallModulus sm(modulus);

	// Set up source of randomness that produces 32 bit random things.
	RandomToStandardAdapter engine(rng);

	// We sample numbers up to 2^63-1 to use barrett_reduce_63
	constexpr uint64_t max_random = static_cast<uint64_t>(0xFFFFFFFFULL);

	uint64_t max_multiple = max_random - util::barrett_reduce_63(max_random, sm) - 1;
	for (size_t i = 0; i < coeff_count; i++)
	{
		// This ensures uniform distribution.
		uint64_t rand;
		do
		{
			rand = engine();
		} while (rand >= max_multiple);
		destination[i] = util::barrett_reduce_63(rand, sm);
	}

	time_end = chrono::high_resolution_clock::now();
	rand_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
}
// 

template <typename T>
void uniform_poly_nz(T* destination, size_t coeff_count, size_t modulus, shared_ptr<UniformRandomGenerator>& rng)
{
	uniform_poly(destination, coeff_count, modulus - 1, rng);
	for (size_t i = 0; i < coeff_count; i++)
		destination[i]++;
}

template <typename T>
void uniform_poly_nz(T* destination, size_t coeff_count, size_t modulus)
{
	uniform_poly(destination, coeff_count, modulus - 1);
	for (size_t i = 0; i < coeff_count; i++)
		destination[i]++;
}

template <typename T>
void uniform_poly32(T* destination, size_t coeff_count, size_t modulus)
{
	shared_ptr<UniformRandomGenerator> rng;
	rng = BlakePRNGFactory().create();

	// Set up source of randomness that produces 32 bit random things.
	RandomToStandardAdapter engine(rng);

	// We sample numbers up to 2^32-1 to use barrett_reduce_63
	constexpr uint64_t max_random = static_cast<uint64_t>(0xFFFFFFFFULL);

	SmallModulus sm(modulus);

	uint32_t max_multiple = max_random - util::barrett_reduce_63(max_random, sm) - 1;
	for (size_t i = 0; i < coeff_count; i++)
	{
		// This ensures uniform distribution.
		uint32_t rand;
		do
		{
			rand = engine();
		} while (rand >= max_multiple);
		destination[i] = util::barrett_reduce_63(rand, sm);
	}


}

template <typename T>
void uniform_poly32_nz(T* destination, size_t coeff_count, size_t modulus)
{
	uniform_poly32(destination, coeff_count, modulus - 1);
	for (size_t i = 0; i < coeff_count; i++)
		destination[i]++;
}
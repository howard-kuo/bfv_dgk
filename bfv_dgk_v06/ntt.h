#pragma once
#include <iostream>
#include <vector>
#include "seal/seal.h"

namespace ntt193
{
	using namespace std;
	/**
		Transform and inverse transform
	*/
	inline unsigned char reverse8(unsigned char b) {
		b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
		b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
		b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
		return b;
	}

	template <typename T>
	void nega_encode(vector<T>& vec, seal::Plaintext& poly, size_t degree);

	template <typename T>
	void nega_decode(seal::Plaintext& poly, vector<T>& vec, size_t degree);

	template <typename T>
	void nega_encode(vector<T>& vec, vector<T>& poly);

	template <typename T>
	void nega_decode(vector<T>& poly, vector<T>& vec);

	template <typename T>
	void transform(vector<T>& poly, vector<T>& vec);

	template <typename T>
	void inverse_transform(vector<T>& vec, vector<T>& poly);


	/**
		NTT table for ntt193
	*/
	constexpr uint32_t PHI = 11;
	constexpr uint32_t PHI_INVERSE = 158;
	constexpr uint32_t BASE = 121;
	constexpr uint32_t INVERSE_OF_64 = 190;
	constexpr uint32_t INVERSE_OF_32 = 187;
	constexpr uint32_t TABLE[33]
	{
		1,      121,    166,    14,
		150,    8,      3,      170,
		112,    42,     64,     24,
		9,      124,    143,    126,
		192,    72,     27,     179,
		43,     185,    190,    23,
		81,     151,    129,    169,
		184,    69,     50,     67,
		1
	};
}

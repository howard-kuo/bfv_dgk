// NTT193_implementation.cpp 

#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cassert>
#include <fstream>
#include <bitset>
#include <chrono>

using namespace std;

namespace ntt193
{
	// 11 has order 64;
	constexpr uint32_t NTT_PHI = 11;
	constexpr uint32_t NTT_PHI_INVERSE = 158;
	constexpr uint32_t NTT_BASE = 121;
	constexpr uint32_t NTT_193_INVERSE_OF_64 = 190;
	constexpr uint32_t NTT_193_INVERSE_OF_32 = 187;
	constexpr uint32_t NTT_TABLE_193[33]
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

	// n = 64
	inline uint32_t Mul(uint32_t& a, uint32_t& b)
	{
		return (a * b) % 193;
	}
	inline uint32_t Add(uint32_t& a, uint32_t& b)
	{
		return (a + b) % 193;
	}
	uint32_t order(uint32_t a)
	{
		if (std::gcd<uint32_t, uint32_t>(a, 193) != 1) {
			return 0;
		}
		uint32_t od = 1;
		uint32_t cur = a;
		while (cur != 1)
		{
			cur = Mul(cur, a);
			od++;
		}
		return od;
	}

	void transform(vector<uint32_t>& a, vector<uint32_t>& A);
	void inverse(vector<uint32_t>& a, vector<uint32_t>& A);
	

	int test()
	{
		chrono::high_resolution_clock::time_point time_start, time_end;
		chrono::microseconds time_diff;
		time_start = chrono::high_resolution_clock::now();
		vector<uint32_t> a(32), A(32);

		a[16] = 1;
		transform(a, A);
		inverse(A, a);
		for (int i = 0; i < 32; i++) {
			cout << "\t" << a[i];
			if (i % 8 == 7)
				cout << endl;
		}

		time_end = chrono::high_resolution_clock::now();
		time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
		cout << "Check..." << endl;
		cout << "   Done [" << time_diff.count() << " microseconds]" << endl;
		return 0;
	}
	inline unsigned char reverse8(unsigned char b) {
		b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
		b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
		b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
		return b;
	}
	void dot_phi(vector<uint32_t>& a) {
		uint32_t cur = 1;
		for (auto& v : a) {
			v = (v * cur) % 193;
			cur = (cur * NTT_PHI) % 193;
		}
	}
	void dot_phi_inverse(vector<uint32_t>& a) {
		uint32_t cur = 1;
		for (auto& v : a) {
			v = (v * cur) % 193;
			cur = (cur * NTT_PHI_INVERSE) % 193;
		}
	}
	chrono::microseconds ntt193_diff;
	void encode(vector<uint32_t>& A, vector<uint32_t>& poly) {
		chrono::high_resolution_clock::time_point time_start, time_end;
		time_start = chrono::high_resolution_clock::now();


		A.resize(32);
		poly.resize(32);
		inverse(A, poly);
		dot_phi_inverse(poly);

		time_end = chrono::high_resolution_clock::now();
		ntt193_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
	}

	void decode(vector<uint32_t>& poly, vector<uint32_t>& A) {
		chrono::high_resolution_clock::time_point time_start, time_end;
		time_start = chrono::high_resolution_clock::now();

		A.resize(32);
		poly.resize(32);
		dot_phi(poly);
		transform(poly, A);

		time_end = chrono::high_resolution_clock::now();
		ntt193_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
	}

	void transform(vector<uint32_t>& a, vector<uint32_t>& A)
	{
		a.resize(32);
		A.resize(32);

		// bit-reverse
		for (size_t i = 0; i < 32; i++) {
			A[reverse8(i) >> 3] = a[i];
		}

		for (size_t s = 0; s < 5; s++) {
			uint32_t m = (2 << s);
			uint8_t step_size = 32 / m;
			for (size_t k = 0; k < 32; k += m)
			{
				uint8_t cur_id = 0;
				for (size_t j = 0; j < (m >> 1); j++) {
					uint32_t omega = NTT_TABLE_193[cur_id];
					uint32_t t = (omega * A[k + j + m / 2]) % 193;
					uint32_t u = A[k + j];
					A[k + j] = u + t;
					A[k + j + m / 2] = u - t + 193;
					cur_id += step_size;
				}
			}
		}
		for (size_t i = 0; i < 32; i++) {
			A[i] %= 193;
		}
	}

	void inverse(vector<uint32_t>& a, vector<uint32_t>& A)
	{
		a.resize(32);
		A.resize(32);

		// bit-reverse
		for (size_t i = 0; i < 32; i++) {
			A[reverse8(i) >> 3] = a[i];
		}

		for (size_t s = 0; s < 5; s++) {
			uint32_t m = (2 << s);
			uint8_t step_size = 32 / m;
			for (size_t k = 0; k < 32; k += m)
			{
				uint32_t cur_id = 32;
				for (size_t j = 0; j < (m >> 1); j++) {
					uint32_t omega = NTT_TABLE_193[cur_id];
					uint32_t t = omega * A[k + j + m / 2];
					uint32_t u = A[k + j];
					A[k + j] = (u + t) % 193;
					A[k + j + m / 2] = (u - t + 37249) % 193;
					cur_id -= step_size;
				}
			}
		}
		for (auto& val : A)
		{
			val = (val * NTT_193_INVERSE_OF_32) % 193;
		}
	}
}
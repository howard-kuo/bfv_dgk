#include "ntt.h"

namespace ntt193
{
	template <typename T>
	void nega_encode(vector<T>& vec, vector<T>& poly)
	{
		inverse_transform(vec, poly);

		T cur = 1;
		for (auto& coeff : poly) {
			coeff = (coeff * cur) % 193;
			cur = (cur * PHI) % 193;
		}
	}

	template <typename T>
	void nega_decode(vector<T>& poly, vector<T>& vec)
	{
		T cur = 1;
		for (auto& coeff : poly) {
			coeff = (coeff * cur) % 193;
			cur = (cur * PHI_INVERSE) % 193;
		}
		transform(poly, vec);
	}

	template <typename T>
	void nega_encode(vector<T>& vec, seal::Plaintext& poly, size_t degree)
	{
		vector<T> poly32(32);
		nega_encode(vec, poly32);
		size_t gap = degree / 32;
		poly.resize(degree);
		for (size_t i = 0; i < degree; i += gap) {
			poly[i] = poly32[i / gap];
		}
	}

	template <typename T>
	void nega_decode(seal::Plaintext& poly, vector<T>& vec, size_t degree)
	{
		vector<T> poly32(32);
		size_t gap = degree / 32;
		poly.resize(degree);
		for (size_t i = 0; i < degree; i += gap) {
			poly32[i / gap] = poly[i];
		}
		nega_decode(poly32, vec);
	}


	template<typename T>
	void transform(vector<T>& poly, vector<T>& vec)
	{
		poly.resize(32);
		vec.resize(32);

		// bit-reverse
		for (size_t i = 0; i < 32; i++) {
			vec[reverse8(i) >> 3] = poly[i];
		}

		for (size_t s = 0; s < 5; s++) {
			uint32_t m = (2 << s);
			uint8_t step_size = 32 / m;
			for (size_t k = 0; k < 32; k += m)
			{
				uint8_t cur_id = 0;
				for (size_t j = 0; j < (m >> 1); j++) {
					uint32_t omega = TABLE[cur_id];
					uint32_t t = (omega * vec[k + j + m / 2]) % 193;
					uint32_t u = vec[k + j];
					vec[k + j] = u + t;
					vec[k + j + m / 2] = u - t + 193;
					cur_id += step_size;
				}
			}
		}
		for (size_t i = 0; i < 32; i++) {
			vec[i] %= 193;
		}
	}

	template <typename T>
	void inverse_transform(vector<T>& vec, vector<T>& poly)
	{
		vec.resize(32);
		poly.resize(32);

		// bit-reverse
		for (size_t i = 0; i < 32; i++) {
			poly[reverse8(i) >> 3] = vec[i];
		}

		for (size_t s = 0; s < 5; s++) {
			uint32_t m = (2 << s);
			uint8_t step_size = 32 / m;
			for (size_t k = 0; k < 32; k += m)
			{
				uint32_t cur_id = 32;
				for (size_t j = 0; j < (m >> 1); j++) {
					uint32_t omega = TABLE[cur_id];
					uint32_t t = omega * poly[k + j + m / 2];
					uint32_t u = poly[k + j];
					poly[k + j] = (u + t) % 193;
					poly[k + j + m / 2] = (u - t + 37249) % 193;
					cur_id -= step_size;
				}
			}
		}
		for (auto& val : poly)
		{
			val = (val * INVERSE_OF_32) % 193;
		}
	}
	
}
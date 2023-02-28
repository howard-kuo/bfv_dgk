#pragma once
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include "seal/seal.h"
#include "ntt.h"
#include "setparms.h"



namespace info
{
	using namespace std;
	using namespace seal;

	static void new_line(size_t id, size_t row_length) {
		if ((id + 1) % row_length == 0) 
			cout << endl;
	}


	template <typename T>
	static void print_vec32(vector<T> vec) {
		// cout << "   print vector:" << endl;
		vec.resize(32);
		for (size_t i = 0; i < 32; i++) {
			cout << setw(7) << vec[i];
			new_line(i, 8);
		}
		cout << endl;
	}
	static void print_plain_some(const Plaintext& plain, size_t print_size = 16) {
		cout << "   print plaintext: " << endl;
		if (!plain.coeff_count())
			cout << "      null plain" << endl;
		for (size_t i = 0; i < plain.coeff_count(); i++) {
			if (i >= print_size) 
				break;
			cout << setw(7) << plain[i];
			new_line(i, 8);
		}
		cout << endl;
	}
	static void print_plain(const Plaintext& plain, size_t gap) {
		cout << "   print plaintext: " << endl;
		if (!plain.coeff_count())
			cout << "      null plain" << endl;
		for (size_t i = 0; i < plain.coeff_count(); i += gap) {
			cout << setw(7) << plain[i];
			new_line(i / gap, 8);
		}
		cout << endl;
	}
    static void print_cipher_packed
        (Ciphertext &cipher, Decryptor &decryptor, size_t degree) 
    {
        cout << "\n print ciphertext (packed): \n" << endl;
        Plaintext plain;
        decryptor.decrypt(cipher, plain);
        vector<uint32_t> vec;
        ntt193::nega_decode(plain, vec, degree);
        print_vec32(vec);
        cout << "   + noise budget " << decryptor.invariant_noise_budget(cipher)
            << "\n" << endl;
    }
    static void print_cipher_sparse
    (Ciphertext& cipher, Decryptor& decryptor, size_t gap)
    {
        cout << "\n print ciphertext: \n" << endl;
        Plaintext plain;
        decryptor.decrypt(cipher, plain);
        print_plain(plain, gap);
        cout << "   + noise budget " << decryptor.invariant_noise_budget(cipher)
            << endl;
    }
	static void print_cipher_some
	(Ciphertext& cipher, Decryptor& decryptor, size_t print_size = 16)
	{
		cout << "\n print ciphertext: \n" << endl;
		Plaintext plain;
		decryptor.decrypt(cipher, plain);
		print_plain_some(plain, print_size);
		cout << "   + noise budget " << decryptor.invariant_noise_budget(cipher)
			<< endl;
	}

	static inline void print_banner(std::string title)
	{
		if (!title.empty())
		{
			std::size_t title_length = title.length();
			std::size_t banner_length = title_length + 2 * 10;
			std::string banner_top = "+" + std::string(banner_length - 2, '-') + "+";
			std::string banner_middle =
				"|" + std::string(9, ' ') + title + std::string(9, ' ') + "|";

			std::cout << std::endl
				<< banner_top << std::endl
				<< banner_middle << std::endl
				<< banner_top << std::endl;
		}
	}

	static void print_parms(shared_ptr<SEALContext> context) {
        // Verify parameters
        if (!context)
        {
            throw std::invalid_argument("context is not set");
        }
        auto& context_data = *context->key_context_data();

        /*
        Which scheme are we using?
        */
        std::string scheme_name;
        switch (context_data.parms().scheme())
        {
        case seal::scheme_type::BFV:
            scheme_name = "BFV";
            break;
        case seal::scheme_type::CKKS:
            scheme_name = "CKKS";
            break;
        default:
            throw std::invalid_argument("unsupported scheme");
        }
        std::cout << "/" << std::endl;
        std::cout << "| Encryption parameters :" << std::endl;
        std::cout << "|   scheme: " << scheme_name << std::endl;
        std::cout << "|   poly_modulus_degree: " <<
            context_data.parms().poly_modulus_degree() << std::endl;

        /*
        Print the size of the true (product) coefficient modulus.
        */
        std::cout << "|   coeff_modulus size: ";
        std::cout << context_data.total_coeff_modulus_bit_count() << " (";
        auto coeff_modulus = context_data.parms().coeff_modulus();
        std::size_t coeff_mod_count = coeff_modulus.size();
        for (std::size_t i = 0; i < coeff_mod_count - 1; i++)
        {
            std::cout << coeff_modulus[i].bit_count() << " + ";
        }
        std::cout << coeff_modulus.back().bit_count();
        std::cout << ") bits" << std::endl;

        /*
        For the BFV scheme print the plain_modulus parameter.
        */
        if (context_data.parms().scheme() == seal::scheme_type::BFV)
        {
            std::cout << "|   plain_modulus: " << context_data.
                parms().plain_modulus().value() << std::endl;
        }

        std::cout << "\\" << std::endl;
	}


	namespace
	{
		void test_nega()
		{
			cout << "NTT193:: TEST NEGA ------\n" << endl;
			vector<uint32_t> vec(32), poly(32);
			poly[0] = 1;
			poly[1] = 2;
			poly[2] = 3;

			cout << "orginial polynomial." << endl;
			info::print_vec32(poly);

			ntt193::nega_decode(poly, vec);

			cout << "encode into vector." << endl;
			info::print_vec32(vec);

			ntt193::nega_encode(vec, poly);

			cout << "decode into orginal polynomial." << endl;
			info::print_vec32(poly);
			for (auto& c : vec) {
				c *= c;
				c %= 193;
			}


			ntt193::nega_encode(vec, poly);

			cout << "compute poly^2 via nega ntt transform." << endl;
			info::print_vec32(poly);
		}
		void test_ntt()
		{
			vector<uint32_t> vec(32), poly(32);
			poly[16] = 2;
			ntt193::transform(poly, vec);
			info::print_vec32(vec);
			ntt193::inverse_transform(vec, poly);
			info::print_vec32(poly);
			for (auto& c : vec) {
				c *= c;
				c %= 193;
			}
			ntt193::inverse_transform(vec, poly);
			info::print_vec32(poly);
		}
		void test_something()
		{
			cout << " TEST ------\n" << endl;
			size_t degree = 1024;
			size_t plain_modulus = 193;
			auto parms = setparms(degree, plain_modulus);
			auto context = SEALContext::Create(parms);
			Plaintext p1;
			Ciphertext c1;
			vector<uint32_t> vec(32);
			vec[16] = 1;
			info::print_vec32(vec);
			ntt193::nega_encode(vec, p1, degree);

			info::print_plain(p1, 32);

			ntt193::nega_decode(p1, vec, degree);
			info::print_vec32(vec);
		}

	}

}

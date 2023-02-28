#pragma once
#include "seal/seal.h"

namespace
{
	using namespace seal;
	SEAL_NODISCARD static EncryptionParameters setparms
	(size_t degree, size_t plain_modulus)
	{
		EncryptionParameters parms(scheme_type::BFV);
		parms.set_poly_modulus_degree(degree);
		parms.set_coeff_modulus(CoeffModulus::BFVDefault(degree));
		parms.set_plain_modulus(plain_modulus);
		return parms;
	}
	SEAL_NODISCARD static 
		EncryptionParameters setparms
		(size_t degree, SmallModulus plain_modulus)
	{
		EncryptionParameters parms(scheme_type::BFV);
		parms.set_poly_modulus_degree(degree);
		parms.set_coeff_modulus(CoeffModulus::BFVDefault(degree));
		parms.set_plain_modulus(plain_modulus);
		return parms;
	}
}
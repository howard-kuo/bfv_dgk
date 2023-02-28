#include "encryption_schemes.h"

int Encryptor_supervisor::n_enc = 0;
int Encryptor_supervisor::n_enc_sym = 0;
int Encryptor_supervisor::n_enc_zero = 0;

std::chrono::microseconds Encryptor_supervisor::time_diff_enc(0);
std::chrono::microseconds Encryptor_supervisor::time_diff_enc_sym(0);
std::chrono::microseconds Encryptor_supervisor::time_diff_enc_zero(0);


int Evaluator_supervisor::n_add = 0;
int Evaluator_supervisor::n_mul = 0;

std::chrono::microseconds Evaluator_supervisor::time_diff_add(0);
std::chrono::microseconds Evaluator_supervisor::time_diff_mul(0);

int Decryptor_supervisor::n_dec = 0;

std::chrono::microseconds Decryptor_supervisor::time_diff_dec(0);
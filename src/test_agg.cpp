#include <iostream>
#include <vector>
#include <cstdlib>
#include "he.hpp"
#include "myutil.hpp"

using namespace std;

int main()
{
    auto ctx = create_ctx();
    auto keys = Keys();
    keys.generate();
    auto batch_encoder = seal::BatchEncoder(ctx);
    auto encryptor = seal::Encryptor(ctx, keys.public_key);
    encryptor.set_secret_key(keys.secret_key.value());

    vector<int> scales = {0, 3, 6, 9};
    for (auto &s : scales)
    {
        int num_c = 1 << s;
        cout << "Num of ciphertexts: 1 << " << s << " = " << (1 << s)
             << " #slots: 1 << " << (poly_degree_log2 + s) << " = " << (1 << (poly_degree_log2 + s)) << endl;
        // prepare ciphertexts
        vector<seal::Ciphertext> cs;
        for (int i = 0; i < num_c; ++i)
        {
            vector<uint64_t> v(slot_count, 0ULL);
            for (int j = 0; j < slot_count; ++j)
            {
                v[j] = rand() % 2;
            }
            seal::Plaintext p;
            batch_encoder.encode(v, p);
            seal::Ciphertext c;
            encryptor.encrypt(p, c);
            cs.push_back(c);
        }

        vector<seal::Ciphertext> cs_copy = cs;
        report_timing("opt_all_merge", true);
        auto merged = mt_merge_cipher_sums(cs_copy, keys, poly_degree_log2, 1);
        report_timing("opt_all_merge", false);

        cs_copy = cs;
        report_timing("opt4_merge", true);
        merged = mt_merge_cipher_sums(cs_copy, keys, 4, 1);
        report_timing("opt4_merge", false);

        cs_copy = cs;
        report_timing("opt2_merge", true);
        merged = mt_merge_cipher_sums(cs_copy, keys, 2, 1);
        report_timing("opt2_merge", false);

        cs_copy = cs;
        report_timing("simple_merge", true);
        merged = mt_merge_cipher_sums(cs_copy, keys, 0, 1);
        report_timing("simple_merge", false);
    }
    return 0;
}
#include "emap.hpp"
#include "myutil.hpp"

int main()
{
    // setup keys
    std::cout << "Setup keys" << std::endl;
    auto ctx = create_ctx();

    report_timing("setup_keys", true);
    auto keygen = seal::KeyGenerator(ctx);
    auto secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    seal::GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    report_timing("setup_keys", false);

    // construct input:
    std::cout << "Construct input" << std::endl;
    size_t mapping_len = 256;
    size_t mapping_output_range = (1 << 17);
    // - a table with slot_num rows
    // - a mapping from 0~mapping_len to 0~plain_mod
    std::vector<uint> k_vec(slot_count);
    for (int i = 0; i < slot_count; ++i)
        k_vec[i] = rand() % mapping_len;
    std::vector<uint64_t> mapping_vec(slot_count);
    size_t offset = 0; // or any mapping_len-aligned number
    for (int i = 0; i < mapping_len; ++i)
        mapping_vec[(i + offset) % slot_count] = rand() % mapping_output_range;

    // run different mapping versions
    std::cout << "Run different mapping versions" << std::endl;
    std::cout << "- Clear" << std::endl;
    report_timing("apply_emap:clear", true);
    std::vector<uint64_t> results_clear_vec(slot_count, 0);
    for (int i = 0; i < slot_count; ++i)
        results_clear_vec[i] = mapping_vec[(k_vec[i] + offset) % slot_count];
    report_timing("apply_emap:clear", false);

    seal::Evaluator evaluator(ctx);
    seal::Encryptor encryptor(ctx, public_key);
    encryptor.set_secret_key(secret_key);
    auto batch_encoder = seal::BatchEncoder(ctx);
    {
        auto slot_count = batch_encoder.slot_count();
        assert(slot_count == poly_degree);
    }
    seal::Plaintext mapping_plain;
    batch_encoder.encode(mapping_vec, mapping_plain);
    seal::Ciphertext mapping_cipher;
    encryptor.encrypt(mapping_plain, mapping_cipher);

    // std::cout << "- Encrypted - Naive" << std::endl;
    // // run naive
    // report_timing("apply_emap:encrypted_naive", true);
    // auto results_naive = apply_emap_naively(k_vec, mapping_cipher, batch_encoder, evaluator, relin_keys, galois_keys);
    // report_timing("apply_emap:encrypted_naive", false);
    // // verify correctness
    // seal::Decryptor decryptor(ctx, secret_key);
    // seal::Plaintext results_naive_plain;
    // decryptor.decrypt(results_naive, results_naive_plain);
    // std::vector<uint64_t> results_naive_vec;
    // batch_encoder.decode(results_naive_plain, results_naive_vec);
    // for (int i = 0; i < slot_count; ++i)
    // {
    //     if (results_naive_vec[i] != results_clear_vec[i])
    //     {
    //         std::cout << "i: " << i << std::endl;
    //         std::cout << "results_naive_vec[i]: " << results_naive_vec[i] << std::endl;
    //         std::cout << "results_clear_vec[i]: " << results_clear_vec[i] << std::endl;
    //     }
    //     assert(results_naive_vec[i] == results_clear_vec[i]);
    // }

    // - encrypted - optimized
    auto k = Keys(keygen);

    std::vector<int> scales = {14, 17, 20};
    for (auto scale : scales)
    {
        // std::cout << "scale: " << scale << std::endl;
        // report_timing("apply_emap:opt:rot_caching", true);
        // auto c_rots = prepare_rots(mapping_cipher, offset, k, 8);
        // report_timing("apply_emap:opt:rot_caching", false);

        for (int i = 0; i < slot_count; ++i)
            k_vec[i] = rand() % mapping_len;

        report_timing("apply_emap:opt:opt_emap_after_rot", true);
        for (int i = 0; i < ((1 << scale) / slot_count); ++i)
        {
            report_timing("apply_emap:opt:rot_caching", true);
            auto c_rots = prepare_rots(mapping_cipher, offset, k, 8);
            report_timing("apply_emap:opt:rot_caching", false);
            auto c = apply_emap(k_vec, c_rots, k, 8);
        }
        report_timing("apply_emap:opt:opt_emap_after_rot", false);
    }

    // benchmark 8-bit, 16-bit, and 32-bit range query
    // TODO

    // compare results (speed)
    // TODO

    return 0;
}

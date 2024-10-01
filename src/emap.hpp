#pragma once
#include "he.hpp"
#include "myutil.hpp"

seal::Ciphertext apply_emap_naively(
    std::vector<uint> &k,
    seal::Ciphertext &mapping,
    seal::BatchEncoder &batch_encoder,
    seal::Evaluator &evaluator,
    seal::RelinKeys &relin_keys,
    seal::GaloisKeys &galois_keys)
{
    assert(k.size() == slot_count);
    seal::Ciphertext ret;
    // for (int i = 0; i < 128; ++i) {
    for (int i = 0; i < k.size(); ++i)
    {
        if (i % 100 == 0)
            std::cout << "i: " << i << std::endl;
        seal::Ciphertext cur;
        int v_loc = k[i] % slot_count;
        std::vector<uint64_t> mask(slot_count, 0);
        mask[v_loc] = 1;
        seal::Plaintext plain;
        batch_encoder.encode(mask, plain);
        evaluator.multiply_plain(mapping, plain, cur);
        evaluator.relinearize_inplace(cur, relin_keys);
        int o_loc = i;
        if ((o_loc < slot_count / 2) != (v_loc < slot_count / 2))
        {
            evaluator.rotate_columns_inplace(cur, galois_keys);
            v_loc %= slot_count / 2;
            o_loc %= slot_count / 2;
        }
        if (v_loc != o_loc)
        {
            evaluator.rotate_rows_inplace(cur, v_loc - o_loc, galois_keys);
        }
        if (i == 0)
        {
            ret = cur;
        }
        else
        {
            evaluator.add_inplace(ret, cur); // noise?
        }
    }
    return ret;
}

seal::Ciphertext apply_emap(
    const std::vector<uint> &k,
    const std::vector<seal::Ciphertext> &rotated_mappings,
    Keys &keys,
    int eq_bit_size = 8)
{
    using namespace std;
    auto batchEncoder = seal::BatchEncoder(create_ctx());
    auto evaluator = seal::Evaluator(create_ctx());
    auto encryptor = seal::Encryptor(create_ctx(), keys.public_key);

    const size_t mapping_batch_cipher_bit_width = eq_bit_size;
    const size_t mapping_batch_cipher_width = (1 << mapping_batch_cipher_bit_width);

    auto record_map_picker = vector<vector<uint64_t>>(mapping_batch_cipher_width);
    for (int i = 0; i < (int)mapping_batch_cipher_width; ++i)
        record_map_picker[i] = vector<uint64_t>(slot_count, 0ULL);
    for (int i = 0; i < (int)slot_count; ++i)
        record_map_picker[(k[i] + mapping_batch_cipher_width - i) % mapping_batch_cipher_width][i] = 1;
    // prepare a full-zero plaintext first
    seal::Plaintext zero_plain;
    std::vector<uint64_t> zero_vec(slot_count, 0ULL);
    batchEncoder.encode(zero_vec, zero_plain);

    auto masked_shift = vector<seal::Ciphertext>(mapping_batch_cipher_width);
    for (int i = 0; i < (int)mapping_batch_cipher_width; ++i)
    {
        // if all coefficient in the record_map_picker[i] is 0, it will lead to transparent ciphertext which is insecure
        // so we need to check if all coefficient in the record_map_picker[i] is 0
        bool all_zero = true;
        for (int j = 0; j < (int)slot_count; ++j)
        {
            if (record_map_picker[i][j] != 0)
            {
                all_zero = false;
                break;
            }
        }
        if (!all_zero)
        {
            seal::Plaintext picker_plain;
            masked_shift[i] = rotated_mappings[i];
            batchEncoder.encode(record_map_picker[i], picker_plain);
            evaluator.multiply_plain_inplace(masked_shift[i], picker_plain);
            evaluator.relinearize_inplace(masked_shift[i], keys.relin_keys);
        }
        else
        {
            encryptor.encrypt(zero_plain, masked_shift[i]); // side-channel?
        }
    }
    he_balanced_sum_inplace(evaluator, masked_shift.data(), 0, mapping_batch_cipher_width);
    return masked_shift[0];
}

seal::Ciphertext mt_apply_emap(
    const std::vector<uint> &k,
    const std::vector<seal::Ciphertext> &rotated_mappings,
    Keys &keys,
    int thread_num = 32,
    int eq_bit_size = 8)
{
    using namespace std;
    // report_timing("prepare", true);
    auto batchEncoder = seal::BatchEncoder(create_ctx());
    auto evaluator = seal::Evaluator(create_ctx());
    auto encryptor = seal::Encryptor(create_ctx(), keys.public_key);

    const size_t mapping_batch_cipher_bit_width = eq_bit_size;
    const size_t mapping_batch_cipher_width = (1 << mapping_batch_cipher_bit_width);

    auto record_map_picker = vector<vector<uint64_t>>(mapping_batch_cipher_width);
    for (int i = 0; i < (int)mapping_batch_cipher_width; ++i)
        record_map_picker[i] = vector<uint64_t>(slot_count, 0ULL);
    for (int i = 0; i < (int)slot_count; ++i)
        record_map_picker[(k[i] + mapping_batch_cipher_width - i) % mapping_batch_cipher_width][i] = 1;
    // prepare a full-zero plaintext first
    seal::Plaintext zero_plain;
    std::vector<uint64_t> zero_vec(slot_count, 0ULL);
    batchEncoder.encode(zero_vec, zero_plain);

    auto masked_shift = vector<seal::Ciphertext>(mapping_batch_cipher_width);
    // report_timing("prepare", false);
    // report_timing("threaded", true);
    vector<thread> threads;
    for (int t = 0; t < thread_num; t++)
    {
        threads.emplace_back([t, thread_num, mapping_batch_cipher_width, &rotated_mappings, &zero_plain, &masked_shift, &batchEncoder, &encryptor, &evaluator, &record_map_picker, &keys]()
                             {
                                int l = t * (mapping_batch_cipher_width / thread_num);
                                int r = (t + 1) * (mapping_batch_cipher_width / thread_num);
for (int i =  l; i < (int)r; ++i)
    {
        // if all coefficient in the record_map_picker[i] is 0, it will lead to transparent ciphertext which is insecure
        // so we need to check if all coefficient in the record_map_picker[i] is 0
        bool all_zero = true;
        for (int j = 0; j < (int)slot_count; ++j)
        {
            if (record_map_picker[i][j] != 0)
            {
                all_zero = false;
                break;
            }
        }
        if (!all_zero)
        {
            seal::Plaintext picker_plain;
            masked_shift[i] = rotated_mappings[i];
            batchEncoder.encode(record_map_picker[i], picker_plain);
            evaluator.multiply_plain_inplace(masked_shift[i], picker_plain);
            evaluator.relinearize_inplace(masked_shift[i], keys.relin_keys);
        }
        else
        {
            encryptor.encrypt(zero_plain, masked_shift[i]); // side-channel?
        }
    } });
    }
    for (auto &t : threads)
        t.join();
    // report_timing("threaded", false);
    // report_timing("sum", true);
    mt_he_balanced_sum_inplace(evaluator, masked_shift.data(), 0, mapping_batch_cipher_width);
    // report_timing("sum", false);
    return masked_shift[0];
}

seal::Ciphertext apply_rot_cached_emap(
    std::vector<uint> &k,
    std::vector<seal::Ciphertext> &rotated_mappings)
{
    // TODO
    seal::Ciphertext ret;
    for (int i = 0; i < k.size(); ++i)
    {
        // TODO
    }
    return ret;
}

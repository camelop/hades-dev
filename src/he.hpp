#pragma once

#include <iostream>
#include <bit>
#include <optional>
#include <json.hpp>
#include <seal/seal.h>
#include <Base64.h>
#include <mutex>

using json = nlohmann::json;
using Base64 = macaron::Base64;

static size_t poly_degree_log2 = 14;
static size_t plain_mod_log2 = 18;
static size_t poly_degree = 1 << poly_degree_log2;
static size_t slot_count = poly_degree;

seal::SEALContext create_ctx()
{
    // cache result if already created
    static std::optional<seal::SEALContext> ctx;
    if (ctx.has_value())
    {
        return ctx.value();
    }
    else
    {
        auto params = seal::EncryptionParameters(seal::scheme_type::bfv);
        auto plain_mod = seal::PlainModulus::Batching(poly_degree, plain_mod_log2);
        params.set_poly_modulus_degree(poly_degree);
        params.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_degree));
        params.set_plain_modulus(plain_mod);
        ctx = seal::SEALContext(params);
        return ctx.value();
    }
}

class Keys
{
public:
    seal::PublicKey public_key;
    seal::GaloisKeys galois_keys;
    seal::RelinKeys relin_keys;
    std::optional<seal::SecretKey> secret_key;
    // to support key serialization later
    std::optional<seal::Serializable<seal::PublicKey>> s_public_key;
    std::optional<seal::Serializable<seal::GaloisKeys>> s_galois_keys;
    std::optional<seal::Serializable<seal::RelinKeys>> s_relin_keys;

    // Keys(const Keys&) = delete;
    Keys &operator=(const Keys &) = delete;
    Keys() = default;
    ~Keys() = default;

    Keys(seal::KeyGenerator &keygen)
    {
        load_from_keygen(keygen);
    }

    void generate()
    {
        auto ctx = create_ctx();
        auto keygen = seal::KeyGenerator(ctx);
        load_from_keygen(keygen);
    }

    void load_from_keygen(seal::KeyGenerator &keygen) {
        auto ctx = create_ctx();
        secret_key = keygen.secret_key();
        s_public_key = keygen.create_public_key();
        std::stringstream public_key_stream;
        s_public_key.value().save(public_key_stream);
        public_key.load(ctx, public_key_stream);

        s_galois_keys = keygen.create_galois_keys();
        std::stringstream galois_keys_stream;
        s_galois_keys.value().save(galois_keys_stream);
        galois_keys.load(ctx, galois_keys_stream);

        s_relin_keys = keygen.create_relin_keys();
        std::stringstream relin_keys_stream;
        s_relin_keys.value().save(relin_keys_stream);
        relin_keys.load(ctx, relin_keys_stream);
    }

    std::stringstream saveProcessingKeys()
    {
        // NOTE: this function should not be called with the loaded keys
        std::stringstream keys_stream;
        s_public_key.value().save(keys_stream);
        s_galois_keys.value().save(keys_stream);
        s_relin_keys.value().save(keys_stream);
        return keys_stream;
    }

    std::stringstream saveSecretKey()
    {
        assert(secret_key.has_value());
        std::stringstream secret_key_stream;
        secret_key->save(secret_key_stream);
        return secret_key_stream;
    }

    void loadProcessingKeys(std::stringstream &keys_stream)
    {
        auto ctx = create_ctx();
        public_key.load(ctx, keys_stream);
        galois_keys.load(ctx, keys_stream);
        relin_keys.load(ctx, keys_stream);
    }

    void loadSecretKey(std::stringstream &secret_key_stream)
    {
        auto ctx = create_ctx();
        secret_key = seal::SecretKey();
        secret_key->load(ctx, secret_key_stream);
    }
};

std::vector<seal::Ciphertext> prepare_rots(
    const seal::Ciphertext &c_mapping,
    const size_t offset,
    const Keys &keys,
    int eq_bit_size = 8)
{
    const size_t mapping_batch_cipher_bit_width = eq_bit_size;
    const size_t mapping_batch_cipher_width = (1 << mapping_batch_cipher_bit_width);
    assert(eq_bit_size <= poly_degree_log2);

    seal::RelinKeys relinKeys = keys.relin_keys;
    seal::GaloisKeys galoisKeys = keys.galois_keys;
    seal::Evaluator evaluator(create_ctx());
    seal::BatchEncoder batchEncoder(create_ctx());

    // 1. Mask & duplicate [****, ****, 1234, ****] -> [1234, 1234, 1234, 1234] (1-4 should all be 0 or 1)
    std::vector<uint64_t> mask(slot_count, 0ULL);
    for (std::size_t i = offset;
         i < offset + mapping_batch_cipher_width;
         ++i)
        mask[i] = 1;
    seal::Plaintext mask_plain;
    batchEncoder.encode(mask, mask_plain);
    seal::Ciphertext masked_group;
    evaluator.multiply_plain(c_mapping, mask_plain, masked_group);
    evaluator.relinearize_inplace(masked_group, relinKeys);

    seal::Ciphertext masked_group_after_rotation;
    evaluator.rotate_columns(masked_group, galoisKeys, masked_group_after_rotation);
    evaluator.add_inplace(masked_group, masked_group_after_rotation);
    for (int i = poly_degree_log2 - 2; i >= (int)mapping_batch_cipher_bit_width; --i)
    {
        evaluator.rotate_rows(masked_group, (1 << i), galoisKeys, masked_group_after_rotation);
        evaluator.add_inplace(masked_group, masked_group_after_rotation);
    }
    // 2. Prepare all possible rotation result [1234, 1234, ...], [2341, 2341, ...], [3412, 3412, ...], ...
    auto masked_shift = std::vector<seal::Ciphertext>(mapping_batch_cipher_width);
    masked_shift[0] = masked_group;
    for (int i = 1; i < (int)mapping_batch_cipher_width; ++i)
    {
        evaluator.rotate_rows(masked_shift[i - 1], 1, galoisKeys, masked_shift[i]);
    }
    return masked_shift;
}

std::vector<seal::Ciphertext> mt_prepare_rots(
    const seal::Ciphertext &c_mapping,
    const size_t offset,
    const size_t width,
    const size_t split,
    const Keys &keys)
{
    const size_t mapping_batch_cipher_bit_width = std::bit_width(width) - 1;
    const size_t mapping_batch_cipher_width = (1 << mapping_batch_cipher_bit_width);

    seal::RelinKeys relinKeys = keys.relin_keys;
    seal::GaloisKeys galoisKeys = keys.galois_keys;
    seal::Evaluator evaluator(create_ctx());
    seal::BatchEncoder batchEncoder(create_ctx());

    // 1. Mask & duplicate [****, ****, 1234, ****] -> [1234, 1234, 1234, 1234] (1-4 should all be 0 or 1)
    std::vector<uint64_t> mask(slot_count, 0ULL);
    for (std::size_t i = offset;
         i < offset + mapping_batch_cipher_width;
         ++i)
        mask[i] = 1;
    seal::Plaintext mask_plain;
    batchEncoder.encode(mask, mask_plain);
    seal::Ciphertext masked_group;
    evaluator.multiply_plain(c_mapping, mask_plain, masked_group);
    evaluator.relinearize_inplace(masked_group, relinKeys);

    seal::Ciphertext masked_group_after_rotation;
    evaluator.rotate_columns(masked_group, galoisKeys, masked_group_after_rotation);
    evaluator.add_inplace(masked_group, masked_group_after_rotation);
    for (int i = poly_degree_log2 - 2; i >= (int)mapping_batch_cipher_bit_width; --i)
    {
        evaluator.rotate_rows(masked_group, (1 << i), galoisKeys, masked_group_after_rotation);
        evaluator.add_inplace(masked_group, masked_group_after_rotation);
    }
    // 2. Prepare all possible rotation result [1234, 1234, ...], [2341, 2341, ...], [3412, 3412, ...], ...
    auto masked_shift = std::vector<seal::Ciphertext>(mapping_batch_cipher_width);
    masked_shift[0] = masked_group;

    std::vector<std::thread> threads;
    int region_size = mapping_batch_cipher_width / split;
    for (int i = 0; i < split; ++i)
    {
        if (i > 0)
        {
            evaluator.rotate_rows(masked_shift[(i - 1) * region_size], region_size, galoisKeys, masked_shift[i * region_size]);
        }
        threads.emplace_back([i, &region_size, &masked_shift, &evaluator, &galoisKeys]()
                             {
            int l = i * region_size + 1;
            int r = (i+1) * region_size;
            for (int j = l; j < r; ++j)
            {
                evaluator.rotate_rows(masked_shift[j - 1], 1, galoisKeys, masked_shift[j]);
            } });
    }
    for (auto &t : threads)
    {
        t.join();
    }
    return masked_shift;
}

void he_balanced_sum_inplace(seal::Evaluator &eval, seal::Ciphertext cs[], size_t l, size_t r)
{
    // sum cs[l:r) into cs[l]
    // e.g. l=0, r=4, cs[0] += cs[1] + cs[2] + cs[3]
    // the additions are balanced to reduce noise
    if (l + 1 >= r)
        return;
    int mid = (l + r + 1) / 2;
    he_balanced_sum_inplace(eval, cs, l, mid);
    he_balanced_sum_inplace(eval, cs, mid, r);
    eval.add_inplace(cs[l], cs[mid]);
}

void mt_he_balanced_sum_inplace(seal::Evaluator &eval, seal::Ciphertext cs[], size_t l, size_t r)
{
    // sum cs[l:r) into cs[l]
    // e.g. l=0, r=4, cs[0] += cs[1] + cs[2] + cs[3]
    // the additions are balanced to reduce noise
    if (l + 1 >= r)
        return;
    int mid = (l + r + 1) / 2;
    if (r - mid >= 16)
    {
        std::thread t0([&eval, &cs, l, mid]()
                       { mt_he_balanced_sum_inplace(eval, cs, l, mid); });
        std::thread t1([&eval, &cs, mid, r]()
                       { mt_he_balanced_sum_inplace(eval, cs, mid, r); });
        t0.join();
        t1.join();
    }
    else
    {
        he_balanced_sum_inplace(eval, cs, l, mid);
        he_balanced_sum_inplace(eval, cs, mid, r);
    }
    eval.add_inplace(cs[l], cs[mid]);
}

seal::Ciphertext merge_cipher_sums(
    std::vector<seal::Ciphertext> &cs,
    const Keys &keys)
{
    // sum up multiple ciphertext and merge them into one ciphertext
    // eg. [1, 2, 3, 4], [5, 6, 7, 8] --> [10, 26, 0, 0]
    // note that this operation consumes the input ciphertexts
    using namespace std;

    auto ctx = create_ctx();
    auto batchEncoder = seal::BatchEncoder(ctx);
    auto encryptor = seal::Encryptor(ctx, keys.public_key);
    auto evaluator = seal::Evaluator(ctx);

    if (cs.size() == 0)
    {
        seal::Plaintext zero_plain;
        std::vector<uint64_t> zero_vec(slot_count, 0ULL);
        batchEncoder.encode(zero_vec, zero_plain);
        seal::Ciphertext zero_c;
        encryptor.encrypt(zero_plain, zero_c);
        return zero_c;
    }

    // make sure one cipher has enough slots to hold all the sums
    assert(cs.size() <= (1 << poly_degree_log2));
    // additionally --> make sure the noise budget is enough
    assert(cs.size() <= (1 << 9));
    // algorithm: 1 step of balanced sum, 1 step of merging ciphertexts
    for (int i = 0; i < poly_degree_log2; ++i)
    {
        int offset = (1 << i);
        for (int j = 0; j < cs.size(); ++j)
        {
            seal::Ciphertext c_after_rotation;
            if (i == poly_degree_log2 - 1)
            {
                // rotate columns (direction does not matter)
                evaluator.rotate_columns(cs[j], keys.galois_keys, c_after_rotation);
                evaluator.add_inplace(cs[j], c_after_rotation);
            }
            else
            {
                if (j & 1)
                {
                    // rotate rows to the left (offset<0)
                    evaluator.rotate_rows(cs[j], -offset, keys.galois_keys, c_after_rotation);
                    evaluator.add_inplace(cs[j], c_after_rotation);
                }
                else
                {
                    // rotate rows to the right (offset>0)
                    evaluator.rotate_rows(cs[j], offset, keys.galois_keys, c_after_rotation);
                    evaluator.add_inplace(cs[j], c_after_rotation);
                }
            }
        }
        if (cs.size() == 1)
            continue; // no need to calculate mask, skip to save noise budget
        // bool apply_mod_switch = (i == 3 || i == 6 || i == 8 || i == 10 || i == 13);
        bool apply_mod_switch = false;
        std::vector<uint64_t> mask0(slot_count, 0ULL);
        std::vector<uint64_t> mask1(slot_count, 0ULL);
        for (int j = 0; j < slot_count; ++j)
        {
            mask0[j] = j & offset ? 0ULL : 1ULL;
            mask1[j] = j & offset ? 1ULL : 0ULL;
        }
        seal::Plaintext mask0_plain;
        batchEncoder.encode(mask0, mask0_plain);
        seal::Plaintext mask1_plain;
        batchEncoder.encode(mask1, mask1_plain);
        // merge
        vector<seal::Ciphertext> new_cs;
        for (int j = 0; j < cs.size(); j += 2)
        {
            evaluator.multiply_plain_inplace(cs[j], mask0_plain);
            evaluator.relinearize_inplace(cs[j], keys.relin_keys);
            if (j < cs.size() - 1)
            {
                // last one
                evaluator.multiply_plain_inplace(cs[j + 1], mask1_plain);
                evaluator.relinearize_inplace(cs[j + 1], keys.relin_keys);
                evaluator.add_inplace(cs[j], cs[j + 1]);
            }
            if (apply_mod_switch)
            {
                evaluator.mod_switch_to_next_inplace(cs[j]);
            }
            new_cs.push_back(cs[j]);
        }
        cs = new_cs;
    }
    assert(cs.size() == 1);
    return cs[0];
}

std::vector<seal::Ciphertext> mt_merge_cipher_sums(
    std::vector<seal::Ciphertext> &cs,
    const Keys &keys,
    size_t opt_step,
    size_t MAX_THREAD = 256)
{
    using namespace std;

    auto ctx = create_ctx();
    auto batchEncoder = seal::BatchEncoder(ctx);
    auto encryptor = seal::Encryptor(ctx, keys.public_key);
    auto evaluator = seal::Evaluator(ctx);

    vector<thread> threads;
    std::mutex mtx;

    if (cs.size() == 0)
    {
        seal::Plaintext zero_plain;
        std::vector<uint64_t> zero_vec(slot_count, 0ULL);
        batchEncoder.encode(zero_vec, zero_plain);
        seal::Ciphertext zero_c;
        encryptor.encrypt(zero_plain, zero_c);
        return {zero_c};
    }

    int total_step = poly_degree_log2;
    assert(opt_step <= total_step);
    int offset_log2 = 0;
    int low_noise_step = total_step - opt_step;
    for (int i = 0; i < opt_step; ++i)
    {
        int offset = (1 << offset_log2);
        std::vector<uint64_t> mask0(slot_count, 0ULL);
        std::vector<uint64_t> mask1(slot_count, 0ULL);
        for (int j = 0; j < slot_count; ++j)
        {
            mask0[j] = j & offset ? 0ULL : 1ULL;
            mask1[j] = j & offset ? 1ULL : 0ULL;
        }
        seal::Plaintext mask0_plain;
        batchEncoder.encode(mask0, mask0_plain);
        seal::Plaintext mask1_plain;
        batchEncoder.encode(mask1, mask1_plain);
        // update cs internally
        for (int j = 0; j < cs.size(); ++j)
        {
            threads.emplace_back([j, &cs, &evaluator, &offset_log2, &keys, &offset]()
                                 {
                seal::Ciphertext c_after_rotation;
                if (offset_log2 == poly_degree_log2 - 1)
                {
                    // rotate columns (direction does not matter)
                    evaluator.rotate_columns(cs[j], keys.galois_keys, c_after_rotation);
                    evaluator.add_inplace(cs[j], c_after_rotation);
                }
                else
                {
                    if (j & 1)
                    {
                        // rotate rows to the left (offset<0)
                        evaluator.rotate_rows(cs[j], -offset, keys.galois_keys, c_after_rotation);
                        evaluator.add_inplace(cs[j], c_after_rotation);
                    }
                    else
                    {
                        // rotate rows to the right (offset>0)
                        evaluator.rotate_rows(cs[j], offset, keys.galois_keys, c_after_rotation);
                        evaluator.add_inplace(cs[j], c_after_rotation);
                    }
                } });
            if (threads.size() >= MAX_THREAD)
            {
                for (auto &t : threads)
                {
                    t.join();
                }
                threads.clear();
            }
        }
        for (auto &t : threads)
        {
            t.join();
        }
        threads.clear();
        // merge
        offset_log2 += 1;
        if (cs.size() == 1)
            continue; // no need to calculate mask, skip to save noise budget
        vector<seal::Ciphertext> new_cs((cs.size() + 1) / 2);
        for (int j = 0; j < cs.size(); j += 2)
        {
            threads.emplace_back([j, &new_cs, &evaluator, &mask0_plain, &mask1_plain, &keys, &cs]()
                                 {
                evaluator.multiply_plain_inplace(cs[j], mask0_plain);
                evaluator.relinearize_inplace(cs[j], keys.relin_keys);
                if (j < cs.size() - 1)  // not last one
                {
                    evaluator.multiply_plain_inplace(cs[j + 1], mask1_plain);
                    evaluator.relinearize_inplace(cs[j + 1], keys.relin_keys);
                    evaluator.add_inplace(cs[j], cs[j + 1]);
                }
                new_cs[j/2] = cs[j]; });
            if (threads.size() >= MAX_THREAD)
            {
                for (auto &t : threads)
                {
                    t.join();
                }
                threads.clear();
            }
        }
        for (auto &t : threads)
        {
            t.join();
        }
        threads.clear();
        cs = new_cs;
    }
    // now we have cs.size() ciphertexts, each with len=offset useful sequence
    // for low_noise method, first, do local fold, then, apply masking
    // local fold
    int block_size_log2 = offset_log2;
    int block_size = 1 << block_size_log2;
    for (int j = 0; j < cs.size(); ++j)
    {
        threads.emplace_back([j, &cs, &evaluator, &keys, &block_size_log2]()
                             {
            for (int k = poly_degree_log2 - 1; k >= block_size_log2; --k) {
                int offset = (1 << k);
                seal::Ciphertext c_after_rotation;
                if (k == poly_degree_log2 - 1)
                {
                    // rotate columns (direction does not matter)
                    evaluator.rotate_columns(cs[j], keys.galois_keys, c_after_rotation);
                    evaluator.add_inplace(cs[j], c_after_rotation);
                }
                else
                {
                    // direction also does not matter as the values are repeated
                    evaluator.rotate_rows(cs[j], offset, keys.galois_keys, c_after_rotation);
                    evaluator.add_inplace(cs[j], c_after_rotation);
                }
            } });
        if (threads.size() >= MAX_THREAD)
        {
            for (auto &t : threads)
            {
                t.join();
            }
            threads.clear();
        }
    }
    for (auto &t : threads)
    {
        t.join();
    }
    threads.clear();
    if (cs.size() == 1)
    {
        return cs;
    }
    // apply masking
    int cur = 0;
    int sec = 0;
    int sec_full = 1 << low_noise_step;
    for (int j = 0; j < cs.size(); ++j)
    {
        std::vector<uint64_t> mask(slot_count, 0ULL);
        for (int k = block_size * sec; k < block_size * (sec + 1); ++k)
        {
            mask[k] = 1ULL;
        }
        seal::Plaintext mask_plain;
        batchEncoder.encode(mask, mask_plain);
        evaluator.multiply_plain_inplace(cs[j], mask_plain);
        evaluator.relinearize_inplace(cs[j], keys.relin_keys);
        if (sec == 0)
        {
            cs[cur] = cs[j];
        }
        else
        {
            evaluator.add_inplace(cs[cur], cs[j]);
        }
        ++sec;
        if (sec == sec_full)
        {
            sec = 0;
            ++cur;
        }
    }
    if (sec != 0)
    {
        ++cur;
    }
    cs.resize(cur);
    return cs;
}

void debug_print_noise_budget(const seal::Ciphertext &ct, const seal::SecretKey &sk)
{
    auto decryptor = seal::Decryptor(create_ctx(), sk);
    auto noise_budget = decryptor.invariant_noise_budget(ct);
    std::cout << "Noise budget " << noise_budget << std::endl;
}

std::stringstream save_ciphertexts(const std::vector<seal::Ciphertext> &ciphers)
{
    std::stringstream ss;
    for (const auto &cipher : ciphers)
    {
        cipher.save(ss);
    }
    return ss;
}

std::vector<seal::Ciphertext> load_ciphertexts(std::stringstream &ss)
{
    std::vector<seal::Ciphertext> ciphers;
    while (ss.tellg() != -1)
    {
        seal::Ciphertext cipher;
        cipher.load(create_ctx(), ss);
        ciphers.push_back(cipher);
    }
    return ciphers;
}
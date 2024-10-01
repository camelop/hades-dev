#include <iostream>
#include <fstream>
#include <algorithm>
#include <cassert>
#include <mutex>
#include <ctime>
#include <cstdlib>

#include "myutil.hpp"
#include "he.hpp"
#include "enc.hpp"
#include "emap.hpp"

using namespace std;

// vector<seal::Ciphertext> prepare_point_query(
//     uint64_t v,
//     size_t value_bit,
//     size_t mapping_bit,
//     seal::BatchEncoder &batchEncoder,
//     seal::Encryptor &encryptor)
// {
//     assert(value_bit <= 64);
//     assert(value_bit % mapping_bit == 0);
//     int required_ciphertext_num = value_bit / mapping_bit;
//     int mask = (1 << mapping_bit) - 1;
//     vector<seal::Ciphertext> ret;
//     vector<uint64_t> slots;
//     for (int i = 0; i < required_ciphertext_num; i++)
//     {
//         uint64_t current_v = (v >> (i * mapping_bit)) & mask;
//         for (int j = 0; j < (1 << mapping_bit); j++)
//         {
//             slots.push_back(j == current_v ? 1 : 0);
//             if (slots.size() == slot_count)
//             {
//                 seal::Plaintext plain;
//                 batchEncoder.encode(slots, plain);
//                 seal::Ciphertext c;
//                 encryptor.encrypt_symmetric(plain, c);
//                 ret.push_back(c);
//                 slots.clear();
//             }
//         }
//     }
//     assert(slots.size() == 0);
//     return ret;
// }

vector<uint64_t> get_rand_vec()
{
    vector<uint64_t> ret;
    for (int i = 0; i < 10; i++)
    {
        ret.push_back(rand() % (1 << plain_mod_log2));
    }
    return ret;
}

void test_add()
{
    Keys keys;
    keys.generate();
    auto ctx = create_ctx();
    auto batchEncoder = seal::BatchEncoder(ctx);
    auto evaluator = seal::Evaluator(create_ctx());
    auto encryptor = seal::Encryptor(ctx, keys.public_key);
    encryptor.set_secret_key(keys.secret_key.value());

    auto l = get_rand_vec();
    seal::Plaintext plain_l;
    batchEncoder.encode(l, plain_l);
    seal::Ciphertext c_l;
    encryptor.encrypt_symmetric(plain_l, c_l);

    auto r = get_rand_vec();
    seal::Plaintext plain_r;
    batchEncoder.encode(r, plain_r);
    seal::Ciphertext c_r;
    encryptor.encrypt_symmetric(plain_r, c_r);

    cout << "test_add 10 times" << endl;
    report_timing("addx10", true);
    for (int i = 0; i < 10; i++)
    {
        evaluator.add_inplace(c_l, c_r);
    }
    report_timing("addx10", false);
}

void test_mul()
{
    Keys keys;
    keys.generate();
    auto ctx = create_ctx();
    auto batchEncoder = seal::BatchEncoder(ctx);
    auto evaluator = seal::Evaluator(create_ctx());
    auto encryptor = seal::Encryptor(ctx, keys.public_key);
    encryptor.set_secret_key(keys.secret_key.value());

    auto l = get_rand_vec();
    seal::Plaintext plain_l;
    batchEncoder.encode(l, plain_l);
    seal::Ciphertext c_l;
    encryptor.encrypt_symmetric(plain_l, c_l);

    auto r = get_rand_vec();
    seal::Plaintext plain_r;
    batchEncoder.encode(r, plain_r);
    seal::Ciphertext c_r;
    encryptor.encrypt_symmetric(plain_r, c_r);

    cout << "test_mul 10 times" << endl;
    report_timing("mulx10", true);
    for (int i = 0; i < 10; i++)
    {
        evaluator.multiply_inplace(c_l, c_r);
        evaluator.relinearize_inplace(c_l, keys.relin_keys);
    }
    report_timing("mulx10", false);

    cout << "test_Pmul 10 times" << endl;
    report_timing("Pmulx10", true);
    for (int i = 0; i < 10; i++)
    {
        evaluator.multiply_plain_inplace(c_l, plain_r);
        evaluator.relinearize_inplace(c_l, keys.relin_keys);
    }
    report_timing("Pmulx10", false);
}

void test_rot()
{
    Keys keys;
    keys.generate();
    auto ctx = create_ctx();
    auto batchEncoder = seal::BatchEncoder(ctx);
    auto evaluator = seal::Evaluator(create_ctx());
    auto encryptor = seal::Encryptor(ctx, keys.public_key);
    encryptor.set_secret_key(keys.secret_key.value());

    auto l = get_rand_vec();
    seal::Plaintext plain_l;
    batchEncoder.encode(l, plain_l);
    seal::Ciphertext c_l;
    encryptor.encrypt_symmetric(plain_l, c_l);

    cout << "test_rot 10 times" << endl;
    report_timing("rotx10", true);
    for (int i = 0; i < 10; i++)
    {
        evaluator.rotate_rows_inplace(c_l, 1, keys.galois_keys);
    }
    report_timing("rotx10", false);
}

void test_cipher_size()
{
    Keys keys;
    keys.generate();
    auto ctx = create_ctx();
    auto batchEncoder = seal::BatchEncoder(ctx);
    auto evaluator = seal::Evaluator(create_ctx());
    auto encryptor = seal::Encryptor(ctx, keys.public_key);
    encryptor.set_secret_key(keys.secret_key.value());
    cout << "test_cipher_size 10 times" << endl;
    report_timing("cipher_size", true);
    for (int i = 0; i < 10; i++)
    {
        auto l = get_rand_vec();
        seal::Plaintext plain_l;
        batchEncoder.encode(l, plain_l);
        seal::Ciphertext c_l;
        encryptor.encrypt_symmetric(plain_l, c_l);
        stringstream ss;
        c_l.save(ss);
        cout << ss.str().size() * 1.0 / 1024 / 1024 << "MB" << endl;
    }
    report_timing("cipher_size", false);
}

void test_point_query(uint64_t v, size_t value_bit, int mapping_bit)
{
    cout << "v: " << v << ", value_bit: " << value_bit << ", mapping_bit: " << mapping_bit << endl;

    report_timing("keygen", true);
    Keys keys;
    keys.generate();
    report_timing("keygen", false);

    report_timing("setup", true);
    auto ctx = create_ctx();
    auto batchEncoder = seal::BatchEncoder(ctx);
    auto evaluator = seal::Evaluator(create_ctx());
    // for client, use seeded encrypt
    auto encryptor = seal::Encryptor(ctx, keys.public_key);
    encryptor.set_secret_key(keys.secret_key.value());
    report_timing("setup", false);

    // generate eq check
    // report_timing("encrypt_query", true);
    // auto c_mappings = prepare_point_query(v, value_bit, mapping_bit, batchEncoder, encryptor);
    // report_timing("encrypt_query", false);

    // report_timing("prepare_rots", true);
    // vector<vector<seal::Ciphertext>> c_rots;
    // for (int i = 0; i < c_mappings.size(); i++)
    // {
    //     c_rots.push_back(prepare_rots(c_mappings[i], 0, keys, mapping_bit));
    // }
    // report_timing("prepare_rots", false);

    // // process eq
    // for (int tbl_num = 1; tbl_num <= 2; tbl_num++)
    // {
    //     for (int eq_check_bit_width = 32; eq_check_bit_width <= 64; eq_check_bit_width *= 2)
    //     {
    //         if (tbl_num == 1 && eq_check_bit_width == 64)
    //             continue;
    //         report_timing("server:process_query", true);
    //         cout << "tbl_num: " << tbl_num << ", eq_check_bit_width: " << eq_check_bit_width << endl;
    //         vector<seal::Ciphertext> c_results;
    //         vector<vector<uint>> ind_tbl;
    //         for (int i = 0; i < tbl_num; i++)
    //         {
    //             vector<uint> tbl;
    //             for (int j = 0; j < poly_degree; ++j)
    //             {
    //                 tbl.push_back(rand() % (1 << eq_bit_size));
    //             }
    //             ind_tbl.push_back(tbl);
    //         }

    //         report_timing("server:process_query:emap_mul", true);
    //         vector<seal::Ciphertext> inds;
    //         vector<thread> threads;
    //         for (int i = 0; i < tbl_num; i++)
    //         {
    //             auto &ind_tbl_i = ind_tbl[i];
    //             threads.emplace_back([i, &ind_tbl_i, &rots, &keys, eq_check_bit_width, &evaluator, eq_bit_size]()
    //                                  {
    //                 vector<seal::Ciphertext> rets;
    //                 for (int j = 0; j < eq_check_bit_width / eq_bit_size; ++j)
    //                 {
    //                     // auto ret = mt_apply_emap(ind_tbl_i, rots, keys, max((1 << eq_bit_size)/8, 1), eq_bit_size);
    //                     auto ret = mt_apply_emap(ind_tbl_i, rots, keys, 2, eq_bit_size);
    //                     rets.push_back(ret);
    //                 }
    //                 for (int j = 1; j < eq_check_bit_width / eq_bit_size; ++j)
    //                 {
    //                     evaluator.multiply_inplace(rets[0], rets[j]);
    //                     evaluator.relinearize_inplace(rets[0], keys.relin_keys);
    //                 } });
    //         }
    //         for (auto &t : threads)
    //         {
    //             t.join();
    //         }
    //         report_timing("server:process_query:emap_mul", false);
    //         report_timing("server:process_query", false);
    //     }
    // }
}

inline uint64_t get_rand(int value_bit)
{
    assert(value_bit <= 64);
    return value_bit < 64 ? rand() % (1ULL << value_bit) : rand();
}

void test_eq(string mode, uint64_t v, size_t value_bit)
{
    cout << "v: " << v << ", value_bit: " << value_bit << endl;
    // This microbench tests the procedure to generate indicators for equality check of certain bits
    // It consists of the following steps
    // 1. Key generation
    // 2. The client prepares the query and encode it into ciphertexts
    // 3. The server process the ciphertext and generates the ciphertext indicators
    // We consider a single table with 2^14 entries as the basic testing unit.

    // Preparation: generate the table and setup the keys, the query is provided in the function parameters
    vector<uint64_t> tbl;
    for (int i = 0; i < slot_count; i++)
    {
        tbl.push_back(get_rand(value_bit));
    }
    tbl[42] = v; // for correctness test, guarantee that the value is in the table

    Keys keys;
    keys.generate();
    // HE setup
    auto ctx = create_ctx();
    auto batchEncoder = seal::BatchEncoder(ctx);
    auto evaluator = seal::Evaluator(create_ctx());
    auto encryptor = seal::Encryptor(ctx, keys.public_key);
    encryptor.set_secret_key(keys.secret_key.value());

    vector<seal::Ciphertext> c_query;
    // Client encode: using default eq_size8
    if (mode == "emap8" || mode == "emap1")
    {
        int eq_size = mode == "emap8" ? 8 : 1;
        assert(value_bit % eq_size == 0);
        assert(value_bit <= 512);
        // how many mappings do we need?
        size_t mapping_num = value_bit / eq_size;
        vector<uint64_t> slots;
        for (int i = 0; i < mapping_num; i++)
        {
            uint64_t current_bits = (v >> (i * eq_size)) % (1 << eq_size);
            for (int j = 0; j < (1 << eq_size); j++)
            {
                slots.push_back(j == current_bits ? 1 : 0);
            }
        }
        assert(slots.size() <= slot_count); // in general, one ciphertext is enough for 512 bits
        // encode the slots into plaintext
        seal::Plaintext plain;
        batchEncoder.encode(slots, plain);
        seal::Ciphertext c_query_first;
        encryptor.encrypt_symmetric(plain, c_query_first);
        c_query.push_back(c_query_first);
    }
    else if (mode == "retrieval")
    {
        size_t mapping_num = value_bit < poly_degree_log2 ? 1 : (1 << (value_bit - poly_degree_log2));
        for (int i = 0; i < mapping_num; i++)
        {
            vector<uint64_t> slots;
            for (int j = 0; j < poly_degree; j++)
            {
                slots.push_back(v == i * poly_degree + j ? 1 : 0);
            }
            seal::Plaintext plain;
            batchEncoder.encode(slots, plain);
            seal::Ciphertext c_query_i;
            encryptor.encrypt_symmetric(plain, c_query_i);
            c_query.push_back(c_query_i);
        }
    }
    else if (mode == "bitwise")
    {
        vector<uint64_t> slots;
        for (int i = 0; i < value_bit; i++)
        {
            slots.push_back((v >> i) & 1);
        }
        seal::Plaintext plain;
        batchEncoder.encode(slots, plain);
        seal::Ciphertext c_query_first;
        encryptor.encrypt_symmetric(plain, c_query_first);
        c_query.push_back(c_query_first);
    }
    else
    {
        cout << "Invalid mode: " << mode << endl;
        assert(false);
    }

    // ---------------------------------------------------------------------------------

    report_timing("process_query", true);
    seal::Ciphertext c_ind;
    // Server generate the indicator
    if (mode == "emap8" || mode == "emap1")
    {
        int eq_size = mode == "emap8" ? 8 : 1;
        vector<seal::Ciphertext> c_sub_inds;
        size_t mapping_num = value_bit / eq_size;
        for (int i = 0; i < mapping_num; i++)
        {
            auto c_rots = prepare_rots(c_query[0], (i * (1 << eq_size)), keys, eq_size);
            vector<uint> tbl_cur;
            for (int j = 0; j < poly_degree; j++)
            {
                tbl_cur.push_back((tbl[j] >> (i * eq_size)) % (1 << eq_size));
            }
            c_sub_inds.emplace_back(apply_emap(tbl_cur, c_rots, keys, eq_size));
        }
        // pair-wise reduce
        while (c_sub_inds.size() > 1)
        {
            vector<seal::Ciphertext> c_sub_inds_new;
            for (int i = 0; i < c_sub_inds.size() / 2; i++)
            {
                if (i * 2 + 1 < c_sub_inds.size())
                {
                    seal::Ciphertext c_tmp;
                    evaluator.multiply(c_sub_inds[2 * i], c_sub_inds[2 * i + 1], c_tmp);
                    evaluator.relinearize_inplace(c_tmp, keys.relin_keys);
                    c_sub_inds_new.push_back(c_tmp);
                }
                else
                {
                    c_sub_inds_new.push_back(c_sub_inds[2 * i]);
                }
            }
            c_sub_inds = c_sub_inds_new;
        }
        c_ind = c_sub_inds[0];
    }
    else if (mode == "retrieval")
    {
        vector<pair<int, seal::Ciphertext>> c_inds; // mark depth
        for (int i = 0; i < slot_count; ++i)
        // for (int i = 0; i < 64; ++i) // for debug only
        {
            // prepare single-record ind
            auto cur = tbl[i];
            seal::Ciphertext c_shift;
            auto &target_c = c_query[cur / poly_degree];
            int loc_from = cur % poly_degree;
            int loc_to = i;
            int row_offset = (loc_from - loc_to + poly_degree) % (poly_degree / 2);
            evaluator.rotate_rows(target_c, row_offset, keys.galois_keys, c_shift);
            if ((loc_from < poly_degree / 2) ^ (loc_to < poly_degree / 2))
            {
                evaluator.rotate_columns_inplace(c_shift, keys.galois_keys);
            }
            vector<uint64_t> mask(slot_count, 0);
            mask[i] = 1;
            seal::Plaintext plain;
            batchEncoder.encode(mask, plain);
            evaluator.multiply_plain_inplace(c_shift, plain);
            // merge
            c_inds.push_back({0, c_shift});
            while (c_inds.size() >= 2 && c_inds[c_inds.size() - 1].first == c_inds[c_inds.size() - 2].first)
            {
                c_inds[c_inds.size() - 2].first++;
                evaluator.add_inplace(c_inds[c_inds.size() - 2].second, c_inds[c_inds.size() - 1].second);
                c_inds.pop_back();
            }
        }
        assert(c_inds.size() == 1);
        c_ind = c_inds[0].second;
    }
    else if (mode == "bitwise")
    {
        vector<seal::Ciphertext> c_sub_inds;
        for (int i = 0; i < value_bit; ++i)
        {
            seal::Ciphertext c_orig;
            vector<uint64_t> mask(slot_count, 0);
            mask[i] = 1;
            seal::Plaintext plain_mask;
            batchEncoder.encode(mask, plain_mask);
            evaluator.multiply_plain(c_query[0], plain_mask, c_orig);
            evaluator.rotate_rows_inplace(c_orig, i, keys.galois_keys);

            vector<pair<int, seal::Ciphertext>> c_inds; // mark depth
            for (int j = 0; j < slot_count; ++j)
            // for (int j = 0; j < 64; ++j)
            {
                if (j != 0)
                {
                    evaluator.rotate_rows_inplace(c_orig, -1, keys.galois_keys);
                    if (j == poly_degree / 2)
                    {
                        evaluator.rotate_columns_inplace(c_orig, keys.galois_keys);
                    }
                }

                seal::Ciphertext c_flip;
                evaluator.negate(c_orig, c_flip);
                vector<uint64_t> one(slot_count, 0);
                one[j] = 1;
                seal::Plaintext plain_one;
                batchEncoder.encode(one, plain_one);
                evaluator.add_plain_inplace(c_flip, plain_one);

                auto cur = (tbl[j] >> i) & 1;
                seal::Ciphertext c_shift = cur == 1 ? c_orig : c_flip;

                c_inds.push_back({0, c_shift});
                while (c_inds.size() >= 2 && c_inds[c_inds.size() - 1].first == c_inds[c_inds.size() - 2].first)
                {
                    c_inds[c_inds.size() - 2].first++;
                    evaluator.add_inplace(c_inds[c_inds.size() - 2].second, c_inds[c_inds.size() - 1].second);
                    c_inds.pop_back();
                }
            }
            assert(c_inds.size() == 1);
            c_sub_inds.push_back(c_inds[0].second);
        }
        // pair-wise reduce
        while (c_sub_inds.size() > 1)
        {
            vector<seal::Ciphertext> c_sub_inds_new;
            for (int i = 0; i < c_sub_inds.size() / 2; i++)
            {
                if (i * 2 + 1 < c_sub_inds.size())
                {
                    seal::Ciphertext c_tmp;
                    evaluator.multiply(c_sub_inds[2 * i], c_sub_inds[2 * i + 1], c_tmp);
                    evaluator.relinearize_inplace(c_tmp, keys.relin_keys);
                    c_sub_inds_new.push_back(c_tmp);
                }
                else
                {
                    c_sub_inds_new.push_back(c_sub_inds[2 * i]);
                }
            }
            c_sub_inds = c_sub_inds_new;
        }
        c_ind = c_sub_inds[0];
    }
    else
    {
        cout << "Invalid mode: " << mode << endl;
        assert(false);
    }
    report_timing("process_query", false);

    // correctness
    // decrypt and check
    seal::Plaintext plain_ind;
    auto decryptor = seal::Decryptor(ctx, keys.secret_key.value());
    decryptor.decrypt(c_ind, plain_ind);
    vector<uint64_t> ind;
    batchEncoder.decode(plain_ind, ind);
    int counter = 0;
    for (int i = 0; i < ind.size(); i++)
    {
        if (ind[i] != 0 || tbl[i] == v)
        {
            cout << "tbl[" << i << "]: " << tbl[i] << "\t| ind[" << i << "]: " << ind[i] << endl;
            counter++;
            if (counter > 5)
            {
                cout << "..." << endl;
                break;
            }
        }
    }
}

int main(int argc, char *argv[])
{
    srand(time(NULL));
    // test_add();
    // test_mul();
    // test_rot();
    // test_cipher_size();
    // test_eq("emap", get_rand(8), 8);
    // test_eq(get_rand(32), 32);
    // test_eq(get_rand(48), 48);
    // test_eq(get_rand(64), 64);

    // test_eq("retrieval", get_rand(8), 8);
    // test_eq("retrieval", get_rand(16), 16);

    // test_eq("emap1", get_rand(8), 8);

    // parse argv
    int value_bit = atoi(argv[1]);

    // test_eq("bitwise", get_rand(value_bit), value_bit);
    // test_eq("bitwise", get_rand(16), 16);
    // test_eq("bitwise", get_rand(32), 32);
    // test_eq("bitwise", get_rand(48), 48);
    // test_eq("bitwise", get_rand(64), 64);

    test_eq("emap1", get_rand(value_bit), value_bit);
    return 0;
}

#pragma once

#include <bit>
#include <iostream>

#include "mpi.h"
#include "he.hpp"

template <typename T>
std::vector<T> get_local_tasks(const std::vector<T> &task)
{
    using namespace std;
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size); // Get the number of processes

    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); // Get the rank of the process

    int task_size = task.size();
    int local_task_size = (task_size + world_size - 1) / world_size;
    int local_task_start = world_rank * local_task_size;
    int local_task_end = (world_rank + 1) * local_task_size;

    if (local_task_start > task_size)
    {
        local_task_start = task_size;
    }
    if (local_task_end > task_size)
    {
        local_task_end = task_size;
    }
    // cout << "world_rank: " << world_rank << " local_task_start: " << local_task_start << " local_task_end: " << local_task_end << endl;

    vector<T> local_task(local_task_end - local_task_start);
    if (local_task_start < local_task_end)
    {
        copy(task.begin() + local_task_start, task.begin() + local_task_end, local_task.begin());
    }
    // cout << "world_rank: " << world_rank << " local_task.size(): " << local_task.size() << endl;
    return local_task;
}

template <typename T>
std::vector<T> get_two_aligned_local_tasks(const std::vector<T> &task)
{
    using namespace std;
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size); // Get the number of processes

    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); // Get the rank of the process

    // only keep power of 2 world_size
    int task_size = task.size();
    unsigned expanded_task_size = std::bit_ceil((unsigned)task.size());
    unsigned used_world_size = std::min(std::bit_floor((unsigned)world_size), expanded_task_size);
    if (world_rank >= used_world_size)
    {
        return vector<T>(0);
    }

    int local_task_size = expanded_task_size / used_world_size;
    int local_task_start = world_rank * local_task_size;
    int local_task_end = (world_rank + 1) * local_task_size;
    if (local_task_start > task_size)
    {
        local_task_start = task_size;
    }
    if (local_task_end > task_size)
    {
        local_task_end = task_size;
    }

    vector<T> local_task(local_task_end - local_task_start);
    if (local_task_start < local_task_end)
    {
        copy(task.begin() + local_task_start, task.begin() + local_task_end, local_task.begin());
    }
    // cout << "world_rank: " << world_rank << " local_task.size(): " << local_task.size() << endl;
    return local_task;
}

std::stringstream mpi_sstream_Gatherv_concat(const std::stringstream &s)
{
    using namespace std;
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size); // Get the number of processes

    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); // Get the rank of the process

    int s_size = s.str().size();

    // cout << "world_rank: " << world_rank << " s_size: " << s_size << endl;

    vector<int> s_sizes(world_size);
    MPI_Gather(&s_size, 1, MPI_INT, s_sizes.data(), 1, MPI_INT, 0, MPI_COMM_WORLD);

    vector<int> s_displs(world_size);
    if (world_rank == 0)
    {
        s_displs[0] = 0;
        for (int i = 1; i < world_size; i++)
        {
            s_displs[i] = s_displs[i - 1] + s_sizes[i - 1];
        }
    }

    int s_total_size;
    if (world_rank == 0)
    {
        s_total_size = s_displs[world_size - 1] + s_sizes[world_size - 1];
    }
    MPI_Bcast(&s_total_size, 1, MPI_INT, 0, MPI_COMM_WORLD);

    vector<char> s_total(s_total_size);
    MPI_Gatherv(s.str().data(), s_size, MPI_CHAR, s_total.data(), s_sizes.data(), s_displs.data(), MPI_CHAR, 0, MPI_COMM_WORLD);

    stringstream sstream;
    if (world_rank == 0)
    {
        sstream.write(s_total.data(), s_total_size);
    }

    // cout << "world_rank: " << world_rank << " s_total_size: " << s_total_size << endl;
    return sstream;
}

std::stringstream mpi_sstream_Allgatherv_concat(const std::stringstream &s)
{
    using namespace std;
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size); // Get the number of processes

    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); // Get the rank of the process

    uint64_t s_size = s.str().size();

    // cout << "world_rank: " << world_rank << " s_size: " << s_size << endl;

    vector<uint64_t> s_sizes(world_size);
    MPI_Allgather(&s_size, 1, MPI_UINT64_T, s_sizes.data(), 1, MPI_UINT64_T, MPI_COMM_WORLD);
    uint64_t s_total_size = 0;
    for (int i = 0; i < world_size; i++)
    {
        s_total_size += s_sizes[i];
    }
    vector<char> s_total(s_total_size);
    vector<uint64_t> s_start(world_size, 0);
    uint64_t total_start = 0;

    // handle the case when s_total_size is larger than 2^31 - 1
    while (total_start < s_total_size)
    {
        vector<int> s_to_send(world_size);
        vector<int> s_displs(world_size);
        uint64_t quota = (1ULL << 31) - 1;
        s_displs[0] = 0;
        for (int i = 0; i < world_size; i++)
        {
            uint64_t s_remain = s_sizes[i] - s_start[i];
            s_to_send[i] = s_remain > quota ? quota : s_remain;
            quota -= s_to_send[i];
            if (i > 0)
                s_displs[i] = s_displs[i - 1] + s_to_send[i - 1];
        }
        MPI_Allgatherv(s.str().data() + s_start[world_rank], s_to_send[world_rank],
                       MPI_CHAR, s_total.data() + total_start, s_to_send.data(), s_displs.data(), MPI_CHAR, MPI_COMM_WORLD);
        for (int i = 0; i < world_size; i++)
        {
            s_start[i] += s_to_send[i];
            total_start += s_to_send[i];
        }
        if (total_start < s_total_size)
        {
            cout << "Multi-round allgatherv triggered." << endl;
        }
    }
    stringstream sstream;
    sstream.write(s_total.data(), s_total_size);

    // cout << "world_rank: " << world_rank << " s_total_size: " << s_total_size << endl;
    return sstream;
}

void mpi_sstream_Bcast(std::stringstream &s)
{
    using namespace std;
    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); // Get the rank of the process
    int s_size = s.str().size();
    MPI_Bcast(&s_size, 1, MPI_INT, 0, MPI_COMM_WORLD);
    vector<char> s_total(s_size);
    if (world_rank == 0)
    {
        s_total.assign(istreambuf_iterator<char>(s), istreambuf_iterator<char>());
    }
    MPI_Bcast(s_total.data(), s_size, MPI_CHAR, 0, MPI_COMM_WORLD);
    if (world_rank != 0)
    {
        s.write(s_total.data(), s_size);
    }
}

std::vector<std::vector<seal::Ciphertext>> mpi_cipher_vec_Allgather_concat(const std::vector<std::vector<seal::Ciphertext>> &v, size_t internal_size)
{
    using namespace std;
    // reuse mpi_sstream_Allgatherv
    stringstream sstream;
    report_timing("mpi_cipher_vec_Allgather_concat:save", true);
    for (const auto &c_vec : v)
    {
        for (const auto &c : c_vec)
        {
            c.save(sstream);
        }
    }
    report_timing("mpi_cipher_vec_Allgather_concat:save", false);

    report_timing("mpi_cipher_vec_Allgather_concat:mpi", true);
    stringstream sstream_total = mpi_sstream_Allgatherv_concat(sstream);
    report_timing("mpi_cipher_vec_Allgather_concat:mpi", false);

    vector<vector<seal::Ciphertext>> v_total(0);
    auto ctx = create_ctx();
    report_timing("mpi_cipher_vec_Allgather_concat:load", true);
    size_t end = sstream_total.str().size();
    while (sstream_total.tellg() != end)
    {
        report_timing("mpi_cipher_vec_Allgather_concat:load_once", true);
        vector<seal::Ciphertext> c_vec(0);
        for (size_t i = 0; i < internal_size; i++)
        {
            seal::Ciphertext c;
            c.unsafe_load(ctx, sstream_total);
            c_vec.push_back(c);
        }
        v_total.push_back(c_vec);
        report_timing("mpi_cipher_vec_Allgather_concat:load_once", false);
    }
    report_timing("mpi_cipher_vec_Allgather_concat:load", false);
    return v_total;
}

std::vector<seal::Ciphertext> mpi_cipher_Gather_concat(const std::vector<seal::Ciphertext> &v)
{
    using namespace std;
    // reuse mpi_sstream_Gatherv
    stringstream sstream;
    for (const auto &c : v)
    {
        c.save(sstream);
    }

    stringstream sstream_total = mpi_sstream_Gatherv_concat(sstream);
    vector<seal::Ciphertext> v_total(0);
    auto ctx = create_ctx();
    sstream_total.seekg(0);
    size_t end = sstream_total.str().size();
    while (sstream_total.tellg() != end)
    {
        seal::Ciphertext c;
        c.unsafe_load(ctx, sstream_total);
        v_total.push_back(c);
    }
    return v_total;
}

std::vector<seal::Ciphertext> mpi_cipher_Allgather_concat(const std::vector<seal::Ciphertext> &v)
{
    using namespace std;
    // reuse mpi_sstream_Allgatherv
    stringstream sstream;
    for (const auto &c : v)
    {
        c.save(sstream);
    }

    stringstream sstream_total = mpi_sstream_Allgatherv_concat(sstream);
    vector<seal::Ciphertext> v_total(0);
    auto ctx = create_ctx();
    sstream_total.seekg(0);
    size_t end = sstream_total.str().size();
    while (sstream_total.tellg() != end)
    {
        seal::Ciphertext c;
        c.unsafe_load(ctx, sstream_total);
        v_total.push_back(c);
    }
    return v_total;
}

void mpi_keys_Bcast(Keys &keys)
{
    using namespace std;
    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); // Get the rank of the process
    stringstream pk_ss;
    stringstream sk_ss;
    if (world_rank == 0)
    {
        pk_ss = keys.saveProcessingKeys();
        sk_ss = keys.saveSecretKey();
    }
    mpi_sstream_Bcast(pk_ss);
    mpi_sstream_Bcast(sk_ss);
    if (world_rank != 0)
    {
        keys.loadProcessingKeys(pk_ss);
        keys.loadSecretKey(sk_ss);
    }
}

void mpi_cipher_Bcast(seal::Ciphertext &c)
{
    using namespace std;
    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); // Get the rank of the process
    stringstream c_ss;
    if (world_rank == 0)
    {
        c.save(c_ss);
    }
    mpi_sstream_Bcast(c_ss);
    auto ctx = create_ctx();
    if (world_rank != 0)
    {
        c.unsafe_load(ctx, c_ss);
    }
}

seal::Ciphertext mpi_merge_cipher_sums(
    size_t task_size,
    std::vector<seal::Ciphertext> &cs, // local ciphers
    const Keys &keys,
    int naive_agg_round = -1)
{
    // sum up multiple ciphertext and merge them into one ciphertext
    // eg. [1, 2, 3, 4], [5, 6, 7, 8] --> [10, 26, 0, 0]
    // note that this operation consumes the input ciphertexts
    using namespace std;
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size); // Get the number of processes
    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); // Get the rank of the process

    auto ctx = create_ctx();
    auto batchEncoder = seal::BatchEncoder(ctx);
    auto encryptor = seal::Encryptor(ctx, keys.public_key);
    auto evaluator = seal::Evaluator(ctx);

    seal::Plaintext zero_plain;
    std::vector<uint64_t> zero_vec(slot_count, 0ULL);
    batchEncoder.encode(zero_vec, zero_plain);
    seal::Ciphertext zero_c;
    encryptor.encrypt(zero_plain, zero_c);

    unsigned expanded_task_size = std::bit_ceil((unsigned)task_size);
    unsigned used_world_size = std::min(std::bit_floor((unsigned)world_size), expanded_task_size);

    // make sure one cipher has enough slots to hold all the sums
    assert(expanded_task_size <= (1 << poly_degree_log2));

    // // additionally --> make sure the noise budget is enough
    // assert(expanded_task_size <= (1 << 9));  // no need, naive agg is added to overcome the noise budget shortage
    if (naive_agg_round == -1)
        naive_agg_round = std::max(0, (int)std::bit_width((unsigned)expanded_task_size) - 1 - 9);
    int local_agg_round = std::max(0, (int)std::bit_width(expanded_task_size / used_world_size) - 1);

    int i = 0;
    // naive agg to save noise budget
    for (; i < naive_agg_round; ++i)
    {
        if (i == local_agg_round)
        {
            // collect the ciphers for global steps
            cs = mpi_cipher_Gather_concat(cs);
            if (world_rank != 0)
            {
                return zero_c;
            }
        }
        int offset = (1 << i);
        for (int j = 0; j < cs.size(); ++j)
        {
            seal::Ciphertext c_after_rotation;
            if (j & (1 << i))
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
    // naive agg - merge in one step
    if (naive_agg_round > 0)
    {
        size_t naive_agg_round_pow_2 = 1 << naive_agg_round;
        for (int j = 0; j < naive_agg_round_pow_2; ++j)
        {
            // construct the mask
            std::vector<uint64_t> mask(slot_count, 0ULL);
            for (int k = 0; k < slot_count / naive_agg_round_pow_2; ++k)
            {
                mask[k * naive_agg_round_pow_2 + j] = 1ULL;
            }
            seal::Plaintext mask_plain;
            batchEncoder.encode(mask, mask_plain);
            // add in place for all cs in the correct location
            for (int k = 0; k + j < cs.size(); k += naive_agg_round_pow_2)
            {
                evaluator.multiply_plain_inplace(cs[k + j], mask_plain);
                evaluator.relinearize_inplace(cs[k + j], keys.relin_keys);
                if (j > 0)
                    evaluator.add_inplace(cs[k], cs[k + j]);
            }
        }
        vector<seal::Ciphertext> new_cs;
        for (int j = 0; j < cs.size(); j += naive_agg_round_pow_2)
        {
            new_cs.push_back(cs[j]);
        }
        cs = new_cs;
    }
    // local agg
    for (; i < poly_degree_log2; ++i)
    {
        if (i == local_agg_round)
        {
            // collect the ciphers for global steps
            cs = mpi_cipher_Gather_concat(cs);
            if (world_rank != 0)
            {
                return zero_c;
            }
        }
        // cout << "world_rank: " << world_rank << " i: " << i << " cs.size(): " << cs.size() << endl;
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
        if (i >= local_agg_round && cs.size() == 1)
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

#include <iostream>
#include <bit>
#include <fstream>
#include <algorithm>
#include <cassert>

#include "myutil.hpp"
#include "he.hpp"
#include "enc.hpp"
#include "emap.hpp"
#include "mpi_he.hpp"

std::mutex mtx;
std::vector<std::thread> threads;
int MAX_THREAD = 128;

void _debug_cs_min_budget(std::string hint_text, std::vector<seal::Ciphertext> &cs, Keys &keys)
{
    seal::Decryptor decryptor(create_ctx(), keys.secret_key.value());
    int min_budget = 0x7fffffff;
    for (auto &c : cs)
    {
        auto noise_budget = decryptor.invariant_noise_budget(c);
        min_budget = std::min(min_budget, noise_budget);
    }
    std::cout << "! Noise budgets at stage: [" << hint_text << "] | " << min_budget << std::endl;
}

int main(int argc, char *argv[])
{
    using namespace std;
    assert(argc >= 2);
    string plan_folder = argv[1];
    if (plan_folder.back() != '/')
    {
        plan_folder += "/";
    }
    if (argc >= 3)
    {
        MAX_THREAD = stoi(argv[2]);
    }
    cout << "Reading plan from: " << plan_folder << endl;
    string FILENAME_CLIENT_MAPPINGS = "client.mappings.txt";
    string FILENAME_PREPARE_ROTS = "server.prepare_rots.csv";
    string FILENAME_READ_IND_TBL = "server.read_ind_tbl.csv";
    string FILENAME_CALC_IND_TASK = "server.calc_ind.csv";
    string FILENAME_CALC_IND_OPS = "server.calc_ind_ops.txt";
    string FILENAME_AGG = "server.agg.csv";
    string TASK_PREFIX_EMAP = "emap";
    string TASK_PREFIX_CALC_IND = "calc";

    int PARALLEL_FACTOR_ROT = -1;  // -1 means auto
    int PARALLEL_FACTOR_EMAP = -1; // -1 means auto
    int MERGE_OPT_FACTOR = -1;

    // Client & Server: key setup
    report_timing("together:key_setup", true);
    Keys keys;
    {
        keys.generate(); // in practice, the server should keep a copy without the secret key
    }
    report_timing("together:key_setup", false);

    // Client: encrypt query
    vector<seal::Ciphertext> c_queries;
    report_timing("client:encrypt_query", true);
    {
        auto ctx = create_ctx();
        auto batchEncoder = seal::BatchEncoder(ctx);
        auto encryptor = seal::Encryptor(ctx, keys.public_key);
        encryptor.set_secret_key(keys.secret_key.value());
        auto decryptor = seal::Decryptor(ctx, keys.secret_key.value());

        string client_mapping_loc = plan_folder + FILENAME_CLIENT_MAPPINGS;
        cout << "From: " << client_mapping_loc << endl;
        ifstream fin(client_mapping_loc);
        if (!fin)
        {
            cerr << "Cannot open file: " << client_mapping_loc << endl;
            exit(1);
        }
        int c_query_num;
        fin >> c_query_num;
        c_queries.resize(c_query_num);
        int c_value_total = 0;
        for (int i = 0; i < c_query_num; i++)
        {
            int value_cnt;
            fin >> value_cnt;
            vector<uint64_t> mapping(slot_count, 0);
            for (int j = 0; j < value_cnt; j++)
            {
                fin >> mapping[j];
            }
            c_value_total += value_cnt;
            seal::Plaintext plain;
            batchEncoder.encode(mapping, plain);
            encryptor.encrypt_symmetric(plain, c_queries[i]);
        }
        cout << "Loaded " << c_query_num << " query mappings with " << c_value_total << " values in total" << endl;
        _debug_cs_min_budget("after_encrypt", c_queries, keys);
    }
    report_timing("client:encrypt_query", false);

    // Server: process query
    vector<seal::Ciphertext>
        c_results;
    vector<pair<size_t, string>> tags;
    size_t result_tail = 0;
    report_timing("server:process_query", true);
    {
        // setup
        report_timing("server:process_query:setup", true);
        auto ctx = create_ctx();
        auto batchEncoder = seal::BatchEncoder(ctx);
        auto encryptor = seal::Encryptor(ctx, keys.public_key);
        auto evaluator = seal::Evaluator(ctx);
        seal::Plaintext zero_plain;
        std::vector<uint64_t> zero_vec(slot_count, 0ULL);
        batchEncoder.encode(zero_vec, zero_plain);
        seal::Ciphertext zero_c;
        encryptor.encrypt(zero_plain, zero_c);
        report_timing("server:process_query:setup", false);

        // Stage 1. prepare rotation
        report_timing("server:process_query:prepare_rots", true);
        string prepare_rots_loc = plan_folder + FILENAME_PREPARE_ROTS;
        ifstream fin_prepare_rots(prepare_rots_loc);
        if (!fin_prepare_rots)
        {
            cerr << "Cannot open file: " << prepare_rots_loc << endl;
            exit(1);
        }
        int rot_num;
        fin_prepare_rots >> rot_num;
        // skip the empty line
        string tmp;
        getline(fin_prepare_rots, tmp);
        vector<vector<seal::Ciphertext>> c_rots(rot_num);
        // format: [task_id] [cipher_id] [offset] [width]
        typedef tuple<string, int, int, int> rot_task;
        vector<rot_task> rot_tasks(rot_num);
        unordered_map<string, size_t> idx_rot_tasks;
        for (int i = 0; i < rot_num; i++)
        {
            string task_id;
            int cipher_id, offset, width;
            getline(fin_prepare_rots, task_id, ',');
            string tmp;
            getline(fin_prepare_rots, tmp, ',');
            cipher_id = stoi(tmp);
            getline(fin_prepare_rots, tmp, ',');
            offset = stoi(tmp);
            getline(fin_prepare_rots, tmp, '\n');
            width = stoi(tmp);
            // cout << "Task: " << task_id << " Ciphertext: " << cipher_id << " Offset: " << offset << " Width: " << width << endl;
            rot_tasks[i] = make_tuple(task_id, cipher_id, offset, width);
            idx_rot_tasks[task_id] = i;
        }
        if (PARALLEL_FACTOR_ROT == -1)
        {
            PARALLEL_FACTOR_ROT = min(16, max(1, (int)std::bit_ceil((size_t)(MAX_THREAD / rot_num))));
            // 32 is slower than 16 even for small workload
        }
        for (int i = 0; i < rot_num; ++i)
        {
            string task_id;
            int cipher_id, offset, width;
            tie(task_id, cipher_id, offset, width) = rot_tasks[i];
            threads.push_back(
                thread([&, i, task_id, cipher_id, offset, width]()
                       { c_rots[i] = mt_prepare_rots(c_queries[cipher_id], offset, width, PARALLEL_FACTOR_ROT, keys); }));
            if (threads.size() >= MAX_THREAD)
            {
                for (auto &t : threads)
                    t.join();
                threads.clear();
            }
        }
        for (auto &t : threads)
            t.join();
        threads.clear();
        report_timing("server:process_query:prepare_rots", false);
        _debug_cs_min_budget("after_prepare_rots", c_rots[0], keys);

        // Stage 2. read indicator table
        report_timing("server:process_query:read_ind_tbl", true);
        string read_ind_tbl_loc = plan_folder + FILENAME_READ_IND_TBL;
        ifstream fin_read_ind_tbl(read_ind_tbl_loc);
        if (!fin_read_ind_tbl)
        {
            cerr << "Cannot open file: " << read_ind_tbl_loc << endl;
            exit(1);
        }
        int ind_tbl_num;
        fin_read_ind_tbl >> ind_tbl_num;
        // skip the empty line
        getline(fin_read_ind_tbl, tmp);
        unordered_map<string, size_t> all_group_size;
        unordered_map<string, size_t> all_cipher_cnt;
        unordered_map<string, vector<int>> all_ind_tbl;
        // format: [task_id] [file_path] [group_name] [col_name] [expected_record_cnt]
        for (int i = 0; i < ind_tbl_num; i++)
        {
            string task_id, file_path, group_name, col_name;
            int expected_record_cnt;
            getline(fin_read_ind_tbl, task_id, ',');
            getline(fin_read_ind_tbl, file_path, ',');
            getline(fin_read_ind_tbl, group_name, ',');
            getline(fin_read_ind_tbl, col_name, ',');
            getline(fin_read_ind_tbl, tmp, '\n');
            expected_record_cnt = stoi(tmp);
            // cout << "Task: " << task_id << " File: " << file_path << " Group: " << group_name << " Column: " << col_name << " Expected Record: " << expected_record_cnt << endl;
            ifstream fin_ind_tbl(file_path);
            if (!fin_ind_tbl)
            {
                cerr << "Cannot open file: " << file_path << endl;
                exit(1);
            }
            vector<int> ind_tbl;
            for (int j = 0; j < expected_record_cnt; j++)
            {
                int val;
                fin_ind_tbl >> val;
                ind_tbl.push_back(val);
            }
            all_ind_tbl[task_id] = ind_tbl;
            all_group_size[group_name] = expected_record_cnt;
            all_cipher_cnt[group_name] = (expected_record_cnt + slot_count - 1) / slot_count;
        }
        report_timing("server:process_query:read_ind_tbl", false);

        // Stage 3. apply elementwise mapping
        report_timing("server:process_query:emap", true);
        string emap_loc = plan_folder + "server.emap.csv";
        ifstream fin_emap(emap_loc);
        if (!fin_emap)
        {
            cerr << "Cannot open file: " << emap_loc << endl;
            exit(1);
        }
        int emap_num;
        fin_emap >> emap_num;
        // skip the empty line
        getline(fin_emap, tmp);
        vector<seal::Ciphertext> c_mapped(emap_num);
        // format: [task_id] [rot_task_id] [ind_tbl_id] [batch_id] [starting_bit]
        typedef tuple<string, string, string, int, int> emap_task;
        vector<emap_task> emap_tasks(emap_num);
        unordered_map<string, size_t> idx_emap_tasks;
        for (int i = 0; i < emap_num; i++)
        {
            string task_id, rot_task_id, ind_tbl_id;
            int batch_id, starting_bit;
            getline(fin_emap, task_id, ',');
            getline(fin_emap, rot_task_id, ',');
            getline(fin_emap, ind_tbl_id, ',');
            getline(fin_emap, tmp, ',');
            batch_id = stoi(tmp);
            getline(fin_emap, tmp, '\n');
            starting_bit = stoi(tmp);
            // cout << "Task: " << task_id << " Rot: " << rot_task_id << " IndTbl: " << ind_tbl_id << " Batch: " << batch_id << " Starting Bit: " << starting_bit << endl;
            emap_tasks[i] = make_tuple(task_id, rot_task_id, ind_tbl_id, batch_id, starting_bit);
            idx_emap_tasks[task_id] = i;
        }
        if (PARALLEL_FACTOR_EMAP == -1)
        {
            PARALLEL_FACTOR_EMAP = min(16, max(1, (int)std::bit_ceil((size_t)(MAX_THREAD / emap_num))));
        }
        for (int i = 0; i < emap_num; ++i)
        {
            string task_id, rot_task_id, ind_tbl_id;
            int batch_id, starting_bit;
            tie(task_id, rot_task_id, ind_tbl_id, batch_id, starting_bit) = emap_tasks[i];
            vector<int> &ind_tbl = all_ind_tbl[ind_tbl_id];
            vector<seal::Ciphertext> &c_r = c_rots[idx_rot_tasks[rot_task_id]];
            threads.push_back(
                thread([&, i, task_id, rot_task_id, ind_tbl_id, batch_id, starting_bit]()
                       {
                        size_t start = batch_id * slot_count;
                        size_t end = min((batch_id + 1) * slot_count, ind_tbl.size());
                        vector<uint> v(slot_count, 0);
                        for (size_t i = start; i < end; i++)
                        {
                            v[i - start] = (ind_tbl[i] >> starting_bit) & 0xFF;
                        } 
                        c_mapped[i] = mt_apply_emap(v, c_r, keys, PARALLEL_FACTOR_EMAP, 8); }));
            if (threads.size() >= MAX_THREAD)
            {
                for (auto &t : threads)
                    t.join();
                threads.clear();
            }
        }
        for (auto &t : threads)
            t.join();
        threads.clear();
        report_timing("server:process_query:emap", false);
        _debug_cs_min_budget("after_emap", c_mapped, keys);

        // Stage 4. run boolean circuit & apply ind mask
        report_timing("server:process_query:calc_ind", true);
        string calc_ind_ops_loc = plan_folder + FILENAME_CALC_IND_OPS;
        ifstream fin_calc_ind_ops(calc_ind_ops_loc);
        if (!fin_calc_ind_ops)
        {
            cerr << "Cannot open file: " << calc_ind_ops_loc << endl;
            exit(1);
        }
        int calc_ind_var_in;
        fin_calc_ind_ops >> calc_ind_var_in;
        int calc_ind_var_all;
        fin_calc_ind_ops >> calc_ind_var_all;
        // skip the empty line
        getline(fin_calc_ind_ops, tmp);
        vector<pair<int, int>> op_cipher_id_and_offset(calc_ind_var_in);
        for (int i = 0; i < calc_ind_var_in; i++)
        {
            int cipher_id, offset;
            fin_calc_ind_ops >> cipher_id >> offset;
            op_cipher_id_and_offset[i] = make_pair(cipher_id, offset);
        }
        int calc_ind_op_num;
        fin_calc_ind_ops >> calc_ind_op_num;
        // skip the empty line
        getline(fin_calc_ind_ops, tmp);
        vector<tuple<string, int, int, int>> calc_ind_ops(calc_ind_op_num);
        for (int i = 0; i < calc_ind_op_num; i++)
        {
            string op;
            int arg0, arg1, arg2;
            getline(fin_calc_ind_ops, op, ' ');
            getline(fin_calc_ind_ops, tmp, ' ');
            arg0 = stoi(tmp);
            getline(fin_calc_ind_ops, tmp, ' ');
            arg1 = stoi(tmp);
            getline(fin_calc_ind_ops, tmp, '\n');
            arg2 = stoi(tmp);
            calc_ind_ops[i] = make_tuple(op, arg0, arg1, arg2);
            // cout << "Op: " << op << " Arg0: " << arg0 << " Arg1: " << arg1 << " Arg2: " << arg2 << endl;
        }
        string calc_ind_loc = plan_folder + FILENAME_CALC_IND_TASK;
        ifstream fin_calc_ind(calc_ind_loc);
        if (!fin_calc_ind)
        {
            cerr << "Cannot open file: " << calc_ind_loc << endl;
            exit(1);
        }
        int calc_ind_num;
        fin_calc_ind >> calc_ind_num;
        // skip the empty line
        getline(fin_calc_ind, tmp);
        vector<seal::Ciphertext> c_inds(calc_ind_num);
        // format: [task_id] [group_id] [batch_id]
        typedef tuple<string, string, int> calc_ind_task;
        vector<calc_ind_task> calc_ind_tasks(calc_ind_num);
        unordered_map<string, size_t> idx_calc_ind_tasks;
        for (int i = 0; i < calc_ind_num; i++)
        {
            string task_id, group_id;
            int batch_id;
            getline(fin_calc_ind, task_id, ',');
            getline(fin_calc_ind, group_id, ',');
            getline(fin_calc_ind, tmp, '\n');
            batch_id = stoi(tmp);
            // cout << "Task: " << task_id << " Group: " << group_id << " Batch: " << batch_id << endl;
            calc_ind_tasks[i] = make_tuple(task_id, group_id, batch_id);
            idx_calc_ind_tasks[task_id] = i;
        }
        for (int i = 0; i < calc_ind_num; ++i)
        {
            string task_id, group_id;
            int batch_id;
            tie(task_id, group_id, batch_id) = calc_ind_tasks[i];
            threads.push_back(
                thread([&, i, task_id, group_id, batch_id]()
                       {
                           vector<int> var_in_idx(calc_ind_var_in);
                           for (int j = 0; j < calc_ind_var_in; j++)
                           {
                               string emap_task_id = TASK_PREFIX_EMAP + "-" + to_string(op_cipher_id_and_offset[j].first) + "-" + to_string(op_cipher_id_and_offset[j].second) + "-" + group_id + "-" + to_string(batch_id);
                               //    cout << "emap_task_id: " << emap_task_id << endl;
                               var_in_idx[j] = idx_emap_tasks[emap_task_id];
                           }
                           vector<seal::Ciphertext> c_var(calc_ind_var_all - calc_ind_var_in);
                           for (int j = 0; j < calc_ind_op_num; ++j)
                           {
                               string op;
                               int arg0, arg1, arg2;
                               tie(op, arg0, arg1, arg2) = calc_ind_ops[j];
                               if (op == "mul")
                               {
                                   seal::Ciphertext &c_arg0 = (arg0 < calc_ind_var_in) ? c_mapped[var_in_idx[arg0]] : c_var[arg0 - calc_ind_var_in];
                                   seal::Ciphertext &c_arg1 = (arg1 < calc_ind_var_in) ? c_mapped[var_in_idx[arg1]] : c_var[arg1 - calc_ind_var_in];
                                   seal::Ciphertext &c_arg2 = (arg2 < calc_ind_var_in) ? c_mapped[var_in_idx[arg2]] : c_var[arg2 - calc_ind_var_in];
                                   evaluator.multiply(c_arg0, c_arg1, c_arg2);
                                   evaluator.relinearize_inplace(c_arg2, keys.relin_keys);
                               }
                               else if (op == "neg_inplace")
                               {
                                   seal::Ciphertext &c_arg0 = (arg0 < calc_ind_var_in) ? c_mapped[var_in_idx[arg0]] : c_var[arg0 - calc_ind_var_in];
                                   evaluator.negate_inplace(c_arg0);
                               }
                               else if (op == "add_inplace")
                               {
                                   seal::Ciphertext &c_arg0 = (arg0 < calc_ind_var_in) ? c_mapped[var_in_idx[arg0]] : c_var[arg0 - calc_ind_var_in];
                                   seal::Ciphertext &c_arg1 = (arg1 < calc_ind_var_in) ? c_mapped[var_in_idx[arg1]] : c_var[arg1 - calc_ind_var_in];
                                   evaluator.add_inplace(c_arg0, c_arg1);
                               }
                               else
                               {
                                   cerr << "Unknown operation: " << op << endl;
                                   exit(1);
                               }
                           }

                           // apply ind mask
                           if (batch_id == all_cipher_cnt[group_id] - 1 && all_group_size[group_id] % slot_count != 0)
                           {
                               vector<uint64_t> ind_mask(slot_count, 0);
                               for (int j = 0; j < slot_count; ++j)
                               {
                                   if (batch_id * slot_count + j < all_group_size[group_id])
                                   {
                                       ind_mask[j] = 1;
                                   }
                               }
                               seal::Plaintext plain;
                               batchEncoder.encode(ind_mask, plain);
                               evaluator.multiply_plain_inplace(c_var[calc_ind_var_all - calc_ind_var_in - 1], plain);
                           }

                           c_inds[i] = c_var[calc_ind_var_all - calc_ind_var_in - 1]; // the output is the last one
                           // print to check here:
                           //    seal::Decryptor decryptor(ctx, keys.secret_key.value());
                           //    seal::Plaintext plain;
                           //    decryptor.decrypt(c_inds[i], plain);
                           //    vector<uint64_t> v;
                           //    batchEncoder.decode(plain, v);
                           //    mtx.lock();
                           //    cout << "Task: " << task_id << " Group: " << group_id << " Batch: " << batch_id << endl;
                           //    cout << "rhs:" << all_cipher_cnt[group_id] - 1 << endl;
                           //    cout << "Ind_tbl size: " << all_group_size[group_id] << endl;
                           //    int sum = 0;
                           //    for (int j = 0; j < slot_count; j++)
                           //    {
                           //          sum += v[j];
                           //    }
                           //    cout << "Sum: " << sum << endl;
                           //    mtx.unlock();
                       }));
            if (threads.size() >= MAX_THREAD)
            {
                for (auto &t : threads)
                    t.join();
                threads.clear();
            }
        }
        for (auto &t : threads)
            t.join();
        threads.clear();
        report_timing("server:process_query:calc_ind", false);
        _debug_cs_min_budget("after_calc_ind", c_inds, keys);

        // Stage 5. Read aggregation table and extract
        report_timing("server:process_query:agg", true);
        string agg_loc = plan_folder + FILENAME_AGG;
        ifstream fin_agg(agg_loc);
        if (!fin_agg)
        {
            cerr << "Cannot open file: " << agg_loc << endl;
            exit(1);
        }
        int agg_num;
        fin_agg >> agg_num;
        // skip the empty line
        getline(fin_agg, tmp);
        vector<seal::Ciphertext> c_agg(agg_num);
        // format: [task_id] [group_id] [batch_id] [is_cnt] [col] [file_path] [starting_bit]
        typedef tuple<string, string, int, bool, string, string, int> agg_task;
        vector<agg_task> agg_tasks(agg_num);
        unordered_map<string, size_t> idx_agg_tasks;
        unordered_map<string, std::vector<u_int64_t>> all_agg_tbls;
        bool agg_noise_printed = false;
        for (int i = 0; i < agg_num; i++)
        {
            string task_id, group_id, agg_col, file_path;
            int batch_id, starting_bit;
            bool is_cnt;
            getline(fin_agg, task_id, ',');
            getline(fin_agg, group_id, ',');
            getline(fin_agg, tmp, ',');
            batch_id = stoi(tmp);
            getline(fin_agg, tmp, ',');
            is_cnt = stoi(tmp);
            getline(fin_agg, agg_col, ',');
            getline(fin_agg, file_path, ',');
            getline(fin_agg, tmp, '\n');
            starting_bit = stoi(tmp);
            // cout << "Task: " << task_id << " Group: " << group_id << " Batch: " << batch_id << " IsCnt: " << is_cnt << " File: " << file_path << " Starting Bit: " << starting_bit << endl;
            agg_tasks[i] = make_tuple(task_id, group_id, batch_id, is_cnt, agg_col, file_path, starting_bit);
            idx_agg_tasks[task_id] = i;
            // read agg table
            if (is_cnt || all_agg_tbls.count(file_path) > 0)
                continue;
            ifstream fin_agg_tbl(file_path);
            if (!fin_agg_tbl)
            {
                cerr << "Cannot open file: " << file_path << endl;
                exit(1);
            }
            vector<u_int64_t> agg_tbl;
            double x;
            while (fin_agg_tbl >> x)
            {
                agg_tbl.push_back(d42_to_u64(x));
            }
            all_agg_tbls[file_path] = agg_tbl;
        }
        for (int i = 0; i < agg_num; ++i)
        {
            string task_id, group_id, agg_col, file_path;
            int batch_id, starting_bit;
            bool is_cnt;
            tie(task_id, group_id, batch_id, is_cnt, agg_col, file_path, starting_bit) = agg_tasks[i];
            string calc_ind_task_id = TASK_PREFIX_CALC_IND + "-" + group_id + "-" + to_string(batch_id);
            seal::Ciphertext &ind_c = c_inds[idx_calc_ind_tasks[calc_ind_task_id]];

            // update tags
            if (is_cnt)
            {
                result_tail++;
                tags.push_back({result_tail, "server:group_" + group_id + ":b" + to_string(batch_id) + ":cnt"});
            }
            else if (starting_bit == 0)
            {
                result_tail += 42 / 3;
                tags.push_back({result_tail, "server:group_" + group_id + ":b" + to_string(batch_id) + ":agg_" + agg_col + ":sum"});
            }
            // cout << "calc_ind_task_id: " << calc_ind_task_id << endl;
            // cout << "The idx: " << idx_calc_ind_tasks[calc_ind_task_id] << endl;
            if (is_cnt)
            {
                c_agg[i] = ind_c;
                continue;
            }
            vector<u_int64_t> &agg_tbl = all_agg_tbls[file_path];
            threads.push_back(
                thread([&, i, task_id, group_id, batch_id, is_cnt, agg_col, file_path, starting_bit]()
                       {
                size_t start = batch_id * slot_count;
                size_t end = min((batch_id + 1) * slot_count, agg_tbl.size());
                vector<u_int64_t> v(slot_count, 0);
                bool all_zero = true;
                for (size_t j = start; j < end; j++)
                {
                    v[j - start] = (agg_tbl[j] >> starting_bit) & 0b111;
                    if (v[j - start] != 0)
                    {
                        all_zero = false;
                    }
                }
                if (all_zero)
                {
                    c_agg[i] = zero_c;
                }
                else
                {
                    seal::Plaintext plain;
                    batchEncoder.encode(v, plain);
                    evaluator.multiply_plain(ind_c, plain, c_agg[i]);
                } }));
            if (threads.size() >= MAX_THREAD)
            {
                for (auto &t : threads)
                    t.join();
                threads.clear();
            }
        }
        for (auto &t : threads)
            t.join();
        threads.clear();
        report_timing("server:process_query:agg", false);

        report_timing("server:process_query:merge", true);

        // TEMP: oracle access to calculate how many merge we can use
        seal::Decryptor decryptor(create_ctx(), keys.secret_key.value());
        auto noise_budget = decryptor.invariant_noise_budget(c_agg[0]);
        cout << "Noise budget in agg: " << noise_budget << " bits" << endl;
        MERGE_OPT_FACTOR = max(MERGE_OPT_FACTOR, noise_budget / 40);
        MERGE_OPT_FACTOR = min(MERGE_OPT_FACTOR, (int)poly_degree_log2);
        cout << "Using merge factor: " << MERGE_OPT_FACTOR << endl;

        auto ret = mt_merge_cipher_sums(c_agg, keys, MERGE_OPT_FACTOR, MAX_THREAD);
        for (auto &r : ret)
        {
            c_results.push_back(r);
        }
        // debug_print_noise_budget(ret[0], keys.secret_key.value());
        report_timing("server:process_query:merge", false);
        _debug_cs_min_budget("after_merge", c_results, keys);
    }
    report_timing("server:process_query", false);

    // Client: decrypt result
    report_timing("client:decrypt_result", true);
    {
        auto batchEncoder = seal::BatchEncoder(create_ctx());
        auto decryptor = seal::Decryptor(create_ctx(), keys.secret_key.value());
        auto &c_result = c_results[0]; // FIXME: support more results
        seal::Plaintext plain;
        // check noise budget
        auto noise_budget = decryptor.invariant_noise_budget(c_result);
        cout << "Noise budget in result: " << noise_budget << " bits" << endl;
        decryptor.decrypt(c_result, plain);
        vector<uint64_t> v;
        batchEncoder.decode(plain, v);

        int cur = 0;
        u_int64_t last_cnt = 0;
        for (auto tag : tags)
        {
            bool is_oct_sum = tag.second.find("sum") != string::npos;
            u_int64_t s = 0;
            for (; cur < tag.first; ++cur)
            {
                s = s * (is_oct_sum ? 8ULL : 1ULL) + (u_int64_t)v[cur];
            }
            if (is_oct_sum)
            {
                cout << "@" << tag.second << ": " << (double)(s - last_cnt * (u_int64_t)(DECIMAL_CAP * 100)) / 100 << endl;
            }
            else
            {
                last_cnt = s;
                cout << "@" << tag.second << ": " << s << endl;
            }
        }
    }
    report_timing("client:decrypt_result", false);

    return 0;
}

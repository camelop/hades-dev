#pragma once
#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <vector>
#include <unordered_map>

#include "mpi.h"

static const double DECIMAL_CAP = 9999999999.99;

u_int64_t d42_to_u64(double x)
{
    return (u_int64_t)(x * 100) + (u_int64_t)(DECIMAL_CAP * 100);
}

std::vector<std::pair<
    std::pair<std::string, bool>,
    std::chrono::time_point<std::chrono::system_clock>>>
    Report_timing_timestamps;

void report_timing(std::string event_name, bool is_start, bool print_report = true)
{
    static std::unordered_map<std::string, std::chrono::time_point<std::chrono::system_clock>> event_last;
    auto nw = std::chrono::system_clock::now();
    Report_timing_timestamps.emplace_back(std::make_pair(std::make_pair(event_name, is_start), nw));
    if (is_start)
    {
        event_last[event_name] = nw;
    }
    else
    {
        int world_rank = 0;
        // MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
        if (print_report && world_rank == 0)
        {
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(nw - event_last.at(event_name));
            std::cout << "* " << event_name << "\t" << std::fixed << std::setprecision(3)
                      << double(duration.count()) / 1000 << " ms" << std::endl;
        }
        event_last.erase(event_name);
    }
}

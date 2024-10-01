#pragma once

#include "myutil.hpp"

// deprecated
size_t gen_mapping_le16(uint16_t x, std::vector<uint> &mapping, size_t offset)
{
    const int bit_width = 8;
    const size_t R = 1 << bit_width;
    for (int i = 0; i < (int)R; ++i)
    {
        mapping[offset + i] = (i < (x >> bit_width) ? 1 : 0);
        mapping[offset + R + i] = (i == (x >> bit_width) ? 1 : 0);
        mapping[offset + 2 * R + i] = (i <= (x & (R - 1)) ? 1 : 0);
    }
    return offset + 3 * R; // return the next offset
}

namespace MAPPING
{
    const int GE = 1;
    const int EQ = 0;
    const int LE = -1;
}

size_t calc_block_shift(int flag, size_t v_bit_width)
{
    assert(v_bit_width <= 64);
    const int bit_width = 8;
    size_t step = (v_bit_width + bit_width - 1) / bit_width;
    switch (flag)
    {
    case MAPPING::GE:
    case MAPPING::LE:
        return step * 2 - 1;
    case MAPPING::EQ:
        return step;
    default:
        assert(false);
    }
}

size_t gen_mapping_cmp(int flag, size_t v_bit_width,
                       uint64_t x, std::vector<uint> &mapping, size_t offset)
{
    assert(v_bit_width <= 64);
    const int bit_width = 8;
    const size_t R = 1 << bit_width;
    size_t step = (v_bit_width + bit_width - 1) / bit_width;
    for (int i = 0; i < (int)R; ++i)
    {
        for (int j = 0; j < step; ++j)
        {
            uint64_t v = (x >> (j * bit_width)) & (R - 1);
            switch (flag)
            {
            case MAPPING::GE:
                if (j == 0)
                {
                    mapping[offset + j * 2 * R + i] = (i >= v ? 1 : 0);
                }
                else
                {
                    mapping[offset + j * 2 * R - R + i] = (i == v ? 1 : 0);
                    mapping[offset + j * 2 * R + i] = (i > v ? 1 : 0);
                }
                break;
            case MAPPING::EQ:
                mapping[offset + j * R + i] = (i == v ? 1 : 0);
                break;
            case MAPPING::LE:
                if (j == 0)
                {
                    mapping[offset + j * 2 * R + i] = (i <= v ? 1 : 0);
                }
                else
                {
                    mapping[offset + j * 2 * R - R + i] = (i == v ? 1 : 0);
                    mapping[offset + j * 2 * R + i] = (i < v ? 1 : 0);
                }
                break;
            default:
                assert(false);
            }
        }
    }
    return offset + R * calc_block_shift(flag, v_bit_width);
}

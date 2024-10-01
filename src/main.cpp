#include "mpi.h"

#include "he.hpp"

void print_seal_parameters(seal::SEALContext &ctx)
{
    auto &ctx_data = *ctx.key_context_data();
    std::string scheme_name;
    switch (ctx_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "--------------------" << std::endl;
    std::cout << "Encryption params :" << std::endl;
    std::cout << "\tscheme: " << scheme_name << std::endl;
    std::cout << "\tpoly_modulus_degree: " << ctx_data.parms().poly_modulus_degree() << std::endl;
    std::cout << "\tplain_modulus: " << ctx_data.parms().plain_modulus().value() << std::endl;
    // TODO: print out more info, ref:https://github.com/microsoft/SEAL/blob/master/native/examples/examples.h#L56
    std::cout << "--------------------" << std::endl;
}

int main(int argc, char *argv[])
{
    MPI_Init(&argc, &argv); // Initialize the MPI environment

    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size); // Get the number of processes

    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); // Get the rank of the process

    std::cout << "Test main" << std::endl;
    std::cout << "World size: " << world_size << std::endl;
    std::cout << "World rank: " << world_rank << std::endl;

    auto ctx = create_ctx();
    print_seal_parameters(ctx);

    MPI_Finalize();
    return 0;
}

#include <fstream>
#include "he.hpp"

int main()
{
    Keys keys;
    keys.generate();
    std::stringstream processing_keys_stream = keys.saveProcessingKeys();
    std::stringstream secret_key_stream = keys.saveSecretKey();
    std::ofstream keys_file("q1.processing_keys.bin", std::ios::binary);
    keys_file << processing_keys_stream.rdbuf();
    std::ofstream secret_key_file("q1.secret_key.bin", std::ios::binary);
    secret_key_file << secret_key_stream.rdbuf();
    keys_file.close();
    secret_key_file.close();
    // check
    std::ifstream keys_file_check("q1.processing_keys.bin", std::ios::binary);
    std::ifstream secret_key_file_check("q1.secret_key.bin", std::ios::binary);
    Keys keys_check;
    std::stringstream processing_keys_stream_check;
    processing_keys_stream_check << keys_file_check.rdbuf();
    std::stringstream secret_key_stream_check;
    secret_key_stream_check << secret_key_file_check.rdbuf();
    keys_check.loadProcessingKeys(processing_keys_stream_check);
    keys_check.loadSecretKey(secret_key_stream_check);
    return 0;
}

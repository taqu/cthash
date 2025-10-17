#include <iostream>
#include "cthash.h"

static constexpr std::array<uint8_t, 32> key = cthash::sha256_string((const uint8_t[])"Hello World!");
static constexpr auto pass = cthash::blake3_encrypt((const uint8_t[]) "Hello World!");
static constexpr auto encrypted = cthash::chacha20_encrypt(key, (const uint8_t[])"Hello World!");

int main(void)
{
    std::cout << key << std::endl;
    std::cout << "encrypted: " << encrypted << std::endl;
    auto decrypted = cthash::chacha20_encrypt(key, encrypted);
    std::cout << "decrypted: " << decrypted << std::endl;

    std::cout << "blake3: " << pass << std::endl;
    return 0;
}

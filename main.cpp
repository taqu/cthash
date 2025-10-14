#include <iostream>
#include "cthash.h"

static constexpr std::array<uint8_t, 32> key = crypt::sha256_string((const uint8_t[])"Hello World!");
static constexpr auto encrypted = crypt::chacha20_encrypt(key, (const uint8_t[])"Hello World!");

int main(void)
{
    std::cout << key << std::endl;
    std::cout << "encrypted: " << encrypted << std::endl;
    auto decrypted = crypt::chacha20_encrypt(key, encrypted);
    std::cout << "decrypted: " << decrypted << std::endl;
    return 0;
}

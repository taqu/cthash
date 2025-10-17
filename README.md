# About
Compile-time hash function and encryption. This library provides a way to compute hash values and perform encryption at compile time using C++ templates and constexpr functions.
Now only supports SHA256, BLAKE3 hash function and ChaCha20 encryption.

# Usage
To use this library, include the header file and call the desired functions. Here are some examples,

```cpp
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
```

# License
This project is licensed under the MIT License or Public Domain - see the [LICENSE](LICENSE) file for details.


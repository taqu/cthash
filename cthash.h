#ifndef INC_CRYPT_H_
#define INC_CRYPT_H_
#include <cstdint>
#include <array>
#ifdef _DEBUG
#include <iostream>
#endif
#include <bit>

namespace crypt
{

    struct sha256_state
    {
        //Round constants
        static constexpr uint32_t K[64] = {
            0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
            0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
            0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
            0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
            0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
            0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
            0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
            0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
            0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
            0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
            0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
            0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
            0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
        };
        uint64_t length_;
        uint64_t bitlen_;
        uint32_t state_[8];
        uint8_t data_[64];

        static constexpr uint32_t choose(uint32_t e, uint32_t f, uint32_t g)
        {
            return (e & f) ^ (~e & g);
        }

        static constexpr uint32_t majority(uint32_t a, uint32_t b, uint32_t c)
        {
            return (a & (b | c)) | (b & c);
        }

        static constexpr uint32_t rotr(uint32_t x, uint32_t n)
        {
            return (x >> n) | (x << (32 - n));
        }

        static constexpr uint32_t sigma0(uint32_t x)
        {
            return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
        }

        static constexpr uint32_t sigma1(uint32_t x)
        {
            return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
        }

        constexpr void compress()
        {
            uint32_t m[64];
            // Copy block into first 16 words m[0..15] of the message schedule array
            for (int32_t i = 0, j = 0; i < 16; ++i, j += 4) {
                m[i] = (data_[j] << 24) | (data_[j + 1] << 16) | (data_[j + 2] << 8) | (data_[j + 3]);
            }

            // Extend the first 16 words into the remaining 48 words m[16..63] of the message schedule array
            for (int32_t i = 16; i < 64; ++i) {
                m[i] = sigma1(m[i - 2]) + m[i - 7] + sigma0(m[i - 15]) + m[i - 16];
            }

            uint32_t state[8];
            for (int32_t i = 0; i < 8; ++i) {
                state[i] = state_[i];
            }

            for (int32_t i = 0; i < 64; ++i) {
                uint32_t s1 = rotr(state[4], 6) ^ rotr(state[4], 11) ^ rotr(state[4], 25);
                uint32_t ch = choose(state[4], state[5], state[6]);
                uint32_t temp1 = m[i] + K[i] + state[7] + ch + s1;
                uint32_t s0 = rotr(state[0], 2) ^ rotr(state[0], 13) ^ rotr(state[0], 22);
                uint32_t maj = majority(state[0], state[1], state[2]);
                uint32_t temp2 = s0 + maj;

                state[7] = state[6];
                state[6] = state[5];
                state[5] = state[4];
                state[4] = state[3] + temp1;
                state[3] = state[2];
                state[2] = state[1];
                state[1] = state[0];
                state[0] = temp1 + temp2;
            }

            // Add the compressed chunk to the current hash value
            for (int32_t i = 0; i < 8; ++i) {
                state_[i] += state[i];
            }
        }

        constexpr void init()
        {
            length_ = 0;
            bitlen_ = 0;
            state_[0] = 0x6A09E667UL;
            state_[1] = 0xBB67AE85UL;
            state_[2] = 0x3C6EF372UL;
            state_[3] = 0xA54FF53AUL;
            state_[4] = 0x510E527FUL;
            state_[5] = 0x9B05688CUL;
            state_[6] = 0x1F83D9ABUL;
            state_[7] = 0x5BE0CD19UL;
        }

        constexpr void update(size_t size, const uint8_t* src)
        {
            const size_t block_size = 64;
            const uint8_t* data = src;

            for (size_t i = 0; i < size; ++i) {
                data_[length_++] = data[i];
                if (block_size == length_) {
                    compress();
                    // End of the block
                    bitlen_ += 8 * block_size;
                    length_ = 0;
                }
            }
        }

        constexpr void memset(uint8_t* mem, uint8_t x, size_t size)
        {
            for (size_t i = 0; i < size; ++i) {
                mem[i] = x;
            }
        }

        constexpr std::array<uint8_t, 32> finalize()
        {
            uint64_t i = length_;
            uint8_t end = length_ < 56 ? 56 : 64;

            data_[i++] = 0x80; // Append a bit 1
            while (i < end) {
                data_[i++] = 0x00; // Pad with zeros
            }

            if (56 <= length_) {
                compress();
                sha256_state::memset(data_, 0, 56);
            }

            // Append to the padding the total message's length in bits and compress.
            bitlen_ += length_ * 8;
            data_[63] = static_cast<uint8_t>(bitlen_);
            data_[62] = static_cast<uint8_t>(bitlen_ >> 8);
            data_[61] = static_cast<uint8_t>(bitlen_ >> 16);
            data_[60] = static_cast<uint8_t>(bitlen_ >> 24);
            data_[59] = static_cast<uint8_t>(bitlen_ >> 32);
            data_[58] = static_cast<uint8_t>(bitlen_ >> 40);
            data_[57] = static_cast<uint8_t>(bitlen_ >> 48);
            data_[56] = static_cast<uint8_t>(bitlen_ >> 56);
            compress();

            // Produces hash in the big-endian order
            std::array<uint8_t, 32> hash;
            for (uint8_t i = 0; i < 4; ++i) {
                for (uint8_t j = 0; j < 8; ++j) {
                    hash[i + (j * 4)] = (state_[j] >> (24 - i * 8)) & 0x000000ffU;
                }
            }
            return hash;
        }
    };

    template<size_t N>
    constexpr std::array<uint8_t, 32> sha256_string(const uint8_t(&src)[N])
    {
        static_assert(0 < N);
        sha256_state state;
        state.init();
        // Do not include the null terminator in the hash
        state.update(N - 1, src);
        return state.finalize();
    }

    template<size_t N>
    constexpr std::array<uint8_t, 32> sha256_data(const uint8_t(&src)[N])
    {
        static_assert(0 < N);
        sha256_state state;
        state.init();
        state.update(N, src);
        return state.finalize();
    }

#define CHACHA_ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define CHACHA_QR(a, b, c, d) (             \
    a += b, d ^= a, d = CHACHA_ROTL(d, 16), \
    c += d, b ^= c, b = CHACHA_ROTL(b, 12), \
    a += b, d ^= a, d = CHACHA_ROTL(d, 8),  \
    c += d, b ^= c, b = CHACHA_ROTL(b, 7))

    constexpr void chacha20_block(uint32_t out[16], const uint32_t in[16])
    {
        uint32_t x[16];
        for (int32_t i = 0; i < 16; ++i)
        {
            x[i] = in[i];
        }
        for (int32_t i = 0; i < 10; ++i)
        {
            // Odd round
            CHACHA_QR(x[0], x[4], x[8], x[12]);  // Column 0
            CHACHA_QR(x[1], x[5], x[9], x[13]);  // Column 1
            CHACHA_QR(x[2], x[6], x[10], x[14]); // Column 2
            CHACHA_QR(x[3], x[7], x[11], x[15]); // Column 3
            // Even round
            CHACHA_QR(x[0], x[5], x[10], x[15]); // Diagonal 0
            CHACHA_QR(x[1], x[6], x[11], x[12]); // Diagonal 1
            CHACHA_QR(x[2], x[7], x[8], x[13]);  // Diagonal 2
            CHACHA_QR(x[3], x[4], x[9], x[14]);  // Diagonal 3
        }
        for (int32_t i = 0; i < 16; ++i)
        {
            out[i] = x[i] + in[i];
        }
    }

    constexpr uint64_t to_uint64(uint32_t low, uint32_t high)
    {
        return (static_cast<uint64_t>(high) << 32) | static_cast<uint64_t>(low);
    }

    constexpr void to_uint32(uint32_t& low, uint32_t& high, uint64_t x)
    {
        low = static_cast<uint32_t>(x & 0xFFFFFFFFUL);
        high = static_cast<uint32_t>((x >> 32) & 0xFFFFFFFFUL);
    }

    constexpr void chacha20_encrypt(uint32_t input[16], uint32_t size, uint8_t* message)
    {
        uint32_t output[16] = {};
        uint8_t* p = message;
        uint64_t counter = to_uint64(input[12], input[13]);
        for (;;)
        {
            chacha20_block(output, input);
            counter += 1;
            if (size <= 64)
            {
                uint8_t* pb = p;
                uint32_t* po = output;
                uint32_t blocks = size>>2;
                uint32_t count = blocks<<2;
                uint32_t remain = size - count;

                for (uint32_t i=0,j=0; j < count; ++i,j+=4)
                {
                    pb[j+0] = pb[j+0] ^ ((po[i]>>0)&0xFFU);
                    pb[j+1] = pb[j+1] ^ ((po[i]>>8)&0xFFU);
                    pb[j+2] = pb[j+2] ^ ((po[i]>>16)&0xFFU);
                    pb[j+3] = pb[j+3] ^ ((po[i]>>24)&0xFFU);
                }

                switch(remain){
                case 1:{
                    pb[count + 0] = pb[count + 0] ^ ((po[blocks] >> 0) & 0xFFU);
                }
                    break;
                case 2:{
                    pb[count + 0] = pb[count + 0] ^ ((po[blocks] >> 0) & 0xFFU);
                    pb[count + 1] = pb[count + 1] ^ ((po[blocks] >> 8) & 0xFFU);
                }
                    break;
                case 3:{
                    pb[count + 0] = pb[count + 0] ^ ((po[blocks] >> 0) & 0xFFU);
                    pb[count + 1] = pb[count + 1] ^ ((po[blocks] >> 8) & 0xFFU);
                    pb[count + 2] = pb[count + 2] ^ ((po[blocks] >> 16) & 0xFFU);
                }
                    break;
                }
                break;
            }
            else
            {
                for (uint32_t i=0,j=0; i < 16; ++i,j+=4)
                {
                    p[j+0] ^= ((output[i]>>0)&0xFFU);
                    p[j+1] ^= ((output[i]>>8)&0xFFU);
                    p[j+2] ^= ((output[i]>>16)&0xFFU);
                    p[j+3] ^= ((output[i]>>24)&0xFFU);
                }
                size -= 64;
                p += (16*4);
            }
        }
        to_uint32(input[12], input[13], counter);
    }

    constexpr void chacha20_encrypt(const std::array<uint8_t, 32>& key, uint32_t size, uint8_t* message)
    {
        static constexpr uint32_t iv_32[4] = {0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U};
        static constexpr uint32_t nonce[2] = { 0x55783743U, 0x421d5279U };

        uint32_t input[16];

        for (int32_t i = 0; i < 4; ++i)
        {
            input[i] = iv_32[i];
        }

        for (int32_t i = 0, j = 0; i < 8; ++i,j+=4)
        {
            input[4 + i] = (key[j+0]<<24) | (key[j+1]<<16) | (key[j+2]<<8) | (key[j+3]);
        }

        input[12] = 0;
        input[13] = 0;
        input[14] = nonce[0];
        input[15] = nonce[1];
        chacha20_encrypt(input, size, message);
    }

    template<size_t N>
    constexpr std::array<uint8_t, N> chacha20_encrypt(const std::array<uint8_t, 32>& key, const std::array<uint8_t, N>& src)
    {
        std::array<uint8_t, N> message = src;
        chacha20_encrypt(key, N, &message[0]);
        return message;
    }

    template<size_t N>
    constexpr std::array<uint8_t, N> chacha20_encrypt(const std::array<uint8_t, 32>& key, const uint8_t(&src)[N])
    {
        static constexpr uint32_t iv_32[4] = {0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U};
        static constexpr uint32_t nonce[2] = { 0x55783743U, 0x421d5279U };

        uint32_t input[16];

        for (int32_t i = 0; i < 4; ++i)
        {
            input[i] = iv_32[i];
        }

        for (int32_t i = 0, j = 0; i < 8; ++i,j+=4)
        {
            input[4 + i] = (key[j+0]<<24) | (key[j+1]<<16) | (key[j+2]<<8) | (key[j+3]);
        }

        input[12] = 0;
        input[13] = 0;
        input[14] = nonce[0];
        input[15] = nonce[1];
        std::array<uint8_t, N> message;
        std::copy(src, src + N, message.begin());
        chacha20_encrypt(input, N, &message[0]);
        return message;
    }

    template <class T, std::size_t N>
    struct wrapper_list;

    template <std::size_t N>
    struct wrapper_list<uint8_t, N> final
    {
        constexpr wrapper_list() noexcept
            : data_{}
        {
        }
        constexpr wrapper_list(const std::array<uint8_t, N>& data) noexcept
            : data_(data)
        {
        }

        constexpr uint8_t operator[](std::size_t i) const noexcept
        {
            return data_[i];
        }
        constexpr uint8_t& operator[](std::size_t i) noexcept
        {
            return data_[i];
        }

        constexpr size_t size() const noexcept { return data_.size(); }

        std::array<uint8_t, N> data_;
    };

    template <class T, std::size_t N>
    std::ostream& operator<<(std::ostream& os, const wrapper_list<T, N>& ar)
    {
        for (size_t i = 0; i < ar.size(); ++i)
        {
            os << std::hex << (int32_t)ar[i];
        }
        return os;
    }

    template <std::size_t N>
    constexpr auto encrypt(const char(&input)[N])
    {
        constexpr auto SIZE = N - 1;
        std::array<uint8_t, SIZE> result;
        for (std::size_t i = 0; i < SIZE; ++i)
        {
            result[i] = static_cast<uint8_t>(input[i]) + 1;
        }
        return wrapper_list<uint8_t, SIZE>(result);
    }

    template <std::size_t N>
    constexpr wrapper_list<uint8_t, N> decrypt(const wrapper_list<uint8_t, N>& encrypted)
    {
        wrapper_list<uint8_t, N> result;
        for (std::size_t i = 0; i < result.size(); ++i)
        {
            // -1もどす
            result[i] = static_cast<char>(encrypted[i] - 1);
        }
        return result;
    }
}

#ifdef _DEBUG
template<class T, size_t N>
std::ostream& operator<<(std::ostream& os, const std::array<T, N>& ar)
{
    for (size_t i = 0; i < ar.size(); ++i) {
        os << std::hex << (int32_t)ar[i];
    }
    return os;
}
#endif

#endif //INC_CRYPT_H_


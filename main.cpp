#include <iostream>
#include <cstdint>
#include <vector>
#include <cstring>

using namespace std;

class GSCH {
private:
    vector<uint8_t> key;
    vector<uint8_t> iv;
    vector<uint8_t> state;

    uint64_t bytesToUint64(const vector<uint8_t>& bytes, size_t offset) {
        uint64_t result = 0;
        for (size_t i = 0; i < 8; ++i) {
            result |= static_cast<uint64_t>(bytes[offset + i]) << (8 * i);
        }
        return result;
    }

    vector<uint8_t> uint64ToBytes(uint64_t value) {
        vector<uint8_t> bytes(8);
        for (size_t i = 0; i < 8; ++i) {
            bytes[i] = (value >> (8 * i)) & 0xFF;
        }
        return bytes;
    }

    void speckRound(uint64_t& x, uint64_t& y, uint64_t k) {
        x = (x >> 8) | ((x << 56) & 0xFFFFFFFFFFFFFFFF);
        x += y;
        x ^= k;
        y = (y << 3) | ((y >> 61) & 0xFFFFFFFFFFFFFFFF);
        y ^= x;
    }

    vector<uint8_t> speckEncrypt(const vector<uint8_t>& plaintext, const vector<uint8_t>& key) {
        uint64_t x = bytesToUint64(plaintext, 0);
        uint64_t y = bytesToUint64(plaintext, 8);

        vector<uint64_t> roundKeys(32);
        roundKeys[0] = bytesToUint64(key, 0);

        for (size_t i = 1; i < 32; ++i) {
            uint64_t prevKey = roundKeys[i - 1];
            uint64_t prevKeyPart = bytesToUint64(key, i * 8 % key.size());
            roundKeys[i] = (prevKey >> 8) | ((prevKey << 56) & 0xFFFFFFFFFFFFFFFF);
            roundKeys[i] += prevKeyPart;
        }

        for (size_t i = 0; i < 32; ++i) {
            speckRound(x, y, roundKeys[i]);
        }

        vector<uint8_t> ciphertext(16);
        vector<uint8_t> xBytes = uint64ToBytes(x);
        vector<uint8_t> yBytes = uint64ToBytes(y);
        copy(xBytes.begin(), xBytes.end(), ciphertext.begin());
        copy(yBytes.begin(), yBytes.end(), ciphertext.begin() + 8);
        return ciphertext;
    }

public:
    GSCH(const vector<uint8_t>& key, const vector<uint8_t>& iv)
        : key(key), iv(iv), state(iv) {}

    uint8_t generateByte() {
        vector<uint8_t> encryptedState = speckEncrypt(state, key);
        state = encryptedState;
        return encryptedState[0];
    }

    vector<uint8_t> generateIV() {
        vector<uint8_t> iv(16);
        for (int i = 0; i < 16; ++i) {
            iv[i] = generateByte();
        }
        return iv;
    }
};

class Speck {
private:
    uint32_t alpha = 3;
    uint32_t beta = 8;
    uint32_t rounds = 32;

    uint64_t rotate_left(uint64_t x, uint32_t n) {
        return (x << n) | (x >> (64 - n));
    }

    uint64_t rotate_right(uint64_t x, uint32_t n) {
        return (x >> n) | (x << (64 - n));
    }

    void speck_round(uint64_t &x, uint64_t &y, uint64_t k) {
        x = rotate_right(x, beta);
        x += y;
        x ^= k;
        y = rotate_left(y, alpha);
        y ^= x;
    }

    void speck_inv_round(uint64_t &x, uint64_t &y, uint64_t k) {
        y ^= x;
        y = rotate_right(y, alpha);
        x ^= k;
        x -= y;
        x = rotate_left(x, beta);
    }

public:
    vector<uint64_t> key_schedule(const vector<uint64_t> &key) {
        vector<uint64_t> round_keys(rounds);
        uint64_t l = key[1];
        uint64_t k = key[0];

        round_keys[0] = k;
        for (uint32_t i = 0; i < rounds - 1; ++i) {
            l = rotate_left(l, alpha);
            l ^= k;
            k = rotate_right(k, beta);
            k ^= (i + 1);
            round_keys[i + 1] = k;
        }
        return round_keys;
    }

    vector<uint8_t> string_to_bytes(const string &text) {
        return vector<uint8_t>(text.begin(), text.end());
    }

    vector<pair<uint64_t, uint64_t>> bytes_to_blocks(const vector<uint8_t> &bytes) {
        vector<pair<uint64_t, uint64_t>> blocks;
        size_t num_blocks = (bytes.size() + 15) / 16;
        blocks.resize(num_blocks, {0, 0});

        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i % 16 < 8) {
                blocks[i / 16].first |= static_cast<uint64_t>(bytes[i]) << ((i % 8) * 8);
            } else {
                blocks[i / 16].second |= static_cast<uint64_t>(bytes[i]) << (((i % 8) - 8) * 8);
            }
        }
        return blocks;
    }

    vector<uint8_t> blocks_to_bytes(const vector<pair<uint64_t, uint64_t>> &blocks) {
        vector<uint8_t> bytes;
        bytes.reserve(blocks.size() * 16);

        for (const auto &block : blocks) {
            for (int i = 0; i < 8; ++i) {
                bytes.push_back(static_cast<uint8_t>((block.first >> (i * 8)) & 0xFF));
            }
            for (int i = 0; i < 8; ++i) {
                bytes.push_back(static_cast<uint8_t>((block.second >> (i * 8)) & 0xFF));
            }
        }
        return bytes;
    }

    void xor_blocks(pair<uint64_t, uint64_t> &result, const pair<uint64_t, uint64_t> &a, const pair<uint64_t, uint64_t> &b) {
        result.first = a.first ^ b.first;
        result.second = a.second ^ b.second;
    }

    string encrypt_text_cbc(const string &plaintext, const vector<uint64_t> &round_keys, const vector<uint8_t> &iv) {
        vector<uint8_t> plaintext_bytes = string_to_bytes(plaintext);
        vector<pair<uint64_t, uint64_t>> blocks = bytes_to_blocks(plaintext_bytes);

        vector<pair<uint64_t, uint64_t>> iv_blocks = bytes_to_blocks(iv);
        pair<uint64_t, uint64_t> prev_block = iv_blocks[0];

        for (size_t i = 0; i < blocks.size(); ++i) {
            pair<uint64_t, uint64_t> xored_block;
            xor_blocks(xored_block, blocks[i], prev_block);

            uint64_t x = xored_block.first;
            uint64_t y = xored_block.second;
            for (uint32_t j = 0; j < rounds; ++j) {
                speck_round(x, y, round_keys[j]);
            }
            for (int j = 0; j < 3; ++j) {
                for (uint32_t r = 0; r < rounds; ++r) {
                    speck_round(x, y, round_keys[r]);
                }
            }
            blocks[i] = {x, y};
            prev_block = blocks[i];
        }

        vector<uint8_t> ciphertext = blocks_to_bytes(blocks);
        return string(ciphertext.begin(), ciphertext.end());
    }

    string decrypt_text_cbc(const string &ciphertext, const vector<uint64_t> &round_keys, const vector<uint8_t> &iv) {
        vector<uint8_t> ciphertext_bytes = string_to_bytes(ciphertext);
        vector<pair<uint64_t, uint64_t>> blocks = bytes_to_blocks(ciphertext_bytes);

        vector<pair<uint64_t, uint64_t>> iv_blocks = bytes_to_blocks(iv);
        pair<uint64_t, uint64_t> prev_block = iv_blocks[0];

        vector<pair<uint64_t, uint64_t>> cipher_blocks = blocks;

        for (size_t i = 0; i < blocks.size(); ++i) {
            uint64_t x = blocks[i].first;
            uint64_t y = blocks[i].second;

            for (int j = 0; j < 3; ++j) {
                for (int r = rounds - 1; r >= 0; --r) {
                    speck_inv_round(x, y, round_keys[r]);
                }
            }
            for (int j = rounds - 1; j >= 0; --j) {
                speck_inv_round(x, y, round_keys[j]);
            }

            pair<uint64_t, uint64_t> decrypted_block = {x, y};
            pair<uint64_t, uint64_t> xored_block;
            xor_blocks(xored_block, decrypted_block, prev_block);
            blocks[i] = xored_block;

            prev_block = cipher_blocks[i];
        }

        vector<uint8_t> plaintext_bytes = blocks_to_bytes(blocks);

        while (!plaintext_bytes.empty() && plaintext_bytes.back() == 0) {
            plaintext_bytes.pop_back();
        }

        return string(plaintext_bytes.begin(), plaintext_bytes.end());
    }
};

vector<uint64_t> transformKey(const string &key_str) {
    if (key_str.size() != 16) {
        cerr << "Ошибка: ключ должен быть длиной 16 символов." << endl;
        exit(1);
    }

    vector<uint64_t> key(2);
    key[0] = 0;
    key[1] = 0;

    for (size_t i = 0; i < 8; ++i) {
        key[0] |= static_cast<uint64_t>(static_cast<uint8_t>(key_str[i])) << (i * 8);
    }
    for (size_t i = 0; i < 8; ++i) {
        key[1] |= static_cast<uint64_t>(static_cast<uint8_t>(key_str[i + 8])) << (i * 8);
    }

    return key;
}

int main() {
    Speck speck;

    vector<uint8_t> iv(16);
    sscanf("3ae091967a3c2c02938583c22b032bb3",
           "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
           &iv[0], &iv[1], &iv[2], &iv[3], &iv[4], &iv[5], &iv[6], &iv[7],
           &iv[8], &iv[9], &iv[10], &iv[11], &iv[12], &iv[13], &iv[14], &iv[15]);

    cout << "Вектор инициализации (hex): ";
    for (unsigned char c : iv) {
        printf("%02x", c);
    }
    cout << endl;

    string key_str;
    cout << "Введите ключ: ";
    getline(cin, key_str);

    vector<uint64_t> key = transformKey(key_str);
    vector<uint64_t> round_keys = speck.key_schedule(key);

    string plaintext;
    cout << "Введите текст: ";
    getline(cin, plaintext);

    string ciphertext = speck.encrypt_text_cbc(plaintext, round_keys, iv);
    cout << "encrypt_text_cbc (hex): ";
    for (unsigned char c : ciphertext) {
        printf("%02x", c);
    }
    cout << endl;

    string decrypted = speck.decrypt_text_cbc(ciphertext, round_keys, iv);
    cout << "decrypt_text_cbc: " << decrypted << endl;

    cout << "decrypt_text_cbc (hex): ";
    for (unsigned char c : decrypted) {
        printf("%02x", c);
    }
    cout << endl;

    return 0;
}

#include <sodium.h>
#include <iostream>
#include <string>
#include <fstream>

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    std::cout << "Libsodium initialized successfully!" << std::endl;

    std::ifstream in("identity.key", std::ios::binary);
    if (in) {
        unsigned char salt[crypto_pwhash_SALTBYTES];
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        unsigned char pk[crypto_box_PUBLICKEYBYTES];
        unsigned char encrypted_sk[crypto_secretbox_MACBYTES + crypto_box_SECRETKEYBYTES];
        
        in.read(reinterpret_cast<char*>(salt), sizeof(salt));
        in.read(reinterpret_cast<char*>(nonce), sizeof(nonce));
        in.read(reinterpret_cast<char*>(pk), sizeof(pk));
        in.read(reinterpret_cast<char*>(encrypted_sk), sizeof(encrypted_sk));
        if (!in) {
            std::cerr << "File is too short or damaged" << std::endl;
            return 1;
        }
        
        std::string password;
        std::cout << "Password: ";
        std::getline(std::cin, password);

        unsigned char key[crypto_secretbox_KEYBYTES];
        if (crypto_pwhash(key, sizeof(key),
                            password.c_str(), password.size(),
                            salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                            crypto_pwhash_MEMLIMIT_INTERACTIVE,
                            crypto_pwhash_ALG_ARGON2ID13) != 0) {
            std::cerr << "Not enough memory" << std::endl;
            return 1;
        }

        unsigned char sk[crypto_box_SECRETKEYBYTES];
        if (crypto_secretbox_open_easy(sk, encrypted_sk, sizeof(encrypted_sk), nonce, key) != 0) {
            std::cerr << "Wrong password or file was modified" << std::endl;
            return 1;
        }

        char pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
        sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
        std::cout << "Unlocked! Public Key: " << pk_hex << std::endl;

        sodium_memzero(sk, sizeof(sk));
        sodium_memzero(key, sizeof(key));
        return 0;
    }

    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);

    char pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    char sk_hex[crypto_box_SECRETKEYBYTES * 2 + 1];
    sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
    sodium_bin2hex(sk_hex, sizeof(sk_hex), sk, sizeof(sk));

    std::cout << "Public Key: " << pk_hex << std::endl;

    std::string password;
    std::cout << "Password: ";
    std::getline(std::cin, password);

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    unsigned char key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(key, sizeof(key),
                        password.c_str(), password.size(),
                        salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                        crypto_pwhash_MEMLIMIT_INTERACTIVE,
                        crypto_pwhash_ALG_ARGON2ID13) != 0) {
            std::cerr << "Not enough memory" << std::endl;
            return 1;
        }
        
        char key_hex[sizeof(key) * 2 + 1];
        sodium_bin2hex(key_hex, sizeof(key_hex), key, sizeof(key));

        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        unsigned char encrypted_sk[crypto_secretbox_MACBYTES + crypto_box_SECRETKEYBYTES];
        crypto_secretbox_easy(encrypted_sk, sk, sizeof(sk), nonce, key);

        unsigned char decrypted_sk[crypto_box_SECRETKEYBYTES];
        if (crypto_secretbox_open_easy(decrypted_sk, encrypted_sk, sizeof(encrypted_sk), nonce, key) != 0) {
            std::cerr << "Decryption failed" << std::endl;
            return 1;
        }

        if (sodium_memcmp(sk, decrypted_sk, sizeof(sk)) == 0) {
            std::cout << "Roundtrip OK" << std::endl;
        }

        std::ofstream out ("identity.key", std::ios::binary);
        if (!out) {
            std::cerr << "Cannot open file" << std::endl;
            return 1;
        }
        out.write(reinterpret_cast<const char*>(salt), sizeof(salt));
        out.write(reinterpret_cast<const char*>(nonce), sizeof(nonce));
        out.write(reinterpret_cast<const char*>(pk), sizeof(pk));
        out.write(reinterpret_cast<const char*>(encrypted_sk), sizeof(encrypted_sk));
        out.close();
        std::cout << "Saved identity key" << std::endl;
    return 0;
}
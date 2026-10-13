#include <sodium.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <filesystem>

bool derive_key(const std::string &password, const unsigned char *salt, unsigned char *key)
{
    return crypto_pwhash(key, crypto_secretbox_KEYBYTES,
                         password.c_str(), password.size(),
                         salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE,
                         crypto_pwhash_ALG_ARGON2ID13) == 0;
}
bool load_identity(const std::string &path, unsigned char *pk, unsigned char *sk)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        std::cerr << "Cannot open " << path << std::endl;
        return false;
    }
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char encrypted_sk[crypto_secretbox_MACBYTES + crypto_box_SECRETKEYBYTES];

    in.read(reinterpret_cast<char *>(salt), sizeof(salt));
    in.read(reinterpret_cast<char *>(nonce), sizeof(nonce));
    in.read(reinterpret_cast<char *>(pk), crypto_box_PUBLICKEYBYTES);
    in.read(reinterpret_cast<char *>(encrypted_sk), sizeof(encrypted_sk));
    if (!in)
    {
        std::cerr << "File is too short or damaged" << std::endl;
        return false;
    }

    std::string password;
    std::cout << "Password: ";
    std::getline(std::cin, password);

    unsigned char key[crypto_secretbox_KEYBYTES];
    if (!derive_key(password, salt, key))
    {
        std::cerr << "Not enough memory" << std::endl;
        return false;
    }

    bool ok = crypto_secretbox_open_easy(sk, encrypted_sk, sizeof(encrypted_sk), nonce, key) == 0;
    sodium_memzero(key, sizeof(key));
    if (!ok)
    {
        std::cerr << "Wrong password or file was modified" << std::endl;
        return false;
    }
    return true;
}
bool create_identity(const std::string &path, unsigned char *pk, unsigned char *sk)
{
    crypto_box_keypair(pk, sk);

    std::string password;
    std::cout << "Password: ";
    std::getline(std::cin, password);

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    unsigned char key[crypto_secretbox_KEYBYTES];
    if (!derive_key(password, salt, key))
    {
        std::cerr << "Not enough memory" << std::endl;
        return false;
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned char encrypted_sk[crypto_secretbox_MACBYTES + crypto_box_SECRETKEYBYTES];
    crypto_secretbox_easy(encrypted_sk, sk, crypto_box_SECRETKEYBYTES, nonce, key);
    sodium_memzero(key, sizeof(key));

    std::ofstream out(path, std::ios::binary);
    if (!out)
    {
        std::cerr << "Cannot open file" << std::endl;
        return false;
    }
    out.write(reinterpret_cast<const char *>(salt), sizeof(salt));
    out.write(reinterpret_cast<const char *>(nonce), sizeof(nonce));
    out.write(reinterpret_cast<const char *>(pk), crypto_box_PUBLICKEYBYTES);
    out.write(reinterpret_cast<const char *>(encrypted_sk), sizeof(encrypted_sk));
    out.close();
    if (!out)
    {
        std::cerr << "Failed to write file" << std::endl;
        return false;
    }
    return true;
}
bool send_message(const unsigned char *my_pk, const unsigned char *my_sk, const std::string &their_pk_hex, const std::string &text, const std::string &out_path)
{
    unsigned char their_pk[crypto_box_PUBLICKEYBYTES];
    size_t decoded_len = 0;
    if (sodium_hex2bin(their_pk, sizeof(their_pk), their_pk_hex.c_str(), their_pk_hex.size(), nullptr, &decoded_len, nullptr) != 0 ||
        decoded_len != crypto_box_PUBLICKEYBYTES)
    {
        std::cerr << "Invalid public key (need 64 hex characters)" << std::endl;
        return false;
    }

    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<unsigned char> encrypted(crypto_box_MACBYTES + text.size());
    if (crypto_box_easy(encrypted.data(), reinterpret_cast<const unsigned char *>(text.c_str()), text.size(), nonce, their_pk, my_sk) != 0)
    {
        std::cerr << "Encryption failed" << std::endl;
        return false;
    }

    std::ofstream out(out_path, std::ios::binary);
    if (!out)
    {
        std::cerr << "Cannot open output file " << std::endl;
        return false;
    }

    out.write(reinterpret_cast<const char *>(my_pk), crypto_box_PUBLICKEYBYTES);
    out.write(reinterpret_cast<const char *>(nonce), sizeof(nonce));
    out.write(reinterpret_cast<const char *>(encrypted.data()),
              static_cast<std::streamsize>(encrypted.size()));
    out.close();
    if (!out)
    {
        std::cerr << "Failed to write output file" << std::endl;
        return false;
    }
    return true;
}
bool recv_message(const unsigned char *my_sk, const std::string &in_path)
{
    std::error_code ec;
    const std::uintmax_t total = std::filesystem::file_size(in_path, ec);
    if (ec)
    {
        std::cerr << "Cannot read file message" << std::endl;
        return false;
    }

    const std::uintmax_t header = crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES;
    if (total < header + crypto_box_MACBYTES)
    {
        std::cerr << "Message file too short" << std::endl;
        return false;
    }

    std::ifstream in(in_path, std::ios::binary);
    if (!in)
    {
        std::cerr << "Cannto open message file" << std::endl;
        return false;
    }

    unsigned char sender_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char nonce[crypto_box_NONCEBYTES];
    std::vector<unsigned char> encrypted(static_cast<size_t>(total - header));

    in.read(reinterpret_cast<char *>(sender_pk), sizeof(sender_pk));
    in.read(reinterpret_cast<char *>(nonce), sizeof(nonce));
    in.read(reinterpret_cast<char *>(encrypted.data()), static_cast<std::streamsize>(encrypted.size()));
    if (!in)
    {
        std::cerr << "Message file is damaged" << std::endl;
        return false;
    }

    std::vector<unsigned char> decrypted(encrypted.size() - crypto_box_MACBYTES);
    if (crypto_box_open_easy(decrypted.data(), encrypted.data(), encrypted.size(), nonce, sender_pk, my_sk) != 0)
    {
        std::cerr << "Message was forged or damaged" << std::endl;
        return false;
    }

    char sender_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(sender_hex, sizeof(sender_hex), sender_pk, sizeof(sender_pk));
    std::cout << "From: " << sender_hex << std::endl;
    std::cout << "Message: " << std::string(decrypted.begin(), decrypted.end()) << std::endl;
    return true;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: secys_cli <identity-file>" << std::endl;
        return 1;
    }
    const std::string identity_path = argv[1];

    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    std::cout << "Libsodium initialized successfully!" << std::endl;

    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    std::ifstream in(identity_path, std::ios::binary);
    bool exists = in.is_open();
    in.close();

    bool ok;
    if (exists)
    {
        ok = load_identity(identity_path, pk, sk);
    }
    else
    {
        ok = create_identity(identity_path, pk, sk);
    }
    if (!ok)
    {
        return 1;
    }

    char pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
    std::cout << "Identity ready. Public Key: " << pk_hex << std::endl;

    if (argc == 6 && std::string(argv[2]) == "send")
    {
        if (!send_message(pk, sk, argv[3], argv[4], argv[5]))
        {
            return 1;
        }
        std::cout << "Message written to " << argv[5] << std::endl;
    }

    if (argc == 4 && std::string(argv[2]) == "recv")
    {
        if (!recv_message(sk, argv[3]))
        {
            return 1;
        }
    }

    sodium_memzero(sk, sizeof(sk));
    return 0;
}
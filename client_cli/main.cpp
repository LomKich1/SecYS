#include <sodium.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>

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

bool demo_message()
{
    unsigned char alice_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char alice_sk[crypto_box_SECRETKEYBYTES];
    unsigned char bob_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char bob_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(alice_pk, alice_sk);
    crypto_box_keypair(bob_pk, bob_sk);

    const std::string message = "Hello, Bob!";

    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<unsigned char> encrypted(crypto_box_MACBYTES + message.size());
    if (crypto_box_easy(encrypted.data(),
                        reinterpret_cast<const unsigned char *>(message.c_str()),
                        message.size(),
                        nonce, bob_pk, alice_sk) != 0)
    {
        std::cerr << "Encryption failed" << std::endl;
        return false;
    }

    std::vector<unsigned char> decrypted(message.size());
    if (crypto_box_open_easy(decrypted.data(), encrypted.data(), encrypted.size(),

                             nonce, alice_pk, bob_sk) != 0)
    {
        std::cerr << "Message was forged or damaged" << std::endl;
        return false;
    }

    std::string text(decrypted.begin(), decrypted.end());
    std::cout << "Bob read: " << text << std::endl;
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

    if (!demo_message())
    {
        return 1;
    }

    sodium_memzero(sk, sizeof(sk));
    return 0;
}
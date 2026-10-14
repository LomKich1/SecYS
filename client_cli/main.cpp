#include <asio.hpp>
#include <sodium.h>
#include "protocol.h"
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <array>
#include <cstdint>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <cwchar>
#ifdef _MSC_VER
#pragma comment(lib, "shell32.lib")
#endif
#endif

using asio::ip::tcp;

constexpr const char *kServerHost = "127.0.0.1";
constexpr unsigned short kServerPort = 9000;

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
bool parse_public_key_hex(const std::string &hex, unsigned char *out)
{
    size_t decoded_len = 0;
    if (sodium_hex2bin(out, crypto_box_PUBLICKEYBYTES, hex.c_str(), hex.size(), nullptr, &decoded_len, nullptr) != 0 ||
        decoded_len != crypto_box_PUBLICKEYBYTES)
    {
        std::cerr << "Invalid public key (need 64 hex characters)" << std::endl;
        return false;
    }
    return true;
}
bool encrypt_message(const unsigned char *my_pk, const unsigned char *my_sk, const std::string &their_pk_hex, const std::string &text, std::vector<unsigned char> &blob)
{
    unsigned char their_pk[crypto_box_PUBLICKEYBYTES];
    if (!parse_public_key_hex(their_pk_hex, their_pk))
    {
        return false;
    }

    blob.resize(crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_MACBYTES + text.size());
    unsigned char *nonce = blob.data() + crypto_box_PUBLICKEYBYTES;
    unsigned char *ciphertext = nonce + crypto_box_NONCEBYTES;

    std::copy(my_pk, my_pk + crypto_box_PUBLICKEYBYTES, blob.begin());
    randombytes_buf(nonce, crypto_box_NONCEBYTES);

    if (crypto_box_easy(ciphertext, reinterpret_cast<const unsigned char *>(text.c_str()), text.size(), nonce, their_pk, my_sk) != 0)
    {
        std::cerr << "Encryption failed" << std::endl;
        return false;
    }
    return true;
}
bool decrypt_message(const unsigned char *my_sk, const std::vector<unsigned char> &blob)
{
    constexpr size_t header = crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES;
    if (blob.size() < header + crypto_box_MACBYTES)
    {
        std::cerr << "Message too short" << std::endl;
        return false;
    }

    const unsigned char *sender_pk = blob.data();
    const unsigned char *nonce = blob.data() + crypto_box_PUBLICKEYBYTES;
    const unsigned char *ciphertext = blob.data() + header;
    const size_t ciphertext_len = blob.size() - header;

    std::vector<unsigned char> decrypted(ciphertext_len - crypto_box_MACBYTES);
    if (crypto_box_open_easy(decrypted.data(), ciphertext, ciphertext_len, nonce, sender_pk, my_sk) != 0)
    {
        std::cerr << "Message was forged or damaged" << std::endl;
        return false;
    }

    char sender_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(sender_hex, sizeof(sender_hex), sender_pk, crypto_box_PUBLICKEYBYTES);
    std::cout << "From: " << sender_hex << std::endl;
    std::cout << "Message: " << std::string(decrypted.begin(), decrypted.end()) << std::endl;
    return true;
}
bool send_message(const unsigned char *my_pk, const unsigned char *my_sk, const std::string &their_pk_hex, const std::string &text, const std::string &out_path)
{
    std::vector<unsigned char> blob;
    if (!encrypt_message(my_pk, my_sk, their_pk_hex, text, blob))
    {
        return false;
    }

    std::ofstream out(out_path, std::ios::binary);
    if (!out)
    {
        std::cerr << "Cannot open output file" << std::endl;
        return false;
    }
    out.write(reinterpret_cast<const char *>(blob.data()), static_cast<std::streamsize>(blob.size()));
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
        std::cerr << "Cannot read message file" << std::endl;
        return false;
    }

    std::ifstream in(in_path, std::ios::binary);
    if (!in)
    {
        std::cerr << "Cannot open message file" << std::endl;
        return false;
    }

    std::vector<unsigned char> blob(static_cast<size_t>(total));
    in.read(reinterpret_cast<char *>(blob.data()), static_cast<std::streamsize>(blob.size()));
    if (!in)
    {
        std::cerr << "Message file is damaged" << std::endl;
        return false;
    }
    return decrypt_message(my_sk, blob);
}
bool write_frame(tcp::socket &socket, const std::vector<unsigned char> &payload)
{
    const auto length = static_cast<std::uint32_t>(payload.size());
    std::vector<unsigned char> frame;
    frame.reserve(4 + payload.size());
    frame.push_back(static_cast<unsigned char>(length >> 24));
    frame.push_back(static_cast<unsigned char>(length >> 16));
    frame.push_back(static_cast<unsigned char>(length >> 8));
    frame.push_back(static_cast<unsigned char>(length));
    frame.insert(frame.end(), payload.begin(), payload.end());

    asio::error_code ec;
    asio::write(socket, asio::buffer(frame), ec);
    return !ec;
}
bool read_frame(tcp::socket &socket, std::vector<unsigned char> &body)
{
    std::array<unsigned char, 4> header{};
    asio::error_code ec;
    asio::read(socket, asio::buffer(header), ec);
    if (ec)
    {
        return false;
    }

    const std::uint32_t length =
        (static_cast<std::uint32_t>(header[0]) << 24) |
        (static_cast<std::uint32_t>(header[1]) << 16) |
        (static_cast<std::uint32_t>(header[2]) << 8) |
        static_cast<std::uint32_t>(header[3]);
    if (length > protocol::kMaxFrameSize)
    {
        return false;
    }

    body.resize(length);
    asio::read(socket, asio::buffer(body), ec);
    return !ec;
}
bool connect_to_server(tcp::socket &socket)
{
    asio::error_code ec;
    const auto address = asio::ip::make_address(kServerHost, ec);
    if (!ec)
    {
        socket.connect(tcp::endpoint(address, kServerPort), ec);
    }
    if (ec)
    {
        std::cerr << "Cannot connect to server: " << ec.message() << std::endl;
        return false;
    }
    return true;
}
bool register_on_server(tcp::socket &socket, const unsigned char *pk)
{
    std::vector<unsigned char> payload;
    payload.push_back(protocol::kMsgRegister);
    payload.insert(payload.end(), pk, pk + protocol::kPublicKeySize);

    std::vector<unsigned char> reply;
    if (!write_frame(socket, payload) || !read_frame(socket, reply))
    {
        std::cerr << "Connection to server lost" << std::endl;
        return false;
    }
    if (reply.size() != 1 || reply[0] != protocol::kMsgOk)
    {
        std::cerr << "Server refused registration" << std::endl;
        return false;
    }
    return true;
}
bool listen_for_messages(const unsigned char *pk, const unsigned char *sk)
{
    asio::io_context io;
    tcp::socket socket(io);
    if (!connect_to_server(socket) || !register_on_server(socket, pk))
    {
        return false;
    }
    std::cout << "Online. Waiting for messages (Ctrl+C to quit)..." << std::endl;

    std::vector<unsigned char> frame;
    while (read_frame(socket, frame))
    {
        if (frame.empty() || frame[0] != protocol::kMsgDeliver)
        {
            continue;
        }
        const std::vector<unsigned char> blob(frame.begin() + 1, frame.end());
        decrypt_message(sk, blob);
    }
    std::cout << "Disconnected from server" << std::endl;
    return true;
}
bool send_via_server(const unsigned char *my_pk, const unsigned char *my_sk, const std::string &their_pk_hex, const std::string &text)
{
    unsigned char their_pk[crypto_box_PUBLICKEYBYTES];
    if (!parse_public_key_hex(their_pk_hex, their_pk))
    {
        return false;
    }

    std::vector<unsigned char> blob;
    if (!encrypt_message(my_pk, my_sk, their_pk_hex, text, blob))
    {
        return false;
    }

    std::vector<unsigned char> payload;
    payload.reserve(1 + protocol::kPublicKeySize + blob.size());
    payload.push_back(protocol::kMsgSend);
    payload.insert(payload.end(), their_pk, their_pk + protocol::kPublicKeySize);
    payload.insert(payload.end(), blob.begin(), blob.end());
    if (payload.size() > protocol::kMaxFrameSize)
    {
        std::cerr << "Message is too long" << std::endl;
        return false;
    }

    asio::io_context io;
    tcp::socket socket(io);
    if (!connect_to_server(socket))
    {
        return false;
    }

    std::vector<unsigned char> reply;
    if (!write_frame(socket, payload) || !read_frame(socket, reply))
    {
        std::cerr << "Connection to server lost" << std::endl;
        return false;
    }

    if (reply.size() == 1 && reply[0] == protocol::kMsgOk)
    {
        return true;
    }
    if (reply.size() == 2 && reply[0] == protocol::kMsgError && reply[1] == protocol::kErrNotOnline)
    {
        std::cerr << "Recipient is offline (offline delivery is not implemented yet)" << std::endl;
        return false;
    }
    std::cerr << "Server refused the message" << std::endl;
    return false;
}

#ifdef _WIN32
struct ConsoleUtf8
{
    UINT old_cp;
    ConsoleUtf8() : old_cp(GetConsoleOutputCP())
    {
        SetConsoleOutputCP(CP_UTF8);
    }
    ~ConsoleUtf8()
    {
        SetConsoleOutputCP(old_cp);
    }
};
#endif

// Аргументы командной строки всегда в UTF-8. На Windows обычный argv приходит в "ANSI"-кодировке (cp1251 и т.п.) и ломает кириллицу, поэтому берём настоящую строку в UTF-16 и конвертируем сами.
std::vector<std::string> get_utf8_args(int argc, char *argv[])
{
    std::vector<std::string> args;
#ifdef _WIN32
    int wargc = 0;
    LPWSTR *wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    if (wargv != nullptr)
    {
        for (int i = 0; i < wargc; ++i)
        {
            const int wlen = static_cast<int>(wcslen(wargv[i]));
            const int size = WideCharToMultiByte(CP_UTF8, 0, wargv[i], wlen, nullptr, 0, nullptr, nullptr);
            std::string arg(static_cast<size_t>(size), '\0');
            if (size > 0)
            {
                WideCharToMultiByte(CP_UTF8, 0, wargv[i], wlen, arg.data(), size, nullptr, nullptr);
            }
            args.push_back(std::move(arg));
        }
        LocalFree(wargv);
        return args;
    }
#endif
    for (int i = 0; i < argc; ++i)
    {
        args.emplace_back(argv[i]);
    }
    return args;
}

int main(int argc, char *argv[])
{
    #ifdef _WIN32
    const ConsoleUtf8 console_utf8;
    #endif
    const std::vector<std::string> args = get_utf8_args(argc, argv);

    if (args.size() < 2)
    {
        std::cerr << "Usage: secys_cli <identity-file>" << std::endl;
        return 1;
    }
    const std::string identity_path = args[1];

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

    if (args.size() == 6 && args[2] == "send")
    {
        if (!send_message(pk, sk, args[3], args[4], args[5]))
        {
            return 1;
        }
        std::cout << "Message written to " << args[5] << std::endl;
    }

    else if (args.size() == 4 && args[2] == "recv")
    {
        if (!recv_message(sk, args[3]))
        {
            return 1;
        }
    }

    else if (args.size() == 3 && args[2] == "listen")
    {
        if (!listen_for_messages(pk, sk))
        {
            return 1;
        }
    }

    else if (args.size() == 5 && args[2] == "sendnet")
    {
        if (!send_via_server(pk, sk, args[3], args[4]))
        {
            return 1;
        }
        std::cout << "Message sent via server" << std::endl;
    }

    else if (args.size() > 2)
    {
        std::cerr << "Usage: secys_cli <identity> send <their-pk-hex> <text> <out-file>\n"
                  << "       secys_cli <identity> recv <in-file>\n"
                  << "       secys_cli <identity> listen\n"
                  << "       secys_cli <identity> sendnet <their-pk-hex> <text>" << std::endl;
        return 1;
    }

    sodium_memzero(sk, sizeof(sk));
    return 0;
}
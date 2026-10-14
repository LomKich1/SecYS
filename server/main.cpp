#include <asio.hpp>
#include <protocol.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using asio::ip::tcp;
using namespace protocol;

using PublicKey = std::array<unsigned char, kPublicKeySize>;

class Session;
using Registry = std::map<PublicKey, std::weak_ptr<Session>>;

std::string short_hex(const PublicKey &key)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < 4; ++i)
    {
        oss << std::setw(2) << static_cast<int>(key[i]);
    }
    return oss.str();
}

class Session : public std::enable_shared_from_this<Session>
{
public:
    Session(tcp::socket socket, Registry &registry)
        : socket_(std::move(socket)), registry_(registry) {}

    void start()
    {
        asio::error_code ec;
        const auto ep = socket_.remote_endpoint(ec);
        if (!ec)
        {
            std::cout << "Client connected: " << ep << std::endl;
        }
        read_header();
    }

private:
    void read_header()
    {
        auto self = shared_from_this();
        asio::async_read(socket_, asio::buffer(header_),
                         [this, self](const asio::error_code &ec, size_t)
                         {
                             if (ec)
                             {
                                 finish("Client disconnected");
                                 return;
                             }
                             const std::uint32_t length =
                                 (static_cast<std::uint32_t>(header_[0]) << 24) |
                                 (static_cast<std::uint32_t>(header_[1]) << 16) |
                                 (static_cast<std::uint32_t>(header_[2]) << 8) |
                                 static_cast<std::uint32_t>(header_[3]);
                             if (length > kMaxFrameSize)
                             {
                                 finish("Frame too large (" + std::to_string(length) + "), closing");
                                 return;
                             }
                             read_body(length);
                         });
    }

    void handle_send()
    {
        if (body_.size() < 1 + kPublicKeySize + 1)
        {
            send_error(kErrBadFrame);
            return;
        }
        const auto key_end = body_.begin() + 1 + static_cast<std::ptrdiff_t>(kPublicKeySize);
        PublicKey recipient{};
        std::copy(body_.begin() + 1, key_end, recipient.begin());

        std::shared_ptr<Session> target;
        const auto it = registry_.find(recipient);
        if (it != registry_.end())
        {
            target = it->second.lock();
        }
        if (!target)
        {
            send_error(kErrNotOnline);
            return;
        }

        const std::vector<unsigned char> blob(key_end, body_.end());
        target->deliver(blob);
        std::cout << "Relayed " << blob.size() << " bytes to " << short_hex(recipient) << "..." << std::endl;
        send_frame({kMsgOk});
    }

    void deliver(const std::vector<unsigned char> &blob)
    {
        std::vector<unsigned char> payload;
        payload.reserve(1 + blob.size());
        payload.push_back(kMsgDeliver);
        payload.insert(payload.end(), blob.begin(), blob.end());
        send_frame(payload);
    }

    void read_body(std::uint32_t length)
    {
        body_.resize(length);
        auto self = shared_from_this();
        asio::async_read(socket_, asio::buffer(body_),
                         [this, self](const asio::error_code &ec, size_t)
                         {
                             if (ec)
                             {
                                 finish("Client disconnected");
                                 return;
                             }
                             handle_frame();
                             read_header();
                         });
    }

    void handle_frame()
    {
        if (body_.empty())
        {
            send_error(kErrBadFrame);
            return;
        }
        switch (body_[0])
        {
        case kMsgRegister:
            handle_register();
            break;
        case kMsgSend:
            handle_send();
            break;
        default:
            send_error(kErrUnknownType);
            break;
        }
    }

    void handle_register()
    {
        if (body_.size() != 1 + kPublicKeySize)
        {
            send_error(kErrBadFrame);
            return;
        }
        unregister();
        std::copy(body_.begin() + 1, body_.end(), pk_.begin());
        registry_[pk_] = weak_from_this();
        registered_ = true;
        std::cout << "Registered " << short_hex(pk_) << "..." << std::endl;
        send_frame({kMsgOk});
    }

    void unregister()
    {
        if (!registered_)
        {
            return;
        }
        registered_ = false;
        const auto it = registry_.find(pk_);
        if (it != registry_.end() && it->second.lock().get() == this)
        {
            registry_.erase(it);
            std::cout << "Unregistered " << short_hex(pk_) << "..." << std::endl;
        }
    }

    void send_error(unsigned char code)
    {
        send_frame({kMsgError, code});
    }

    void send_frame(const std::vector<unsigned char> &payload)
    {
        const auto length = static_cast<std::uint32_t>(payload.size());
        std::vector<unsigned char> frame;
        frame.reserve(4 + payload.size());
        frame.push_back(static_cast<unsigned char>(length >> 24));
        frame.push_back(static_cast<unsigned char>(length >> 16));
        frame.push_back(static_cast<unsigned char>(length >> 8));
        frame.push_back(static_cast<unsigned char>(length));
        frame.insert(frame.end(), payload.begin(), payload.end());
        out_queue_.push_back(std::move(frame));
        if (!writing_)
        {
            writing_ = true;
            do_write();
        }
    }

    void do_write()
    {
        auto self = shared_from_this();
        asio::async_write(socket_, asio::buffer(out_queue_.front()),
                          [this, self](const asio::error_code &ec, size_t)
                          {
                              if (ec)
                              {
                                  finish("Client disconnected");
                                  return;
                              }
                              out_queue_.pop_front();
                              if (out_queue_.empty())
                              {
                                  writing_ = false;
                              }
                              else
                              {
                                  do_write();
                              }
                          });
    }

    void finish(const std::string &reason)
    {
        if (finished_)
        {
            return;
        }
        finished_ = true;
        std::cout << reason << std::endl;
        unregister();
        asio::error_code ignored;
        socket_.close(ignored);
    }

    tcp::socket socket_;
    Registry &registry_;
    std::array<unsigned char, 4> header_{};
    std::vector<unsigned char> body_;
    std::deque<std::vector<unsigned char>> out_queue_;
    bool writing_ = false;
    bool finished_ = false;
    bool registered_ = false;
    PublicKey pk_{};
};

class Server
{
public:
    Server(asio::io_context &io, unsigned short port)
        : acceptor_(io, tcp::endpoint(asio::ip::address_v4::loopback(), port))
    {
        do_accept();
    }

private:
    void do_accept()
    {
        acceptor_.async_accept(
            [this](const asio::error_code &ec, tcp::socket socket)
            {
                if (!ec)
                {
                    std::make_shared<Session>(std::move(socket), registry_)->start();
                }
                do_accept();
            });
    }

    tcp::acceptor acceptor_;
    Registry registry_;
};

int main()
{
    try
    {
        asio::io_context io;
        Server server(io, 9000);
        std::cout << "Server is listening on 127.0.0.1:9000" << std::endl;
        io.run();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
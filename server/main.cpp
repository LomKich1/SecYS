#include <asio.hpp>
#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

using asio::ip::tcp;

constexpr std::uint32_t kMaxFrameSize = 64 * 1024;

class Session : public std::enable_shared_from_this<Session>
{
public:
    explicit Session(tcp::socket socket) : socket_(std::move(socket)) {}

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
                    std::cout << "Client disconnected" << std::endl;
                    return;
                }
                const std::uint32_t length =
                    (static_cast<std::uint32_t>(header_[0]) << 24) |
                    (static_cast<std::uint32_t>(header_[1]) << 16) |
                    (static_cast<std::uint32_t>(header_[2]) << 8) |
                    static_cast<std::uint32_t>(header_[3]);
                if (length > kMaxFrameSize)
                {
                    std::cout << "Frame too large (" << length << "), closing" << std::endl;
                    return;
                }
                read_body(length);
            });
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
                    std::cout << "Client disconnected" << std::endl;
                    return;
                }
                std::cout << "frame " << body_.size() << " bytes" << std::endl;
                write_frame();
            });
    }

    void write_frame()
    {
        out_.assign(header_.begin(), header_.end());
        out_.insert(out_.end(), body_.begin(), body_.end());
        auto self = shared_from_this();
        asio::async_write(socket_, asio::buffer(out_),
            [this, self](const asio::error_code &ec, size_t)
            {
                if (ec)
                {
                    std::cout << "Client disconnected" << std::endl;
                    return;
                }
                read_header();
            });
    }

    tcp::socket socket_;
    std::array<unsigned char, 4> header_{};
    std::vector<unsigned char> body_;
    std::vector<unsigned char> out_;
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
                    std::make_shared<Session>(std::move(socket))->start();
                }
                do_accept();
            });
    }

    tcp::acceptor acceptor_;
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
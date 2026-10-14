#include <asio.hpp>
#include <iostream>
#include <memory>

using asio::ip::tcp;

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
        do_read();
    }

private:
    void do_read()
    {
        auto self = shared_from_this();
        socket_.async_read_some(asio::buffer(data_),
            [this, self](const asio::error_code &ec, size_t n)
            {
                if (ec)
                {
                    std::cout << "Client disconnected" << std::endl;
                    return;
                }
                do_write(n);
            });
    }

    void do_write(size_t n)
    {
        auto self = shared_from_this();
        asio::async_write(socket_, asio::buffer(data_, n),
            [this, self](const asio::error_code &ec, size_t)
            {
                if (ec)
                {
                    std::cout << "Client disconnected" << std::endl;
                    return;
                }
                do_read();
            });
    }

    tcp::socket socket_;
    char data_[1024];
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
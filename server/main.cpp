#include <asio.hpp>
#include <iostream>

using asio::ip::tcp;

int main()
{
    try
    {
        asio::io_context io;
        tcp::acceptor acceptor(io, tcp::endpoint(asio::ip::address_v4::loopback(), 9000));
        std::cout << "Server is listening on 127.0.0.1:9000" << std::endl;

        for (;;)
        {
            tcp::socket socket(io);
            acceptor.accept(socket);
            std::cout << "Client connected: " << socket.remote_endpoint() << std::endl;

            char data[1024];
            asio::error_code ec;
            for (;;)
            {
                const size_t n = socket.read_some(asio::buffer(data), ec);
                if (ec)
                {
                    break;
                }
                asio::write(socket, asio::buffer(data, n), ec);
                if (ec)
                {
                    break;
                }
            }
            std::cout << "Client disconnected" << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
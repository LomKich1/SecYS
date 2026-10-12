#include <sodium.h>
#include <iostream>

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    std::cout << "Libsodium initialized successfully!" << std::endl;
    return 0;
}
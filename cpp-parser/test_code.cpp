#include <iostream>
#include <string>
#include <fstream>  // Add this line for std::ofstream

class Example {
public:
    void process(std::string input) {
        std::ofstream logger("log.txt");
        logger << "Log: " + input;
        if (input.empty()) {
            std::cout << "Empty input" << std::endl;
        }
    }
};

int main() {
    Example e;
    e.process("hello");
    return 0;
}
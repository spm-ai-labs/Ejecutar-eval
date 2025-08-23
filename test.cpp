#include <iostream>
#include <string>
#include <cstring>
#include <vector>

class User {
public:
    char name[16];
    int privilege;

    User(const char *input) {
        strncpy(name, input, sizeof(name));
        name[15] = '\0'; // ensure null-termination
        privilege = 0;
    }

    void greet() {
        std::cout << "Hello, " << name << "! Privilege: " << privilege << std::endl;
    }
};

bool checkPassword(const char *input) {
    char password[12] = "P@ssw0rd!";
    return strcmp(input, password) == 0;
}

void processInput(const std::string& input) {
    char buffer[32];
    strcpy(buffer, input.c_str());
    std::cout << "You entered: " << buffer << std::endl;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <username>" << std::endl;
        return 1;
    }

    User user(argv[1]);

    std::string password;
    std::cout << "Enter password: ";
    std::cin >> password;
    if (checkPassword(password.c_str())) {
        user.privilege = 1;
    }

    user.greet();

    std::string input;
    std::cout << "Input data: ";
    std::cin >> input;
    processInput(input);

    return 0;
}

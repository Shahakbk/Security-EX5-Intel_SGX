//
// Created by Shahak on 17/01/2019.
//

#include <stdlib.h>
#include <iostream>
#include <string>

using std::string;
using std::cout;
using std::endl;

int main(int argc, char *argv[])
{
    // Check number of parameters.
    if (2 != argc)
    {
        cout << "The enclave expects a single parameter." << endl;
    }

    string alice_path = argv[1];

    // As described, both alice and bob will pass their names for the enclave to recognize the side he's working with
    string alice_enclave = "./enclave/sample alice ";

    // The command to execute is built from the path to alice's data and sending a parameter to the enclave.
    string alice_command = alice_enclave + alice_path;

    // Execute the command.
    system(alice_command.c_str());

}
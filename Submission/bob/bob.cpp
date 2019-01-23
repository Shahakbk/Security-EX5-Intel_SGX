//
// Created by Shahak on 17/01/2019.
//

#include <stdlib.h>
#include <iostream>
#include <string>

using std::string;

int main(int argc, char *argv[])
{
    string bob_path = argv[1];
    // as described, both alice and bob will pass their names for the enclave to recognize the side he's working with
    string bob_enclave = "./enclave/sample bob";

    // the command to execute is built from the path to bob's data and sending a parameter to the enclave.
    string bob_command = bob_enclave + bob_path;

    // execute the command.
    system(bob_command.c_str());

}
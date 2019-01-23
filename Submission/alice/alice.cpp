//
// Created by Shahak on 17/01/2019.
//

#include <stdlib.h>
#include <iostream>
#include <string>

using std::string;

int main(int argc, char *argv[])
{
    string alice_path = argv[1];
    // as described, both alice and bob will pass their names for the enclave to recognize the side he's working with
    string alice_enclave = "./enclave/sample alice";

    // the command to execute is built from the path to alice's data and sending a parameter to the enclave.
    string alice_command = alice_enclave + alice_path;

    // execute the command.
    system(alice_command.c_str());

}
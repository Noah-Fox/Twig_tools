#include <iostream>
#include <string.h>

using namespace std;

int DEBUG = 0;

void cliHelp(string cmd);

int main(int argc, char *argv[]){
    string ipAddr = "";

    for (int i = 1; i < argc; i ++){
        if (strcmp(argv[i], "-d") == 0){
            DEBUG ++;
        }
        else if (strcmp(argv[i], "-i") == 0){
            if (i == argc-1){
                cliHelp(argv[0]);
            }
            ipAddr = argv[i+1];
            i++;
        }
        else {
            cliHelp(argv[0]);
        }
    }
    if (ipAddr == ""){
        cliHelp(argv[0]);
    }

    if (DEBUG){
        cout << "Beginning twig on IPv4 Address " << ipAddr << "\n";
    }
}

void cliHelp(string cmd){
    cout << "Usage: " << cmd << " [-d] -i IPv4addr_masklength\n";
    exit(0);
}
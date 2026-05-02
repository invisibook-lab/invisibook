#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <chrono>
#include "sha256_compare.h"

using namespace emp;

static void print_usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s <party> <port> [host]\n"
        "       --v <value>          uint64 secret value\n"
        "       --r <hex>            256-bit randomness (64 hex chars)\n"
        "       --c1 <hex>           commitment C1 = SHA-256(v1||r1) (64 hex chars)\n"
        "       --c2 <hex>           commitment C2 = SHA-256(v2||r2) (64 hex chars)\n"
        "       --circuit <path>     path to composed Bristol circuit\n"
        "\n"
        "  party: 1 (Alice/garbler) or 2 (Bob/evaluator)\n"
        "  host:  required for Bob (party 2), e.g. 127.0.0.1\n"
        "  Both parties must provide both commitments C1 and C2.\n"
        "\n"
        "Example:\n"
        "  Alice: %s 1 12345 --v 100 --r aabb...cc --c1 ddee...ff --c2 1122...33\n"
        "  Bob:   %s 2 12345 127.0.0.1 --v 50 --r 4455...66 --c1 ddee...ff --c2 1122...33\n",
        prog, prog, prog
    );
}

int main(int argc, char** argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    int party = atoi(argv[1]);
    int port = atoi(argv[2]);

    if (party != ALICE && party != BOB) {
        fprintf(stderr, "Error: party must be 1 (ALICE) or 2 (BOB)\n");
        return 1;
    }

    // For BOB, the third positional arg is the host
    const char* host = nullptr;
    int arg_start = 3;
    if (party == BOB) {
        if (argc < 4 || argv[3][0] == '-') {
            fprintf(stderr, "Error: Bob (party 2) requires a host address\n");
            return 1;
        }
        host = argv[3];
        arg_start = 4;
    }

    // Parse named arguments
    uint64_t my_v = 0;
    uint8_t my_r[32] = {0};
    uint8_t C1[32] = {0};
    uint8_t C2[32] = {0};
    const char* circuit_file = "circuits/sha256_compare.txt";
    bool has_v = false, has_r = false, has_c1 = false, has_c2 = false;

    for (int i = arg_start; i < argc; i++) {
        if (strcmp(argv[i], "--v") == 0 && i + 1 < argc) {
            my_v = strtoull(argv[++i], nullptr, 10);
            has_v = true;
        } else if (strcmp(argv[i], "--r") == 0 && i + 1 < argc) {
            hex_to_bytes(argv[++i], my_r, 32);
            has_r = true;
        } else if (strcmp(argv[i], "--c1") == 0 && i + 1 < argc) {
            hex_to_bytes(argv[++i], C1, 32);
            has_c1 = true;
        } else if (strcmp(argv[i], "--c2") == 0 && i + 1 < argc) {
            hex_to_bytes(argv[++i], C2, 32);
            has_c2 = true;
        } else if (strcmp(argv[i], "--circuit") == 0 && i + 1 < argc) {
            circuit_file = argv[++i];
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!has_v || !has_r || !has_c1 || !has_c2) {
        fprintf(stderr, "Error: --v, --r, --c1, and --c2 are all required\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("Party %d (%s) | port=%d", party, party == ALICE ? "Alice" : "Bob", port);
    if (host) printf(" | host=%s", host);
    printf(" | v=%lu\n", (unsigned long)my_v);

    // Connect
    NetIO* io = new NetIO(party == ALICE ? nullptr : host, port);

    auto t_start = std::chrono::high_resolution_clock::now();

    CompareResult result = run_sha256_compare(party, io, my_v, my_r, C1, C2, circuit_file);

    auto t_end = std::chrono::high_resolution_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();

    if (!result.valid) {
        printf("ABORT: commitment verification failed\n");
        printf("Time: %.1f ms\n", elapsed_ms);
        delete io;
        return 1;
    }

    printf("Result: v1 %s v2\n", result.v1_greater ? ">" : "<=");
    printf("Time: %.1f ms\n", elapsed_ms);

    delete io;
    return 0;
}

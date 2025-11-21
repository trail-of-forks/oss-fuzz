// fuzz_topo_compute.cc
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core.h"
#include "topo.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 20)
        return 0;

    struct ncclTopoSystem *system;
    ncclCalloc(&system, 1);
    if (!system)
        return 0;

    // Set system parameters from fuzz data
    // Note: is this enough input?
    system->nodes[NCCL_TOPO_NODE_GPU].count = (data[0] % 8) + 1;
    system->nodes[NCCL_TOPO_NODE_NIC].count = (data[1] % 4);
    system->nodes[NCCL_TOPO_NODE_CPU].count = (data[2] % 4) + 1;
    ncclTopoComputePaths(system, NULL);

    free(system);
    return 0;
}
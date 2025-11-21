#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core.h"
#include "topo.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16)
        return 0;

    struct ncclTopoSystem *system;
    ncclCalloc(&system, 1);
    if (!system) 
        return 0;

    // Set up GPUs with fuzzed data
    int nranks = (data[0] % 8) + 1;
    system->nodes[NCCL_TOPO_NODE_GPU].count = nranks;

    for (int i = 0; i < nranks && i < size - 1; i++) {
        system->nodes[NCCL_TOPO_NODE_GPU].nodes[i].gpu.dev = data[i + 1] % 16;
    }

    // Test ranking
    int rank = data[8] % nranks;
    ncclTopoIdToIndex(system, NCCL_TOPO_NODE_GPU, rank);

    free(system);
    return 0;
}
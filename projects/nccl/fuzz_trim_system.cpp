#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core.h"
#include "topo.h"
#include "graph.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10)
        return 0;

    struct ncclTopoSystem *system;
    ncclCalloc(&system, 1);
    if (!system)
        return 0;

    system->nodes[NCCL_TOPO_NODE_GPU].count = (data[0] % 8) + 1;

    struct ncclTopoGraph graph;
    memset(&graph, 0, sizeof(graph));
    graph.nChannels = (data[1] % 16) + 1;
    graph.pattern = data[2] % 4;
    ncclTopoTrimSystem(system, &graph);

    free(system);
    return 0;
}
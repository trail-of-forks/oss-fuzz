#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core.h"
#include "graph.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8)
    return 0;
  
  struct ncclTopoGraph *graph;
  ncclCalloc(&graph, 1);
  if (!graph)
    return 0;
  
  // Set graph properties from fuzz data
  // Not sure whether additional validation of inputs is needed
  graph->nChannels = (data[0] % 32) + 1;
  graph->speedIntra = data[1] % 256;
  graph->speedInter = data[2] % 256;
  graph->type = data[3] % 4;
  graph->pattern = data[4] % 4;
  
  int nChannels = 0;
  ncclTopoSearchParams(graph, graph->pattern, &nChannels);

  free(graph);
  return 0;
}
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "nccl.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5)
      return 0;

    // Parse fuzzer input
    int nRanks = (data[0] % 8) + 1;  // 1-8 ranks
    int rank = data[1] % nRanks;
    ncclDataType_t datatype = (ncclDataType_t)(data[2] % 10);
    ncclRedOp_t op = (ncclRedOp_t)(data[3] % 6);
    size_t count = (data[4] % 100) + 1;

    // Initialize NCCL
    ncclComm_t comm;
    ncclUniqueId id;

    if (ncclGetUniqueId(&id) != ncclSuccess)
      return 0;
    if (ncclCommInitRank(&comm, nRanks, id, rank) != ncclSuccess)
      return 0;

    // Allocate buffers
    void *sendbuff = malloc(count * 4);
    void *recvbuff = malloc(count * 4);
    if (!sendbuff || !recvbuff) {
        free(sendbuff);
        free(recvbuff);
        ncclCommDestroy(comm);
        return 0;
    }

    memcpy(sendbuff, data + 16, (size - 16) < (count * 4) ? (size - 16) : (count * 4));
    ncclAllReduce(sendbuff, recvbuff, count, datatype, op, comm, NULL);

    free(sendbuff);
    free(recvbuff);
    ncclCommDestroy(comm);
    
    return 0;
}

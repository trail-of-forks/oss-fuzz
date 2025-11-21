#include <stdint.h>
#include <string.h>
#include "nccl.h"
#include "core.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;

    ncclRedOp_t op = (ncclRedOp_t)(data[0] % 10);
    ncclDataType_t datatype = (ncclDataType_t)(data[1] % 16);
    ncclRedOp_t customOp;

    // Test PreMulSum scalar
    double scalar;
    memcpy(&scalar, data + 2, sizeof(double));



    ncclRedOpCreatePreMulSum(&customOp, &scalar, datatype, ncclScalarHostImmediate, NULL);

    if (customOp != NULL) {
        ncclRedOpDestroy(customOp, NULL);
    }

    return 0;
}
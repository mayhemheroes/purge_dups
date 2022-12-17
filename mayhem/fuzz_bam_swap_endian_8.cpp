#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "bamlite.c"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    uint64_t v = provider.ConsumeIntegral<uint64_t>();
    bam_swap_endian_8(v);

    return 0;
}
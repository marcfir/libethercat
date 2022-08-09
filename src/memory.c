#include "libethercat/ec.h"
#include "libethercat/memory.h"

#include <stdlib.h>

#if 0 
typedef uint8_t big_chunk[2048];
typedef uint8_t small_chunk[128];

void *ec_malloc(size_t size) {
    void *ret;

#define CHUNK_POOL_SIZE 2048
    static int big_pool_index = 0;
    static big_chunk big_pool[CHUNK_POOL_SIZE];

    static int small_pool_index = 0;
    static small_chunk small_pool[CHUNK_POOL_SIZE];

    if (size <= 128u) {
        if (small_pool_index >= CHUNK_POOL_SIZE) {
//            ec_log(1, __func__, "out of small pool mem\n");
            ret = NULL;
        } else {
            //        ec_log(100, __func__, "size %d taken from small pool, cnt %d\n", size, small_pool_index);
            ret = small_pool[small_pool_index];
            small_pool_index++;
        }
    } else if (size <= 2048u) {
        if (big_pool_index >= CHUNK_POOL_SIZE) {
            ec_log(1, __func__, "out of big pool mem\n");
            ret = NULL;
        } else {
            //        ec_log(100, __func__, "size %d taken from big pool, cnt %d\n", size, big_pool_index);
            ret = big_pool[big_pool_index];
            big_pool_index++;
        }
    } else {
//        ec_log(5, __func__, "size %d doing old-school-malloc!\n", size);
        ret = malloc(size);
    }

    return ret;
}

void ec_free(void *ptr) {
    (void)ptr;
//    ec_log(5, __func__, "not possible\n");
}
#else
void *ec_malloc(size_t size) { 
    return malloc(size);
}

void ec_free(void *ptr) {
    free(ptr);
}
#endif

#include "rapl_stopwatch.h"

#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char const *argv[]) {
    int err = rapl_energy_api_init();
    if (err) {
        fprintf(stderr, "Error initializing the API\n");
        return -1;
    }

    rapl_stopwatch_t rapl_sw;
    rapl_stopwatch_init(&rapl_sw);

    rapl_stopwatch_play(&rapl_sw);
    sleep(1);
    rapl_stopwatch_pause(&rapl_sw);

    uint64_t count = 0;
    err = rapl_stopwatch_get_mj(&rapl_sw, RAPL_NODE, &count);
    if (err) {
        fprintf(stderr, "Error reading the counter\n");
        return -1;
    }

    printf("mJ: %" PRIu64 "\n", count);

    rapl_stopwatch_destroy(&rapl_sw);
    rapl_energy_api_destroy();

    return 0;
}

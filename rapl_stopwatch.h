#include <stdint.h>

typedef enum {
    RAPL_PACKAGE,
    RAPL_CORE,
    RAPL_UNCORE,
    RAPL_DRAM,
    RAPL_NODE,

    NUM_RAPL_DOMAINS,
} rapl_domain_t;

typedef struct rapl_stopwatch_s {
    uint64_t *last_read_mj;
    uint64_t *total_count_mj;
} rapl_stopwatch_t;

int rapl_energy_api_init(void);

void rapl_energy_api_destroy(void);

void rapl_stopwatch_init(rapl_stopwatch_t *const rapl_sw);

void rapl_stopwatch_destroy(rapl_stopwatch_t *const rapl_sw);

void rapl_stopwatch_reset(rapl_stopwatch_t *const rapl_sw);

void rapl_stopwatch_play(rapl_stopwatch_t *const rapl_sw);

void rapl_stopwatch_pause(rapl_stopwatch_t *const rapl_sw);

int rapl_stopwatch_get_mj(rapl_stopwatch_t *const rapl_sw, const rapl_domain_t domain,
                          uint64_t *const total_mj_domain);

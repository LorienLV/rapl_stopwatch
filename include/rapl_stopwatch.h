#ifndef _RAPL_STOPWATCH_H_
#define _RAPL_STOPWATCH_H_

/**
 * A thread-safe library to measure energy consumption using Intel Running Average
 * Power Limit (RAPL) sysfs files. The library handles overflows in the RAPL files
 * using an extended energy counter for each file that is periodically updated
 * by a thread.
 *
 * @author Lorién López Villellas (lorien.lopez@bsc.es)
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// The RAPL domains.
typedef enum {
    RAPL_PACKAGE,   // The packages of the system (cores + uncore)
    RAPL_CORE,      // The cores of the CPUs 
    RAPL_UNCORE,    // Everything inside the packages but not the cores.
    RAPL_DRAM,      // The main memory.
    RAPL_NODE,      // All the node.

    NUM_RAPL_DOMAINS,
} rapl_domain_t;

typedef struct rapl_stopwatch_s {
    uint64_t *last_read_mj;
    uint64_t *total_count_mj;
} rapl_stopwatch_t;

/**
 * Prepare the library to start measuring energy using RAPL sysfs files.
 * This function must be called before instantiating any rapl_stopwatch.
 * Returns 0 on success or a number different from 0 otherwise.
 *
 * @return 0 on success or a number different from 0 otherwise.
 */
int rapl_stopwatch_api_init(void);

/**
 * Destroy the RAPL-stopwatch API. Clean all dynamic memory allocated when initializing
 * the API.
 *
 */
void rapl_stopwatch_api_destroy(void);

/**
 * Initialize the given rapl_stopwatch.
 *
 * @param rapl_sw A pointer to a rapl_stopwatch.
 */
void rapl_stopwatch_init(rapl_stopwatch_t *const rapl_sw);

/**
 * Destroy the given rapl_stopwatch. Clean all dynamic memory allocated when 
 * initializing the rapl_stopwatch.
 *
 * @param rapl_sw A pointer to a rapl_stopwatch.
 */
void rapl_stopwatch_destroy(rapl_stopwatch_t *const rapl_sw);

/**
 * Reset the energy counters of the given rapl_stopwatch.
 *
 * @param rapl_sw A pointer to a rapl_stopwatch.
 */
void rapl_stopwatch_reset(rapl_stopwatch_t *const rapl_sw);

/**
 * Start counting energy consumption in the given rapl_stopwatch.
 *
 * @param rapl_sw A pointer to a rapl_stopwatch.
 */
void rapl_stopwatch_play(rapl_stopwatch_t *const rapl_sw);

/**
 * Stop counting energy consumption in the given rapl_stopwatch. This function
 * does NOT reset the energy counters.
 *
 * @param rapl_sw A pointer to a rapl_stopwatch.
 */
void rapl_stopwatch_pause(rapl_stopwatch_t *const rapl_sw);

/**
 * Get the total energy consumption (in mJ) measured by the given rapl_stopwatch
 * in the RAPL domain DOMAIN. The value will be sotored in TOTAL_MJ_DMIAN.
 * Return 0 on success or a number different from 0 otherwise.
 * 
 * @param rapl_sw A pointer to a rapl_stopwatch.
 * @param domain The RAPL domain.
 * @param total_mj_domain On return, it will contain the total energy consumption
 * in mJ.
 * @return 0 on success or a number different from 0 otherwise.
 */
int rapl_stopwatch_get_mj(const rapl_stopwatch_t *const rapl_sw,
                          const rapl_domain_t domain,
                          uint64_t *const total_mj_domain);

#ifdef __cplusplus
}
#endif

#endif
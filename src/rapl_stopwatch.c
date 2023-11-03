#include "rapl_stopwatch.h"

#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_CPUS 1024
#define MAX_PACKAGES 16

static int num_packages = 0;
static int num_cores = 0;

#define DOMAIN_NAME_SIZE 30
#define FILE_NAME_SIZE 256
// The energy-file of each package domain. Example for package 0:
// subdirectories intel-rapl:0:0/energy_uj intel-rapl:0:1/energy_uj
static char *package_domain_energy_files = NULL;

#define RAPL_ROOT_PATH "/sys/class/powercap/intel-rapl/intel-rapl:%d"
#define RAPL_SUBDOMAIN_PATH "/intel-rapl:%d:%d"

/*
 * Global state updated by the updater tread and read when playing pausing the
 * rapl_stopwatches.
 */

static uint64_t *last_read_uj = NULL;
static uint64_t *extended_counter_mj = NULL;
static uint64_t *max_uj = NULL;

static pthread_rwlock_t global_state_lock;

/*
 * Updater thread.
 */

#define UPDATER_WAIT_SEC 30

static pthread_t updater_thread;
static sem_t updater_thread_sem;   // Used to release the thread.

// Clean way to access the counters and the files.
#define counters_idx(i, j) ((i)*NUM_RAPL_DOMAINS + (j))
#define files_idx(i, j, k) \
    ((i)*NUM_RAPL_DOMAINS * FILE_NAME_SIZE + (j)*FILE_NAME_SIZE + (k))

/**
 * Get the RAPL_DOMAIN enum corresponding to a given rapl domain name (string).
 *
 * @param domain_name The domain name (string).
 * @param rapl_domain The corresponding RAPL_DOMAIN enum.
 * @return rapl_error_t
 */
static rapl_error_t domain_string_to_rapl_domain(const char *const domain_name,
                                                 rapl_domain_t *const rapl_domain) {

    if (strcmp(domain_name, "core") == 0) {
        *rapl_domain = RAPL_CORE;
    }
    else if (strcmp(domain_name, "uncore") == 0) {
        *rapl_domain = RAPL_UNCORE;
    }
    else if (strcmp(domain_name, "dram") == 0) {
        *rapl_domain = RAPL_DRAM;
    }
    // Can be package_0, package_1 etc.
    // strncmp(name, "package", sizeof("package") - 1) == 0)
    // else if (strcmp(domain_name, "package") == 0) {
    //     *rapl_domain = RAPL_PACKAGE;
    // }
    // TODO: Implement PSYS domain (full node)
    // else if (strcmp(domain_name, "psys") == 0) {
    //     *rapl_domain = RAPL_NODE;
    // }
    else {
        return UNABLE_TO_ACCESS_DOMAIN;
    }

    return SUCCESS;
}

/**
 * Read a value from a file given a format.
 *
 * @param file_name The path to the file.
 * @param format The format of the value to read. This format should follow the
 * scanf's.
 * @param value On return, this variable will contain the value read.
 * @return rapl_error_t.
 */
static rapl_error_t read_from_file(const char *const file_name,
                                   const char *const format,
                                   void *const value) {

    FILE *file = fopen(file_name, "r");
    if (file == NULL) {
        return UNABLE_TO_ACCESS_DOMAIN;
    }

    fscanf(file, format, value);
    fclose(file);

    return SUCCESS;
}

/**
 * Returns true if the domain associated to the package can be read.
 *
 * @param package The package index.
 * @param domain The RAPL domain index.
 * @return true if the domain associated to the package can be read. False
 * otherwise.
 */
static bool valid_domain(const int package, const int domain) {
    return package_domain_energy_files[files_idx(package, domain, 0)] != '\0';
}

/**
 * Get the uJ counter of a the given package and domain by reading the
 * corresponding RAPL file. Also, set the variable UPDATED_EXTENDED_COUNTER_MJ
 * using the read value and the last value of EXTENDED_COUNTER_MJ.
 *
 * @param package The package index.
 * @param domain The domain index.
 * @param uj_now The value read from the corresponding RAPL file.
 * @param updated_extended_counter_mj The updated value of EXTENDED_COUNTER_MJ.
 * @return rapl_error_t.
 */
static rapl_error_t get_updated_counters(const int package,
                                         const int domain,
                                         uint64_t *const uj_now,
                                         uint64_t *const updated_extended_counter_mj) {

    // uJ now.
    if (!valid_domain(package, domain)) {
        return UNABLE_TO_ACCESS_DOMAIN;
    }

    rapl_error_t
        err = read_from_file(&package_domain_energy_files[files_idx(package, domain, 0)],
                             "%" PRId64,
                             uj_now);

    if (err != SUCCESS) {
        return err;
    }

    // Updated extended counter mJ

    uint64_t increment = 0;
    if (*uj_now >= last_read_uj[counters_idx(package, domain)]) {
        increment = *uj_now - last_read_uj[counters_idx(package, domain)];
    }
    else {   // Overflow.
        increment = max_uj[counters_idx(package, domain)] -
                    last_read_uj[counters_idx(package, domain)] + *uj_now;
    }

    *updated_extended_counter_mj = extended_counter_mj[counters_idx(package, domain)] +
                                   increment / 1E3;

    return SUCCESS;
}

/**
 * The thread running this function will periodically (every UPDATER_WAIT_SEC
 * seconds) update EXTENDED_COUNTER_MJ and LAST_READ_UJ arrays. This function is
 * used to detect and correc overflows in the RAPL files.
 *
 * @param vargp Not used.
 * @return NULL.
 */
static void *updater_loop(void *vargp) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    now.tv_sec += UPDATER_WAIT_SEC;

    // Update the global state every UPDATER_WAIT_SEC while updater_thread_sem
    // is equal to 0.
    while (sem_timedwait(&updater_thread_sem, &now) != 0) {
        pthread_rwlock_wrlock(&global_state_lock);

        for (int package = 0; package < num_packages; ++package) {
            for (int domain = 0; domain < NUM_RAPL_DOMAINS; ++domain) {
                uint64_t uj_now;
                uint64_t updated_extended_counter_mj;
                rapl_error_t err = get_updated_counters(package,
                                                        domain,
                                                        &uj_now,
                                                        &updated_extended_counter_mj);

                if (err != SUCCESS) {
                    uj_now = 0;
                    updated_extended_counter_mj = 0;
                }

                last_read_uj[counters_idx(package, domain)] = uj_now;
                extended_counter_mj[counters_idx(package, domain)] = updated_extended_counter_mj;
            }
        }

        pthread_rwlock_unlock(&global_state_lock);

        clock_gettime(CLOCK_REALTIME, &now);
        now.tv_sec += UPDATER_WAIT_SEC;
    }

    return NULL;
}

/**
 * Detect the number of packages and cores in the system. Update the
 * num_packages and num_cores global variables.
 *
 */
static void detect_packages(void) {
    num_packages = 0;
    num_cores = 0;

    bool package_counted[MAX_PACKAGES];
    for (int package = 0; package < MAX_PACKAGES; ++package) {
        package_counted[package] = false;
    }

    for (int cpu = 0; cpu < MAX_CPUS; ++cpu) {
        char cpu_filename[FILE_NAME_SIZE];
        sprintf(cpu_filename,
                "/sys/devices/system/cpu/cpu%d/topology/physical_package_id",
                cpu);

        int package;
        int err = read_from_file(cpu_filename, "%d", &package);
        if (err) {
            break;
        }

        if (!package_counted[package]) {
            ++num_packages;
            package_counted[package] = true;
        }
        ++num_cores;
    }
}

rapl_error_t rapl_stopwatch_api_init(void) {
    // Set num_packages and num_cores.
    detect_packages();

    if (num_packages == 0) {
        fprintf(stderr, "Could not detect the number of packages\n");
        return CONFIG_ERROR;
    }

    last_read_uj = (uint64_t *)malloc(num_packages * NUM_RAPL_DOMAINS *
                                      sizeof(*last_read_uj));
    extended_counter_mj = (uint64_t *)malloc(num_packages * NUM_RAPL_DOMAINS *
                                             sizeof(*extended_counter_mj));
    max_uj = (uint64_t *)malloc(num_packages * NUM_RAPL_DOMAINS * sizeof(*max_uj));

    package_domain_energy_files = (char *)
        malloc(num_packages * NUM_RAPL_DOMAINS * FILE_NAME_SIZE *
               sizeof(*package_domain_energy_files));

    for (int package = 0; package < num_packages; ++package) {
        // Set the energy file name of each RAPL domain of this package to NULL.
        for (int domain = 0; domain < NUM_RAPL_DOMAINS; ++domain) {
            package_domain_energy_files[files_idx(package, domain, 0)] = '\0';
        }

        /*
         * The package domain itself.
         */

        char package_root[FILE_NAME_SIZE - 40];
        sprintf(package_root, RAPL_ROOT_PATH, package);

        // Max value of the energy counter.

        char range_file_name[FILE_NAME_SIZE];
        sprintf(range_file_name, "%s/max_energy_range_uj", package_root);
        int err = read_from_file(range_file_name,
                                 "%lld",
                                 &max_uj[counters_idx(package, RAPL_PACKAGE)]);
        if (err) {
            fprintf(stderr, "Could not read %s\n", range_file_name);
            fprintf(stderr, "Failed to initialize the RAPL energy API.\n");
            return CONFIG_ERROR;
        }

        // Initial uJ read.
        sprintf(&package_domain_energy_files[files_idx(package, RAPL_PACKAGE, 0)],
                "%s/energy_uj",
                package_root);

        uint64_t uj_now;
        err = read_from_file(&package_domain_energy_files[files_idx(package, RAPL_PACKAGE, 0)],
                             "%lld",
                             &uj_now);
        if (err) {
            fprintf(stderr,
                    "Could not read %s\n",
                    &package_domain_energy_files[files_idx(package, RAPL_PACKAGE, 0)]);
            fprintf(stderr, "Failed to initialize the RAPL energy API.\n");
            return CONFIG_ERROR;
        }
        last_read_uj[counters_idx(package, RAPL_PACKAGE)] = uj_now;
        extended_counter_mj[counters_idx(package, RAPL_PACKAGE)] = 0;

        /*
         * Iterate over the package subdomains (DRAM, CORE and UNCORE).
         */
        assert(NUM_RAPL_DOMAINS == 5);   // Something has changed in the RAPL
                                         // api.
        const int num_subdomains = 3;
        for (int domain_idx = 0; domain_idx < num_subdomains; ++domain_idx) {

            // The subdomain name

            char name_file_name[FILE_NAME_SIZE];
            sprintf(name_file_name,
                    "%s" RAPL_SUBDOMAIN_PATH "/name",
                    package_root,
                    package,
                    domain_idx);

            char domain_name[DOMAIN_NAME_SIZE];
            rapl_error_t err = read_from_file(name_file_name, "%s", &domain_name);
            // Cannot access subdomain.
            if (err != SUCCESS) {
                continue;
            }

            rapl_domain_t domain;
            err = domain_string_to_rapl_domain(domain_name, &domain);
            if (err) {
                fprintf(stderr, "Failed to initialize the RAPL energy API.\n");
                return CONFIG_ERROR;
            }

            // Max value of the energy counter.

            char range_file_name[FILE_NAME_SIZE];
            sprintf(range_file_name,
                    "%s" RAPL_SUBDOMAIN_PATH "/max_energy_range_uj",
                    package_root,
                    package,
                    domain_idx);
            err = read_from_file(range_file_name,
                                 "%lld",
                                 &max_uj[counters_idx(package, domain)]);
            // Cannot access subdomain.
            if (err != SUCCESS) {
                continue;
            }

            // Initial uJ read.

            sprintf(&package_domain_energy_files[files_idx(package, domain, 0)],
                    "%s" RAPL_SUBDOMAIN_PATH "/energy_uj",
                    package_root,
                    package,
                    domain_idx);

            uint64_t uj_now;
            err = read_from_file(&package_domain_energy_files[files_idx(package, domain, 0)],
                                 "%lld",
                                 &uj_now);
            // Cannot access subdomain.
            if (err != SUCCESS) {
                package_domain_energy_files[files_idx(package, domain, 0)] = '\0';
                continue;
            }

            last_read_uj[counters_idx(package, domain)] = uj_now;
            extended_counter_mj[counters_idx(package, domain)] = 0;
        }
    }

    pthread_rwlock_init(&global_state_lock, NULL);
    sem_init(&updater_thread_sem, 0, 0);

    // Create the updater thread.
    pthread_create(&updater_thread, NULL, updater_loop, NULL);

    return SUCCESS;
}

void rapl_stopwatch_api_destroy(void) {
    // Tell the updater thread that it can exit its loop.
    sem_post(&updater_thread_sem);
    // Wait until the updater thread exits.
    pthread_join(updater_thread, NULL);

    pthread_rwlock_destroy(&global_state_lock);
    sem_destroy(&updater_thread_sem);

    free(last_read_uj);
    free(extended_counter_mj);
    free(max_uj);

    free(package_domain_energy_files);
}

void rapl_stopwatch_init(rapl_stopwatch_t *const rapl_sw) {
    rapl_sw->last_read_mj = (uint64_t *)malloc(num_packages * NUM_RAPL_DOMAINS *
                                               sizeof(*rapl_sw->last_read_mj));
    rapl_sw->total_count_mj = (uint64_t *)malloc(num_packages * NUM_RAPL_DOMAINS *
                                                 sizeof(*rapl_sw->total_count_mj));

    rapl_stopwatch_reset(rapl_sw);
}

void rapl_stopwatch_destroy(rapl_stopwatch_t *const rapl_sw) {
    free(rapl_sw->last_read_mj);
    free(rapl_sw->total_count_mj);
}

void rapl_stopwatch_reset(rapl_stopwatch_t *const rapl_sw) {
    for (int package = 0; package < num_packages; ++package) {
        for (int domain = 0; domain < NUM_RAPL_DOMAINS; ++domain) {
            rapl_sw->total_count_mj[counters_idx(package, domain)] = 0;
        }
    }
}

void rapl_stopwatch_play(rapl_stopwatch_t *const rapl_sw) {
    pthread_rwlock_rdlock(&global_state_lock);

    for (int package = 0; package < num_packages; ++package) {
        for (int domain = 0; domain < NUM_RAPL_DOMAINS; ++domain) {
            uint64_t uj_now;
            int err = get_updated_counters(package,
                                           domain,
                                           &uj_now,
                                           &rapl_sw->last_read_mj[counters_idx(package, domain)]);

            if (err != SUCCESS) {
                // I assume the error is because we can not read the file
                // because we do not have permission/it does not exist.
                continue;
            }
        }
    }

    pthread_rwlock_unlock(&global_state_lock);
}

void rapl_stopwatch_pause(rapl_stopwatch_t *const rapl_sw) {
    pthread_rwlock_rdlock(&global_state_lock);

    for (int package = 0; package < num_packages; ++package) {
        for (int domain = 0; domain < NUM_RAPL_DOMAINS; ++domain) {
            uint64_t uj_now;
            uint64_t extended_counter_mj_now;
            int err = get_updated_counters(package,
                                           domain,
                                           &uj_now,
                                           &extended_counter_mj_now);

            if (err != SUCCESS) {
                // I assume the error is because we can not read the file
                // because we do not have permission/it does not exist.
                continue;
            }

            rapl_sw->total_count_mj[counters_idx(package, domain)] +=
                extended_counter_mj_now -
                rapl_sw->last_read_mj[counters_idx(package, domain)];
        }
    }

    pthread_rwlock_unlock(&global_state_lock);
}

rapl_error_t rapl_stopwatch_get_mj(const rapl_stopwatch_t *const rapl_sw,
                                   const rapl_domain_t domain,
                                   uint64_t *const total_mj_domain) {

    *total_mj_domain = 0;

    if (domain == RAPL_NODE) {
        // The NODE energy is the energy consumed by the package (core + uncore)
        // + the energy consumed by the DRAM.
        uint64_t mj_package;
        int err_package = rapl_stopwatch_get_mj(rapl_sw, RAPL_PACKAGE, &mj_package);
        uint64_t mj_dram;
        int err_dram = rapl_stopwatch_get_mj(rapl_sw, RAPL_DRAM, &mj_dram);

        if (err_package || err_dram) {
            return UNABLE_TO_ACCESS_DOMAIN;
        }

        *total_mj_domain = mj_package + mj_dram;
    }
    else {
        // Summation of the energy consummed by the RAPL-domain among all
        // packages.
        for (int package = 0; package < num_packages; ++package) {
            if (!valid_domain(package, domain)) {
                return UNABLE_TO_ACCESS_DOMAIN;
            }
            *total_mj_domain += rapl_sw->total_count_mj[counters_idx(package, domain)];
        }
    }

    return SUCCESS;
}

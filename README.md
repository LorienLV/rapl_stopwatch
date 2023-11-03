# RAPL Stopwatch

The RAPL Stopwatch library provides an abstraction to easily measure energy consumption using Intel Running Average Power Limit (RAPL) sysfs files. Instead of directly accessing the RAPL files, you create an rapl_stopwatch that starts measuring energy consumption when is played and stops when it is paused. You can obtain the measured energy consumption for a given RAPL domain at any time.

The library is thread-safe and handles the occasional overflow of the RAPL counters by using an extended counter for each file that is periodically updated by a thread.

## Prerequisites

Your system must support intel-rapl powercap interface (introduced in Linux 3.13). Check that the required files exist and you have access:

```
ll /sys/class/powercap/intel-rapl
```

## Building and Installing

Build the library using CMake:

```
mkdir build
cd build
cmake ..
make
```

By default, the library created is static. To create a dynamic library instead:
```
cmake -DBUILD_SHARED_LIBS=ON ..
```

To install the library:
```
make install
```

The library in installed in GNU default directories. You can set a custom parent directory:
```
cmake -DCMAKE_INSTALL_PREFIX=OTHER_DIRECTORY
```

We provide some tests to check that the library runs correctly on your system. You can run them using CTest:
```
cmake -DBUILD_TESTS=ON ..
make test
```

## Usage

### Available RAPL Domains

- **RAPL_CORE**: Energy consumed by all the CPU cores of the system, including core resources and private caches (such as L1 and L2 caches). 
- **RAPL_UNCORE**: Energy consumed by components outside of the CPU cores, such as shared caches, memory controller, integrated graphics, and other uncore components. 
- **RAPL_PACKAGE**: The sum of energy consumption within both RAPL_CORE and RAPL_UNCORE domains. In some systems, RAPL_CORE and RAPL_UNCORE are unavailable, but RAPL_PACKAGE is available.
- **RAPL_DRAM**: Energy consumed by the main memory (DRAM) used by the system.
- **RAPL_NODE**: The sum of energy consumption within both RAPL_PACKAGE and RAPL_DRAM domains. In order to read this domain, you must be able to read RAPL_PACKAGE and RAPL_DRAM.

### Basic Example

```c
// Prepare the library to start measuring energy using RAPL sysfs files.
rapl_error_t err = rapl_stopwatch_api_init();
if (err != SUCCESS) {
    fprintf(stderr, "Error initializing the API\n");
    return 1;
}

// Instantiate a rapl_stopwatch
rapl_stopwatch_t rapl_sw;
rapl_stopwatch_init(&rapl_sw);

// Start measuring energy.
rapl_stopwatch_play(&rapl_sw);

// Do some work...

// Stop measuring energy.
rapl_stopwatch_pause(&rapl_sw);

// Get the energy consumed during the work in the full node.
uint64_t count = 0;
err = rapl_stopwatch_get_mj(&rapl_sw, RAPL_NODE, &count);
if (err != SUCCESS) {
    fprintf(stderr, "Error reading the counter\n");
    return 1;
}

printf("mJ: %" PRIu64 "\n", count);

// Destroy the rapl_stopwatch.
rapl_stopwatch_destroy(&rapl_sw);
// Destroy the RAPL API.
rapl_stopwatch_api_destroy();
```

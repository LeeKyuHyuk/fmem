# Changelog

All notable changes to this project will be documented in this file.

## [1.7.0] - 2023-04-01

- Changed to work only on Linux Kernel v5.8.0 or higher
- Write code `read_mem()`, `write_mem()` and `mmap_mem()` by referring to Linux Kernel v5.8.0
    - `write_mem()` and `mmap_mem()` implementation complete

## [1.6.0] - 2019-07-19

- Support for Linux kernel 5.7.0 or higher

## [1.5.0]

- Minor Bug Fixes:
    - Fixed compilation errors on older kernels and RHEL
    - `run.sh` fixed (module will not load, if address is invalid)

## [1.4.0]

- Renamed to fmem (name collision)

## [1.3.0]

- Header fix for x64 architecture. Tested on x64.

## [1.2.0]

- Minor Bugfixes, `run.sh` improved

## [1.0.0]

- Release first properly working version


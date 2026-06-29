# CheckMD5 Qt Port

This is a C++20/Qt6 port of the original checkmd5 C utility.

## Features

- **Qt6 Core/Concurrent**: Uses Qt data structures (QString, QByteArray, QFile, etc.) and optional parallel hashing
- **C++20**: Modern C++ features with proper RAII and memory management
- **Signal handling**: Proper Qt-style signal handling for graceful shutdown
- **Cross-platform**: Qt provides better cross-platform compatibility
- **Cancellation**: Handles Ctrl+C/SIGTERM/SIGHUP for graceful shutdown

## Building

Requirements:
- CMake 3.16+
- Qt6 Core and Concurrent
- C++20 compatible compiler

```bash
mkdir build
cd build
cmake ..
make
```

## Usage

Same command-line interface as the original:

```bash
./checkmd5-qt [--force] [--verbose] [--machine] [--log=file] [--jobs=count] file.md5
```

Use `--jobs=count` to hash multiple files in parallel, or `--jobs=0` to use Qt's default thread count.
Machine mode writes progress percentages to stdout for script consumption.

## Key Changes from C Version

1. **Memory Management**: Uses Qt containers and RAII instead of manual memory management
2. **File I/O**: QFile and QTextStream instead of stdio functions
3. **String Handling**: QString for proper Unicode support
4. **Error Handling**: Qt-style error reporting
5. **Signals**: Qt signal/slot mechanism for progress updates
6. **MD5 Implementation**: Modernized with Qt data types while maintaining compatibility

## Architecture

- `CheckMD5` class: Main application logic with Qt signals
- `MD5` class: Streamlined MD5 hasher using QByteArray
- CMake build system with automatic MOC processing
- CMake/CTest coverage for success, mismatch, malformed-list, missing-file, machine-output, and parallel checks

## Translation Status

The original gettext catalogs are not used by the Qt port and have been removed from the active source tree.
Qt translation wiring should be added with a future `.ts`/`.qm` pipeline if localized output is required.

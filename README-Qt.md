# CheckMD5 Qt Port

This is a C++20/Qt6 port of the original checkmd5 C utility.

## Features

- **Qt6 Core**: Uses Qt data structures (QString, QByteArray, QFile, etc.) instead of standard library
- **C++20**: Modern C++ features with proper RAII and memory management
- **Signal handling**: Proper Qt-style signal handling for graceful shutdown
- **Cross-platform**: Qt provides better cross-platform compatibility
- **Internationalization**: Built-in Qt translation support framework

## Building

Requirements:
- CMake 3.16+
- Qt6 Core
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
./checkmd5-qt [--force] [--verbose] [--machine] [--log=file] file.md5
```

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
- CMake build system with automatic MOC/RCC processing
- Resource file for future translation support
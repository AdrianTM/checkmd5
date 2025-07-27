cmake_minimum_required(VERSION 3.16)
project(checkmd5-qt VERSION 0.100 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt6
find_package(Qt6 REQUIRED COMPONENTS Core)

# Enable automatic MOC, UIC, and RCC processing
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Add executable
add_executable(checkmd5-qt
    main.cpp
    checkmd5.cpp
    checkmd5.h
    md5.cpp
    md5.h
    version.h
    resources.qrc
)

# Link Qt libraries
target_link_libraries(checkmd5-qt Qt6::Core)

# Set compiler flags for optimization
target_compile_options(checkmd5-qt PRIVATE
    -Wall
    -Wextra
    -O3
    -flto
)

# Set linker flags
target_link_options(checkmd5-qt PRIVATE
    -flto
)

# Enable internationalization support
target_compile_definitions(checkmd5-qt PRIVATE QT_I18N)

# Install target
install(TARGETS checkmd5-qt
    RUNTIME DESTINATION bin
)

# Install man page
install(FILES checkmd5.1
    DESTINATION share/man/man1
)
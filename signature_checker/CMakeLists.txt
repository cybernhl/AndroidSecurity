# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)
message(WARNING "Here Start Cmake !!!")
# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
             security

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             src/main/cpp/native-security.cpp )

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       security

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

add_definitions(-DISALT=${SALT})
add_definitions(-DITYPE=${SIGN_SHA_TYPE})
add_definitions(-DISHA=${SIGN_SHA})


# 將 FlavorSHAS 傳遞到 C++ 代碼中
#此外，請注意，在使用 CMake 的 add_definitions 命令時，您需要使用轉義字元（例如，\）來轉義冒號（:），以避免在 CMakeLists.txt 中出現語法錯誤。
#string(REPLACE ";" " " FLAVOR_SHAS "${FLAVOR_SHAS}")
# Convert the APP_FLAVORS_SHA_VALUE string to a map
string(REPLACE ";" "\n" APP_FLAVORS_SHA_VALUE_TMP "${ARGS_APP_FLAVORS_SHA_VALUE}")
#string(REPLACE ";" "\\;" FLAVOR_SHAS "${FLAVOR_SHAS}")
#list(GET FLAVOR_SHAS 0 my_map_element)
#string(REPLACE ":" "\\:" my_map_element "${my_map_element}")
#list(GET my_map_element 0 key)
#list(GET my_map_element 1 value)
#if ("${key}" STREQUAL "key1")
#    message(STATUS "The value of key1 is: ${value}")
#endif()
#add_definitions(-DIFLAVOR_SHAS=${FLAVOR_SHAS})

add_definitions(-DIFLAVOR_SHAS=${APP_FLAVORS_SHA_VALUE_TMP})
#add_definitions(-DIFLAVOR_TYPE_SHAS="${APP_FLAVORS_SHA_VALUES}")
message(WARNING "Show  message ...Get SALT ,${SALT}")
message(WARNING "Show  message ...Get TYPE ,${SIGN_SHA_TYPE}")
message(WARNING "Show  message ...Get SHA ,${SIGN_SHA}")
message(WARNING "Show  message ...Get SHA!! ,${FLAVOR_SHAS}")
message(WARNING "Show  message ...Get TEST ,${TEST}")
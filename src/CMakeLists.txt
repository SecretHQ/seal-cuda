file(GLOB_RECURSE CURRENT_HEADERS *.h *.hpp *.cuh)
file(GLOB_RECURSE CURRENT_SOURCES *.cpp *.cu *.c)

source_group("Include" FILES ${CURRENT_HEADERS})
source_group("Source" FILES ${CURRENT_SOURCES})

add_library(troy SHARED ${CURRENT_HEADERS} ${CURRENT_SOURCES})
set_target_properties(troy PROPERTIES CUDA_SEPERABLE_COMPILATION ON)

set(gcc_like_cxx "$<COMPILE_LANG_AND_ID:CXX,ARMClang,AppleClang,Clang,GNU>")
set(nvcc_cxx "$<COMPILE_LANG_AND_ID:CUDA,NVIDIA>")

target_compile_options(troy INTERFACE
  "$<${gcc_like_cxx}:$<BUILD_INTERFACE:-fPIC>>"
  "$<${nvcc_cxx}:$<BUILD_INTERFACE:--compiler-options=-fPIC>>"
)
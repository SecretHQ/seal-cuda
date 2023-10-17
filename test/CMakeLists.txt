enable_testing()

find_package(SEAL 4.0 REQUIRED)

add_executable(troytest)
target_sources(troytest PRIVATE 

    utils/common.cpp
    utils/galois.cpp
    utils/hash.cpp
    utils/ntt.cpp
    utils/numth.cpp
    utils/polyarithsmallmod.cpp
    utils/rns.cpp
    utils/uintarith.cpp
    utils/uintarithmod.cpp
    utils/uintarithsmallmod.cpp
    utils/uintcore.cpp

    batchencoder.cpp
    ckks.cpp
    context.cpp
    encryptionparams.cpp
    encryptor.cpp
    evaluator.cpp
    keygenerator.cpp
    modulus.cpp

    encryptor_cuda.cu
    evaluator_cuda.cu
    ckks_cuda.cu
)
target_link_libraries(troytest gtest gtest_main troy)

add_executable(timetest)
target_sources(timetest PRIVATE timetest.cu)
target_link_libraries(timetest troy)

add_executable(timetest_seal)
target_sources(timetest_seal PRIVATE timetest_seal.cpp)
target_link_libraries(timetest_seal SEAL::seal)

add_executable(linear)
target_sources(linear PRIVATE app/linear.cu)
target_link_libraries(linear troy)

add_executable(linear_seal)
target_sources(linear_seal PRIVATE app/linear_seal.cpp)
target_link_libraries(linear_seal SEAL::seal)

include(GoogleTest)
gtest_discover_tests(troytest)
# seal-cuda

The homomorphic encryption library implemented on GPU. Seal-cuda includes BFV, BGV, and CKKS scheme. Its implementation referred to the Microsoft SEAL library.

## Code structures
* `src` includes the implementation of the library. Just include `troy_cuda.cuh` and you are ready to go.
* `test` includes the tests.
* `extern` includes third-party libraries: googletest and pybind11.
* `binder` includes the pybind11 code to encapsulate the C/C++/CUDA interfaces for python.
* `app` includes a high-level implementation for computing matrix multiplication and 2d-convolution in HE.

## How to run

1. Build the basic library
    ```
    mkdir build
    cd build
    cmake ..
    make
    cd ..
    ```
2. Run tests
    ```
    cd build
    ctest
    ./test/timetest
    cd ..
    ```
2. Make the module for python
    ```
    bash makepackage.sh
    ```
    
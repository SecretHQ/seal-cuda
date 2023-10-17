#pragma once

#include <stdexcept>

namespace troy {

    class KernelProvider {

        static bool initialized;
        
    public:

        static void checkInitialized() {
            if (!initialized)
                throw std::invalid_argument("KernelProvider not initialized.");
        }

        static void initialize() {
            cudaSetDevice(0);
            initialized = true;
        }

        template <typename T>
        static T* malloc(size_t length) {
            checkInitialized();
            if (length == 0) return nullptr;
            T* ret;
            auto status = cudaMalloc((void**)&ret, length * sizeof(T));
            if (status != cudaSuccess) 
                throw std::runtime_error("Cuda Malloc failed.");
            return ret;
        }

        template <typename T> 
        static void free(T* pointer) {
            checkInitialized();
            cudaFree(pointer);
        }

        template <typename T>
        static void copy(T* deviceDestPtr, const T* hostFromPtr, size_t length) {
            checkInitialized();
            if (length == 0) return;
            auto status = cudaMemcpy(deviceDestPtr, hostFromPtr, length * sizeof(T), cudaMemcpyHostToDevice);
            if (status != cudaSuccess) 
                throw std::runtime_error("Cuda copy from host to device failed.");
        }

        template <typename T>
        static void copyOnDevice(T* deviceDestPtr, const T* deviceFromPtr, size_t length) {
            checkInitialized();
            if (length == 0) return;
            auto status = cudaMemcpy(deviceDestPtr, deviceFromPtr, length * sizeof(T), cudaMemcpyDeviceToDevice);
            if (status != cudaSuccess) 
                throw std::runtime_error("Cuda copy on device failed.");
        }

        template <typename T>
        static void retrieve(T* hostDestPtr, const T* deviceFromPtr, size_t length) {
            checkInitialized();
            if (length == 0) return;
            auto status = cudaMemcpy(hostDestPtr, deviceFromPtr, length * sizeof(T), cudaMemcpyDeviceToHost);
            if (status != cudaSuccess) 
                throw std::runtime_error("Cuda retrieve from device to host failed.");
        }

        template <typename T>
        static void memsetZero(T* devicePtr, size_t length) {
            if (length == 0) return;
            cudaMemset(devicePtr, 0, sizeof(T) * length);
        }

    };

}

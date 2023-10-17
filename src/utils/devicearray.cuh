#pragma once


#include "hostarray.h"
#include "../kernelprovider.cuh"
#include "memorypool_cuda.cuh"
#include <vector>
#include <exception>

namespace troy { namespace util {

template <typename T> class DevicePointer;
template <typename T> class DeviceArray;

template <typename T>
class ConstDevicePointer {
    const T* ptr;
public:
    ConstDevicePointer(): ptr(nullptr) {}
    ConstDevicePointer(const T* ptr): ptr(ptr) {}
    ConstDevicePointer(const DevicePointer<T>& d): ptr(d.get()) {}
    bool isNull() const {return ptr == nullptr;}
    operator bool() const {
        return !isNull();
    }
    const T* get() const {return ptr;}
    ConstDevicePointer<T> operator+(size_t d) {
        return ConstDevicePointer(ptr+d);
    }
    ConstDevicePointer(const DeviceArray<T>& arr):
        ptr(arr.get()) {}
};

template <typename T>
class DevicePointer {
    friend class DeviceArray<T>;
    T* ptr;
public:
    DevicePointer(T* ptr): ptr(ptr) {}
    DevicePointer(DeviceArray<T>& r): ptr(r.get()) {}
    DevicePointer() {
        ptr = nullptr;
    }
    bool isNull() {return ptr == nullptr;}
    operator bool() const {
        return !isNull();
    }
    const T* get() const {return ptr;}
    T* get() {return ptr;}
    DevicePointer<T> operator +(size_t d) {return DevicePointer(ptr+d);}
    DevicePointer<T>& operator +=(size_t d) {
        ptr += d;
        return *this;
    }
};

template <typename T> 
class DeviceObject {
    T* ptr;
public:
    DeviceObject(T* p): ptr(p) {}
    DeviceObject(): ptr(nullptr) {}
    DeviceObject(const DeviceObject<T>& copy) {
        if (!copy.isNull()) {
            ptr = KernelProvider::malloc<T>(1);
            KernelProvider::copyOnDevice(ptr, copy.get(), 1);
        }
    }
    DeviceObject(DeviceObject&& move) {
        ptr = move.ptr; move.ptr = nullptr;
    }
    DeviceObject& operator=(const DeviceObject& copy) {
        if (copy.isNull()) {
            if (ptr) KernelProvider::free(ptr); ptr = nullptr;
        } else {
            if (!ptr) ptr = KernelProvider::malloc<T>(1);
            KernelProvider::copyOnDevice(ptr, copy.get(), 1);
        }
        return *this;
    }
    DeviceObject& operator=(DeviceObject&& move) {
        if (ptr) KernelProvider::free(ptr);
        ptr = move.ptr; move.ptr = nullptr;
        return *this;
    }
    bool isNull() const {return ptr == nullptr;}
    operator bool() const {
        return !isNull();
    }
    ~DeviceObject() {
        if (ptr) KernelProvider::free(ptr);
    }
    const T* get() {return ptr;}
    T* get() const {return ptr;}
    DeviceObject(const HostObject<T>& hostobject) {
        ptr = KernelProvider::malloc<T>(1);
        KernelProvider::copy(ptr, hostobject.get(), 1);
    }
    HostObject<T> toHost() {
        auto r = malloc(sizeof(T));
        KernelProvider::retrieve(r, ptr, 1);
        return HostObject<T>(r);
    }
};

template <typename T>
class DeviceArray {
    T* data; size_t len;
public:
    DeviceArray() {
        data = nullptr; len = 0;
    }
    DeviceArray(size_t cnt) {
        data = reinterpret_cast<T*>(MemoryPoolCuda::Get(cnt * sizeof(T)));
        len = cnt;
    }

    size_t length() const {return len;}
    size_t size() const {return len;}

    // Directly use the given pointer.
    DeviceArray(T* data, size_t length):
        data(data), len(length) {}

    DeviceArray(DeviceArray&& a) {
        data = a.data; 
        len = a.len;
        a.data = nullptr; a.len = 0;
    }
    DeviceArray& operator=(DeviceArray&& a) {
        if (data) MemoryPoolCuda::Free(reinterpret_cast<void*>(data), len * sizeof(T));
        data = a.data; 
        len = a.len;
        a.data = nullptr; a.len = 0;
        return *this;
    }

    DeviceArray(const HostArray<T>& host) {
        len = host.length();
        data = reinterpret_cast<T*>(MemoryPoolCuda::Get(len * sizeof(T)));
        KernelProvider::copy<T>(data, host.get(), len);
    }

    ~DeviceArray() {
        if (data) MemoryPoolCuda::Free(reinterpret_cast<void*>(data), len * sizeof(T));
    }

    DeviceArray copy() const {
        T* copied = reinterpret_cast<T*>(MemoryPoolCuda::Get(len * sizeof(T)));
        KernelProvider::copyOnDevice<T>(copied, data, len);
        return DeviceArray(copied, len);
    }
    DeviceArray& operator = (const DeviceArray& r) {
        if (data) MemoryPoolCuda::Free(reinterpret_cast<void*>(data), len * sizeof(T));
        len = r.len;
        data = reinterpret_cast<T*>(MemoryPoolCuda::Get(len * sizeof(T)));
        KernelProvider::copyOnDevice<T>(data, r.data, len);
        return *this;
    }
    DeviceArray(const DeviceArray& r) {
        len = r.len;
        data = reinterpret_cast<T*>(MemoryPoolCuda::Get(len * sizeof(T)));
        KernelProvider::copyOnDevice<T>(data, r.data, len);
    }

    HostArray<T> toHost() const {
        T* ret = new T[len];
        KernelProvider::retrieve(ret, data, len);
        return HostArray<T>(ret, len);
    }

    T* get() {return data;}
    const T* get() const {return data;}
    DevicePointer<T> asPointer() {return DevicePointer<T>(data);}
    ConstDevicePointer<T> asPointer() const {return ConstDevicePointer<T>(data);}
    DevicePointer<T> operator+(size_t d) {
        return DevicePointer(data + d);
    }
    ConstDevicePointer<T> operator+(size_t d) const {
        return ConstDevicePointer(data + d);
    }

    __device__ inline T deviceAt(size_t id) const {
        return data[id];
    }
    __device__ inline T* deviceGet() const {
        return data;
    }

    T back() const {
        T ret; 
        if (data) KernelProvider::retrieve(&ret, data + len - 1, 1);
        return ret;
    }

    bool isNull() const {
        return data == nullptr;
    }

};

template <typename T>
class DeviceDynamicArray {

    DeviceArray<T> internal;
    size_t size_;

    void move(size_t newCapacity) {
        if (newCapacity == internal.size()) return;
        DeviceArray<T> n(newCapacity);
        if (newCapacity < size_) size_ = newCapacity;
        KernelProvider::copyOnDevice(n.get(), internal.get(), size_);
        if (newCapacity > size_)
            KernelProvider::memsetZero(n.get() + size_, newCapacity - size_);
        internal = std::move(n);
    }

public:

    DeviceDynamicArray(): internal(), size_(0) {}
    DeviceDynamicArray(size_t len): internal(len), size_(len) {}
    DeviceDynamicArray(size_t capacity, size_t size): internal(capacity), size_(size) {}
    DeviceDynamicArray(DeviceArray<T>&& move, size_t size): 
        internal(std::move(move)), size_(size) {}

    DeviceDynamicArray<T> copy() const {
        return DeviceDynamicArray(internal.copy(), size_);
    }

    DeviceDynamicArray(DeviceArray<T>&& move) {
        size_ = move.size();
        internal = std::move(move);
    }
    DeviceDynamicArray(DeviceDynamicArray<T>&& move) {
        size_ = move.size();
        internal = std::move(move.internal);
        move.size_ = 0;
    }
    
    DeviceDynamicArray(const DeviceDynamicArray<T>& copy) {
        size_ = copy.size();
        internal = std::move(copy.internal.copy());
    }

    DeviceDynamicArray(const HostDynamicArray<T>& h):
        size_(h.size()),
        internal(h.internal) {}

    DeviceDynamicArray& operator = (const DeviceDynamicArray& copy) {
        if (copy.size_ <= size_) {
            KernelProvider::copyOnDevice(internal.get(), copy.internal.get(), copy.size_);
            size_ = copy.size();
        } else {
            size_ = copy.size();
            internal = std::move(copy.internal.copy());
        }
        return *this;
    }
    DeviceDynamicArray& operator = (DeviceArray<T>&& move) {
        size_ = move.size();
        internal = std::move(move);
        return *this;
    } 
    DeviceDynamicArray& operator = (DeviceDynamicArray<T>&& move) {
        size_ = move.size();
        internal = std::move(move.internal);
        move.size_ = 0;
        return *this;
    }
    
    size_t size() const {return size_;}
    size_t capacity() const {return internal.size();}

    void reserve(size_t newCapacity) {
        if (capacity() >= newCapacity) return;
        move(newCapacity);
    }

    void shrinkToFit() {
        if (capacity() == size_) return;
        move(size_);
    }

    void release() {
        internal = std::move(DeviceArray<T>());
        size_ = 0;
    }

    void resize(size_t newSize) {
        if (newSize > capacity()) move(newSize);
        size_ = newSize;
    }

    DevicePointer<T> ensure(size_t size) {
        if (size > size_) resize(size);
        return asPointer();
    }

    T* get() {return internal.get();}
    DevicePointer<T> asPointer() {return internal.asPointer();}
    ConstDevicePointer<T> asPointer() const {
        return internal.asPointer();
    }
    const T* get() const {return internal.get();}

    inline std::size_t maxSize() const noexcept {
        return (std::numeric_limits<std::size_t>::max)();
    }

    HostDynamicArray<T> toHost() const {
        T* copy = new T[size_];
        KernelProvider::retrieve(copy, internal.get(), size_);
        return HostDynamicArray<T>(std::move(HostArray(copy, size_)));
    }
    
};


}}
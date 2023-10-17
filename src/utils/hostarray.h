#pragma once

#include <vector>
#include <exception>
#include <cstring>
#include <limits>

namespace troy { namespace util {
    
template <typename T> class DeviceArray;
template <typename T> class HostArray;
template <typename T> class HostPointer;

template <typename T>
class ConstHostPointer {
    const T* ptr;
public:
    ConstHostPointer(const T* p) : ptr(p) {}
    ConstHostPointer(): ptr(nullptr) {}
    ConstHostPointer(const HostPointer<T>& h): ptr(h.get()) {}
    bool isNull() {return ptr == nullptr;}
    const T* get() {return ptr;}
    ConstHostPointer<T> operator+ (size_t d) const {
        return ConstHostPointer<T>(ptr+d);
    }
    const T& operator[](std::size_t i) const {return ptr[i];}
    const T* operator->() {return ptr;}
    const T& operator*() {return *ptr;}
    ConstHostPointer& operator++() {ptr++; return *this;}
    ConstHostPointer operator++(int) {ConstHostPointer copied = *this; ptr++; return copied;}
};

template <typename T>
class HostPointer {
    T* ptr;
public:
    HostPointer(T* p) : ptr(p) {}
    HostPointer(): ptr(nullptr) {}
    bool isNull() {return ptr == nullptr;}
    T* get() {return ptr;}
    const T* get() const {return ptr;}
    HostPointer<T> operator+ (size_t d) const {
        return HostPointer<T>(ptr+d);
    }
    HostPointer<T> operator- (size_t d) const {
        return HostPointer<T>(ptr-d);
    }
    T& operator[](std::size_t i) {return ptr[i];}
    const T& operator[](std::size_t i) const {return ptr[i];}
    T* operator->() {return ptr;}
    T& operator*() {return *ptr;}
    HostPointer& operator++() {ptr++; return *this;}
    HostPointer operator++(int) {HostPointer copied = *this; ptr++; return copied;}
    HostPointer& operator+=(size_t p) {
        ptr += p; return *this;
    }
    ConstHostPointer<T> toConst() {return ConstHostPointer<T>(ptr);}
};

template <typename T>
class HostObject {
    T* ptr;
public:
    HostObject(T* p) : ptr(p) {}
    HostObject(): ptr(nullptr) {}
    HostObject(const HostObject& copy) = delete;
    HostObject& operator=(const HostObject& copy) = delete;
    HostObject(HostObject&& move) {
        ptr = move.ptr; move.ptr = nullptr;
    }
    HostObject& operator=(HostObject&& move) {
        if (ptr) delete ptr;
        ptr = move.ptr; move.ptr = nullptr;
        return *this;
    }
    bool isNull() const {return ptr == nullptr;}
    const T* get() const {return ptr;}
    T* get() {return ptr;}
    ~HostObject() {
        if (ptr) delete ptr;
    }
    T* operator->() {return ptr;}
    T& operator*() {return *ptr;}
    const T* operator->() const {return ptr;}
    const T& operator*() const {return *ptr;}
};

template <typename T>
class HostArray {
    T* data;
    std::size_t len;
public:
    std::size_t length() const {return len;}
    std::size_t size() const {return len;}
    HostArray() {
        data = nullptr; len = 0;
    }
    HostArray(std::size_t cnt) {
        if (cnt > 0) {
            data = new T[cnt];
            memset(data, 0, sizeof(T) * cnt);
        }
        else data = nullptr;
        len = cnt;
    }

    HostArray(T* data, std::size_t cnt):
        data(data), len(cnt) {}

    HostArray(const T* copyfrom, std::size_t cnt) {
        if (cnt == 0) {data = nullptr; len = 0; return;}
        data = new T[cnt];
        for (std::size_t i=0; i<cnt; i++) data[i] = copyfrom[i];
        len = cnt;
    }

    HostArray(const std::vector<T>& a) {
        len = a.size();
        data = new T[len];
        for (std::size_t i=0; i<len; i++) data[i] = a[i];
    }
    HostArray(HostArray&& arr) {
        data = arr.data; 
        len = arr.len;
        arr.data = nullptr; arr.len = 0;
    }
    ~HostArray() {
        if (data) delete[] data;
    }
    HostArray& operator = (const HostArray& r) = delete;
    HostArray& operator = (HostArray&& from) {
        if (data) delete[] data;
        data = from.data;
        len = from.len;
        from.data = nullptr;
        from.len = 0;
        return *this;
    }
    HostArray(const HostArray& r) = delete;
    HostArray<T> copy() const {
        // need to cast data into const pointer
        // to make sure the contents are copied.
        const T* constptr = static_cast<const T*>(data);
        return HostArray<T>(constptr, len);
    }
    const T& operator[](std::size_t i) const {return data[i];}
    T& operator[](std::size_t i) {return data[i];}
    // DeviceArray<T> toDevice() {
    //     T* copied = KernelProvider::malloc<T>(len);
    //     KernelProvider::copy<T>(copied, data, len);
    //     return DeviceArray<T>(copied, len);
    // }
    T* get() {return data;}
    const T* get() const {return data;}
    HostPointer<T> operator +(size_t d) const {return HostPointer<T>(data + d);}
    HostPointer<T> asPointer() {return HostPointer<T>(data);}

};

template <typename T> class DeviceDynamicArray;

template <typename T> 
class HostDynamicArray {

    friend class DeviceDynamicArray<T>;

    HostArray<T> internal;
    size_t size_;

    void move(size_t newCapacity) {
        if (newCapacity == internal.size()) return;
        HostArray<T> n(newCapacity);
        if (newCapacity < size_) size_ = newCapacity;
        for (size_t i = 0; i < size_; i++) {
            n[i] = internal[i]; // copy
        }
        for (size_t i = size_; i < newCapacity; i++) {
            n[i] = T();
        }
        internal = std::move(n);
    }

public:

    HostDynamicArray(): internal(), size_(0) {}
    HostDynamicArray(size_t len): internal(len), size_(len) {}
    HostDynamicArray(size_t capacity, size_t size): internal(capacity), size_(size) {}
    HostDynamicArray(HostArray<T>&& move, size_t size): 
        internal(std::move(move)), size_(size) {}

    HostDynamicArray<T> copy() const {
        return HostDynamicArray(internal.copy(), size_);
    }

    HostDynamicArray(const HostDynamicArray<T>& copy) {
        size_ = copy.size();
        internal = std::move(copy.internal.copy());
    }

    HostDynamicArray(HostArray<T>&& move) {
        size_ = move.size();
        internal = std::move(move);
    } 
    HostDynamicArray(HostDynamicArray<T>&& move) {
        size_ = move.size();
        internal = std::move(move.internal);
    }

    HostDynamicArray& operator = (const HostDynamicArray& copy) {
        size_ = copy.size();
        internal = std::move(copy.internal.copy());
        return *this;
    }
    HostDynamicArray& operator = (HostArray<T>&& move) {
        size_ = move.size();
        internal = std::move(move);
        return *this;
    } 
    HostDynamicArray& operator = (HostDynamicArray<T>&& move) {
        size_ = move.size();
        internal = std::move(move.internal);
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
        internal = std::move(HostArray<T>());
        size_ = 0;
    }

    void resize(size_t newSize) {
        if (newSize > capacity()) move(newSize);
        size_ = newSize;
    }

    T& operator[](size_t i) {return internal[i];}
    const T& operator[](size_t i) const {return internal[i];}

    T& at(size_t i) {return operator[](i);}
    const T& at(size_t i) const {return operator[](i);}

    T* begin() {return internal.get();}
    T* end() {return internal.get() + size_;}
    const T* cbegin() const {return internal.get();}
    const T* cend() const {return internal.get() + size_;}

    inline std::size_t maxSize() const noexcept {
        return (std::numeric_limits<std::size_t>::max)();
    }
    
};

}}
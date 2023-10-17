#include <iostream>

namespace troy {

    template <typename T>
    inline void savet(std::ostream& stream, const T* obj) {
        stream.write(reinterpret_cast<const char*>(obj), sizeof(T));
    }
    
    template <typename T>
    inline void loadt(std::istream& stream, T* obj) {
        stream.read(reinterpret_cast<char*>(obj), sizeof(T));
    }

}
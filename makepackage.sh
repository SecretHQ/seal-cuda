echo "Making base library"

cd build
cmake ..
make
cd ..

nvcc -x cu \
    -std=c++17 \
    -lpython3.8 \
    --compiler-options -fPIC \
    -I/usr/include/python3.8 \
    -I./extern/pybind11/include/ \
    -I./src -I/usr/include/python3.8 \
    --compiler-options -fPIC \
    -c binder/binder.cu \
    -o build/binder.o

echo "Binder.o generated"

nvcc -shared \
    ./build/src/libtroy.so \
    build/binder.o \
    -o build/pytroy.cpython-38-x86_64-linux-gnu.so
    
echo "Shared lib generated"

    # ./build/src/libtroy.a \
#lib.linux-x86_64-3.8/pytroy.cpython-38-x86_64-linux-gnu.so
cp build/pytroy.cpython-38-x86_64-linux-gnu.so ./binder/pytroy.cpython-38-x86_64-linux-gnu.so
cp ./build/src/libtroy.so ./binder/libtroy.so

echo "Copied to ./binder"

echo "Need sudo"

sudo rm /usr/lib/libtroy.so
sudo cp ./binder/libtroy.so   /usr/lib

echo "Created soft link in /usr/lib"

cp build/pytroy.cpython-38-x86_64-linux-gnu.so ~/private-training/tools/
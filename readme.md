# HADES: Range-Filtered Private Aggregation on Public Data

## Dependency

1. Install SEAL. See https://github.com/microsoft/SEAL
```sh
# if installed to ~/mylibs without sudo
export CMAKE_PREFIX_PATH=$HOME/mylibs
```
2. For Python compiler:
```sh
pip install fire tqdm pydantic pandas
```
3. TPC-H: Download the official [tpc-h-v3.0.1 tool](https://www.tpc.org/tpc_documents_current_versions/download_programs/tools-download-request5.asp?bm_type=TPC-H&bm_vers=3.0.1&mode=CURRENT-ONLY), place it in this folder under /tpc-h-v3.0.1, and compile the dbgen binary

## Build & Run

To build:
```sh
mkdir build && cd build
# Note: if SEAL is not installed with sudo, run:
# export CMAKE_PREFIX_PATH=$HOME/mylibs:$CMAKE_PREFIX_PATH
cmake .. -DCMAKE_BUILD_TYPE=Release # use =Debug if debugging is needed
make -j 
cd ..
```

To run end-2-end with compiler (for example, with TPC-H Q1):
```sh
mkdir tmp
python compiler/example_q1.py gen -l 10000  # IR is written to ./tmp
```

To run the query (after compilation):
```sh
python compiler/example_q1.py run
```

For more parameters, check the script or see the help message:
```sh
python compiler/example_q1.py
```

## Performance optimization
For the `tmp` folder, consider using a tmpfs to reduce disk I/O overhead if you have enough memory. For example:
```sh
sudo mount -o size=32G -t tmpfs none tmp
```
You can test the speed change before / after with
```sh
dd if=/dev/zero of=tmp/test.tmp bs=1M count=1024 oflag=dsync
```

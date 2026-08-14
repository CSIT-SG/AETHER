# Benchmark Test Binary

## Workflow

```
1. Compile benchmark_test.c → benchmark_test.exe
2. Open benchmark_test.exe in IDA Pro
3. Note the function addresses (or run find_addrs.py in IDA)
4. Fill the addresses into benchmark_rubric.yaml
5. Run AETHER's annotator on the binary in IDA
6. Run aether-benchmark --idb benchmark_test.i64 --rubric benchmark_rubric.yaml
```

## Compiling

**Windows (MSVC):**
```
cl /O2 /GS- benchmark_test.c /link /SUBSYSTEM:CONSOLE /OUT:benchmark_test.exe
```

**Linux (GCC):**
```
gcc -O2 -o benchmark_test benchmark_test.c
```

## Finding Function Addresses

Open the binary in IDA and open the Functions window (Shift+F9).
Look up the addresses for these exported functions:

| Function | Address (fill in) |
|---|---|
| `xor_encrypt` | `0x` |
| `hex_encode` | `0x` |
| `compute_crc8` | `0x` |
| `validate_crc8` | `0x` |
| `str_append` | `0x` |
| `main` | `0x` |

Then update `benchmark_rubric.yaml` with these addresses.

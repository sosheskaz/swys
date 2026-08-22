# AES-GCM performance report

## Summary

This report compares the explicit legacy AES-CBC path with the bounded AES-GCM path introduced on `feat/issue-3-aes-gcm`. It records local measurements from commit `9bfcff5734779ee7640225d860be9094998c7c56` on 2026-08-10.

On this Apple M1 Pro, AES-GCM had lower median execution time in every sampled in-memory and file workload. It also allocated substantially more memory because GCM reads and authenticates each bounded message as a single operation, while CBC streams through fixed-size buffers.

These measurements characterize this machine and implementation. They do not establish a general speed advantage, and `B/op` is cumulative allocation rather than peak resident memory.

## Environment

| Property | Value |
| --- | --- |
| OS | macOS (`darwin/arm64`) |
| CPU | Apple M1 Pro |
| Go | 1.26.5 |
| Samples | 10 per benchmark |
| Benchmark duration | `-benchtime=1x` |
| Memory reporting | `-benchmem` |
| Comparison tool | `golang.org/x/perf/cmd/benchstat@v0.0.0-20260709024250-82a0b07e230d` |
| GCM AAD | Empty |

The one-iteration sample duration keeps the 64 MiB cases practical, but it also makes timing results more sensitive to scheduler, garbage collector, and filesystem-cache noise. Allocation results were stable across samples.

## In-memory results

The in-memory benchmarks read from `bytes.Reader` and write to `io.Discard`. Cipher construction and known-ciphertext setup occur outside the timed region. GCM random nonce generation is included in each encryption operation.

### Execution time

| Operation | CBC median | GCM median | GCM change | Samples |
| --- | ---: | ---: | ---: | ---: |
| Encrypt 1 MiB | 1.356 ms ± 1% | 0.572 ms ± 29% | -57.80% | 10 |
| Decrypt 1 MiB | 0.891 ms ± 12% | 0.521 ms ± 18% | -41.53% | 10 |
| Encrypt 10 MiB | 13.205 ms ± 4% | 4.247 ms ± 38% | -67.84% | 10 |
| Decrypt 10 MiB | 6.319 ms ± 2% | 3.075 ms ± 4% | -51.34% | 10 |
| Encrypt 64 MiB | 85.95 ms ± 2% | 21.78 ms ± 26% | -74.66% | 10 |
| Decrypt 64 MiB | 40.39 ms ± 1% | 16.99 ms ± 1% | -57.94% | 10 |

### Allocations

| Operation | CBC B/op | GCM B/op | CBC allocs/op | GCM allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Encrypt 1 MiB | 72.55 KiB | 3,207.83 KiB | 3.0 | 27.5 |
| Decrypt 1 MiB | 128.6 KiB | 3,207.8 KiB | 5.0 | 27.0 |
| Encrypt 10 MiB | 72.55 KiB | 33,167.88 KiB | 3.0 | 33.5 |
| Decrypt 10 MiB | 128.6 KiB | 33,167.8 KiB | 5.0 | 33.0 |
| Encrypt 64 MiB | 72.55 KiB | 227,015.82 KiB | 3.0 | 38.0 |
| Decrypt 64 MiB | 128.6 KiB | 227,015.8 KiB | 5.0 | 38.0 |

CBC allocation remains nearly flat as input grows. GCM allocation grows with message size and reaches approximately 221.7 MiB of cumulative allocation per 64 MiB encrypt or decrypt operation.

## File-operation results

The file benchmarks process a 10 MiB temporary file and include file open, truncate, read, write, and close costs. They do not call `fsync`, and results can be influenced by the operating-system filesystem cache.

| Operation | CBC median | GCM median | GCM change | CBC B/op | GCM B/op | CBC allocs/op | GCM allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Encrypt 10 MiB file | 19.088 ms ± 16% | 6.829 ms ± 8% | -64.22% | 72.83 KiB | 33,168.17 KiB | 8.0 | 38.5 |
| Decrypt 10 MiB file | 10.057 ms ± 11% | 6.502 ms ± 4% | -35.34% | 128.9 KiB | 33,168.2 KiB | 10.0 | 39.0 |

## Interpretation

- The local timing results favor GCM, but several GCM timing ranges are wide. Treat the direction as observed evidence for this machine, not a portable performance guarantee.
- CBC is streaming and maintains nearly constant allocation across input sizes.
- GCM's allocation is intentionally size-proportional because authenticated plaintext cannot be released before the final tag is verified. Input remains capped at 64 MiB.
- The benchmarks measure cumulative Go allocations. They do not measure peak RSS, allocator reuse outside the timed operation, or system-wide memory pressure.
- File benchmarks cover the crypter and ordinary filesystem behavior, not durability latency or CLI encoding overhead.

## Reproduction

Run the benchmark smoke suite used by CI:

```sh
mise run bench -- -benchtime=1x
```

Collect the matched CBC and GCM samples:

```sh
go test -run='^$' -bench='^Benchmark(RealisticMemory|FileOperations)$/^(Encrypt|Decrypt)' -benchmem -benchtime=1x -count=10 ./internal/crypter > cbc.txt
go test -run='^$' -bench='^Benchmark(RealisticMemory|FileOperations)$/^GCM_(Encrypt|Decrypt)' -benchmem -benchtime=1x -count=10 ./internal/crypter | sed 's#/GCM_#/#' > gcm.txt
benchstat cbc.txt gcm.txt
```

The `sed` transformation aligns the explicitly prefixed GCM benchmark names with the pre-existing CBC names for `benchstat`; it does not alter measured values.

# ESP32-S3 ML-KEM example

This ESP-IDF C++ example performs a complete **ML-KEM-768** (Kyber) key
encapsulation and decapsulation using Espressif's `esp-pqc` component.

## Setup

Install ESP-IDF 6.0 or newer, then place the component beside this project:

```bash
cd ..
git clone --recursive https://github.com/espressif/esp-pqc.git
cd esp32-s3-pqc
. "$IDF_PATH/export.sh"
idf.py set-target esp32s3
idf.py build flash monitor
```

The component uses the ESP32-S3 hardware RNG for liboqs randomness. ML-KEM
operations run in software; this example is for experimentation and
evaluation, not a production security boundary.

## Benchmark output

The firmware prints CSV-like lines to the serial monitor:

```text
PQC_SAMPLE,operation,iteration,latency_us,cycles,heap_free_before,heap_free_after,transient_heap_low_water,stack_free_before,stack_free_after
```

It reports 10 measured iterations each for `keypair`, `encaps`, and `decaps`
after one warm-up iteration. `preallocated_buffer_bytes` is the persistent
buffer memory used by the benchmark. `transient_heap_low_water` estimates peak
temporary heap consumption during the operation, and the stack columns report
unused stack space before and after the operation.

Capture the serial output while measuring INA219 current/energy. Align the
INA219 sample window with each `PQC_SAMPLE` operation; the firmware does not
control or read the INA219.

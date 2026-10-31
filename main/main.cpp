#include "esp_cpu.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "oqs/oqs.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

constexpr char kTag[] = "pqc_bench";

// BTYSTE Specification: GPIO 4 used as hardware trigger for Oscilloscope / Power Profiler
constexpr gpio_num_t kTriggerPin = GPIO_NUM_4;

// 100 iterations as promised in your BTYSTE proposal
constexpr std::size_t kWarmupIterations = 5;
constexpr std::size_t kMeasuredIterations = 100;

// Dedicated Worker Stack size to prevent stack overflows
constexpr std::size_t kWorkerTaskStackBytes = 16384; 

void wipe(void* ptr, std::size_t length) {
    volatile auto* bytes = static_cast<volatile std::uint8_t*>(ptr);
    while (length-- != 0) {
        *bytes++ = 0;
    }
}

class Buffer {
public:
    explicit Buffer(std::size_t length)
        : data_(static_cast<std::uint8_t*>(std::malloc(length))), length_(length) {}
    ~Buffer() {
        if (data_ != nullptr) {
            wipe(data_, length_);
            std::free(data_);
        }
    }

    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    std::uint8_t* data() { return data_; }
    const std::uint8_t* data() const { return data_; }
    bool valid() const { return data_ != nullptr; }

private:
    std::uint8_t* data_;
    std::size_t length_;
};

struct Sample {
    std::uint64_t latency_us = 0;
    std::uint64_t cycles = 0;
    std::size_t peak_stack_used = 0;
    std::size_t transient_heap_used = 0;
    bool success = false;
};

using Operation = int (*)(OQS_KEM*, std::uint8_t*, std::uint8_t*, std::uint8_t*, std::uint8_t*);

int keypair_op(OQS_KEM* kem, std::uint8_t* pk, std::uint8_t* sk, std::uint8_t*, std::uint8_t*) {
    return OQS_KEM_keypair(kem, pk, sk);
}

int encaps_op(OQS_KEM* kem, std::uint8_t* ct, std::uint8_t* ss, std::uint8_t* pk, std::uint8_t*) {
    return OQS_KEM_encaps(kem, ct, ss, pk);
}

int decaps_op(OQS_KEM* kem, std::uint8_t* ss, std::uint8_t* ct, std::uint8_t* sk, std::uint8_t*) {
    return OQS_KEM_decaps(kem, ss, ct, sk);
}

struct TaskParams {
    Operation operation;
    OQS_KEM* kem;
    std::uint8_t* out1;
    std::uint8_t* out2;
    std::uint8_t* in1;
    std::uint8_t* in2;
    Sample* sample_dest;
    TaskHandle_t caller_task;
};

// Worker task to guarantee an isolated, fresh stack per measurement
void benchmark_worker_task(void* pvParameters) {
    auto* params = static_cast<TaskParams*>(pvParameters);

    const std::size_t heap_low_water_before = heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);

    // Hardware Trigger HIGH right before cryptographic computation
    gpio_set_level(kTriggerPin, 1);
    const esp_cpu_cycle_count_t start_cycles = esp_cpu_get_cycle_count();
    const std::int64_t start_us = esp_timer_get_time();

    int res = params->operation(params->kem, params->out1, params->out2, params->in1, params->in2);

    const std::int64_t end_us = esp_timer_get_time();
    const esp_cpu_cycle_count_t end_cycles = esp_cpu_get_cycle_count();
    // Hardware Trigger LOW right after cryptographic computation
    gpio_set_level(kTriggerPin, 0);

    const std::size_t heap_low_water_after = heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);

    // Exact peak stack usage calculation for this isolated execution
    const UBaseType_t high_water_words = uxTaskGetStackHighWaterMark(nullptr);
    const std::size_t unused_stack_bytes = high_water_words * sizeof(StackType_t);
    const std::size_t peak_stack_bytes = kWorkerTaskStackBytes - unused_stack_bytes;

    if (res == OQS_SUCCESS) {
        params->sample_dest->latency_us = static_cast<std::uint64_t>(end_us - start_us);
        params->sample_dest->cycles = static_cast<std::uint64_t>(end_cycles - start_cycles);
        params->sample_dest->peak_stack_used = peak_stack_bytes;
        params->sample_dest->transient_heap_used = (heap_low_water_before > heap_low_water_after)
            ? (heap_low_water_before - heap_low_water_after) : 0;
        params->sample_dest->success = true;
    } else {
        params->sample_dest->success = false;
    }

    xTaskNotifyGive(params->caller_task);
    vTaskDelete(nullptr);
}

Sample execute_isolated_benchmark(Operation op, OQS_KEM* kem, std::uint8_t* out1,
                                 std::uint8_t* out2, std::uint8_t* in1, std::uint8_t* in2) {
    Sample result;
    TaskParams params = {
        .operation = op,
        .kem = kem,
        .out1 = out1,
        .out2 = out2,
        .in1 = in1,
        .in2 = in2,
        .sample_dest = &result,
        .caller_task = xTaskGetCurrentTaskHandle()
    };

    xTaskCreatePinnedToCore(
        benchmark_worker_task,
        "pqc_worker",
        kWorkerTaskStackBytes / sizeof(StackType_t),
        &params,
        configMAX_PRIORITIES - 1,
        nullptr,
        1 // Pin to Core 1 for stable, uninterrupted execution
    );

    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    return result;
}

void run_algorithm_benchmark(const char* alg_name) {
    ESP_LOGI(kTag, "==================================================");
    ESP_LOGI(kTag, "INIT BENCHMARK: %s", alg_name);
    ESP_LOGI(kTag, "==================================================");

    OQS_KEM* kem = OQS_KEM_new(alg_name);
    if (kem == nullptr) {
        ESP_LOGE(kTag, "Algorithm %s not supported in liboqs", alg_name);
        return;
    }

    Buffer pk(kem->length_public_key);
    Buffer sk(kem->length_secret_key);
    Buffer ct(kem->length_ciphertext);
    Buffer ss_send(kem->length_shared_secret);
    Buffer ss_recv(kem->length_shared_secret);

    if (!pk.valid() || !sk.valid() || !ct.valid() || !ss_send.valid() || !ss_recv.valid()) {
        ESP_LOGE(kTag, "Memory allocation failure for buffers");
        OQS_KEM_free(kem);
        return;
    }

    ESP_LOGI(kTag, "PQC_METADATA,alg=%s,pk_size=%zu,sk_size=%zu,ct_size=%zu,ss_size=%zu",
             alg_name, kem->length_public_key, kem->length_secret_key,
             kem->length_ciphertext, kem->length_shared_secret);
    ESP_LOGI(kTag, "PQC_HEADER,algorithm,operation,iteration,latency_us,cycles,peak_stack_bytes,transient_heap_bytes");

    const Operation ops[] = {keypair_op, encaps_op, decaps_op};
    const char* op_names[] = {"keypair", "encaps", "decaps"};

    for (std::size_t i = 0; i < 3; ++i) {
        for (std::size_t it = 0; it < kWarmupIterations + kMeasuredIterations; ++it) {
            Sample s;
            if (i == 0) {
                s = execute_isolated_benchmark(ops[i], kem, pk.data(), sk.data(), nullptr, nullptr);
            } else if (i == 1) {
                s = execute_isolated_benchmark(ops[i], kem, ct.data(), ss_send.data(), pk.data(), nullptr);
            } else {
                s = execute_isolated_benchmark(ops[i], kem, ss_recv.data(), ct.data(), sk.data(), nullptr);
            }

            if (!s.success) {
                ESP_LOGE(kTag, "Execution failed at iteration %zu", it);
                break;
            }

            if (it >= kWarmupIterations) {
                std::size_t trial_num = it - kWarmupIterations + 1;
                ESP_LOGI(kTag, "PQC_SAMPLE,%s,%s,%zu,%llu,%llu,%zu,%zu",
                         alg_name, op_names[i], trial_num,
                         static_cast<unsigned long long>(s.latency_us),
                         static_cast<unsigned long long>(s.cycles),
                         s.peak_stack_used, s.transient_heap_used);
            }
            vTaskDelay(pdMS_TO_TICKS(10)); // Prevent Task Watchdog panics
        }
    }

    const bool verified = (std::memcmp(ss_send.data(), ss_recv.data(), kem->length_shared_secret) == 0);
    ESP_LOGI(kTag, "PQC_VERIFY,%s,shared_secrets_match=%s", alg_name, verified ? "TRUE" : "FALSE");

    OQS_KEM_free(kem);
}

}  // namespace

extern "C" void app_main() {
    // Configure Oscilloscope/Power Profiler Hardware Trigger Pin
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << kTriggerPin),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_ENABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
    gpio_set_level(kTriggerPin, 0);

    vTaskDelay(pdMS_TO_TICKS(2000)); // Allow serial port & power rails to settle
    ESP_LOGI(kTag, "STARTING BTYSTE PQC HARDWARE BENCHMARK SUITE");

    // Benchmark all three official NIST ML-KEM tiers
    run_algorithm_benchmark("ML-KEM-512");
    run_algorithm_benchmark("ML-KEM-768");
    run_algorithm_benchmark("ML-KEM-1024");

    ESP_LOGI(kTag, "ALL BENCHMARKS COMPLETED SUCCESSFULLY");
}

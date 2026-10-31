#include "esp_cpu.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "oqs/oqs.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace {

constexpr char kTag[] = "pqc";
constexpr char kAlgorithm[] = "ML-KEM-768";
constexpr std::size_t kWarmupIterations = 1;
constexpr std::size_t kMeasuredIterations = 10;

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
    std::uint64_t latency_us;
    std::uint64_t cycles;
    std::size_t heap_before;
    std::size_t heap_after;
    std::size_t heap_low_water;
    std::size_t stack_free_before;
    std::size_t stack_free_after;
};

struct Statistics {
    std::uint64_t latency_sum = 0;
    std::uint64_t cycles_sum = 0;
    std::uint64_t latency_min = UINT64_MAX;
    std::uint64_t latency_max = 0;
    std::size_t transient_heap_max = 0;
    std::size_t stack_used_max = 0;

    void add(const Sample& sample) {
        latency_sum += sample.latency_us;
        cycles_sum += sample.cycles;
        latency_min = sample.latency_us < latency_min ? sample.latency_us : latency_min;
        latency_max = sample.latency_us > latency_max ? sample.latency_us : latency_max;
        transient_heap_max = sample.heap_low_water > transient_heap_max
            ? sample.heap_low_water : transient_heap_max;
        const std::size_t stack_used =
            sample.stack_free_before > sample.stack_free_after
                ? sample.stack_free_before - sample.stack_free_after : 0;
        stack_used_max = stack_used > stack_used_max ? stack_used : stack_used_max;
    }
};

using Operation = int (*)(OQS_KEM*, std::uint8_t*, std::uint8_t*,
                          std::uint8_t*, std::uint8_t*);

Sample measure(Operation operation, OQS_KEM* kem, std::uint8_t* output,
               std::uint8_t* auxiliary, std::uint8_t* input,
               std::uint8_t* secret_key) {
    const std::size_t heap_before = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    const std::size_t low_water_before =
        heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);
    const std::size_t stack_free_before =
        uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t);
    const std::int64_t start_us = esp_timer_get_time();
    const esp_cpu_cycle_count_t start_cycles = esp_cpu_get_cycle_count();

    if (operation(kem, output, auxiliary, input, secret_key) != OQS_SUCCESS) {
        return {};
    }

    const esp_cpu_cycle_count_t end_cycles = esp_cpu_get_cycle_count();
    const std::int64_t end_us = esp_timer_get_time();
    const std::size_t heap_after = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    const std::size_t low_water_after =
        heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);
    const std::size_t stack_free_after =
        uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t);

    return {
        static_cast<std::uint64_t>(end_us - start_us),
        static_cast<std::uint64_t>(end_cycles - start_cycles),
        heap_before,
        heap_after,
        low_water_before > low_water_after ? low_water_before - low_water_after : 0,
        stack_free_before,
        stack_free_after,
    };
}

int keypair_operation(OQS_KEM* kem, std::uint8_t* public_key,
                      std::uint8_t* secret_key, std::uint8_t*, std::uint8_t*) {
    return OQS_KEM_keypair(kem, public_key, secret_key);
}

int encaps_operation(OQS_KEM* kem, std::uint8_t* ciphertext,
                     std::uint8_t* shared_secret, std::uint8_t* public_key,
                     std::uint8_t*) {
    return OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
}

int decaps_operation(OQS_KEM* kem, std::uint8_t* shared_secret,
                     std::uint8_t* ciphertext, std::uint8_t* secret_key,
                     std::uint8_t*) {
    return OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
}

void print_csv_header(const OQS_KEM* kem, std::size_t buffer_bytes) {
    ESP_LOGI(kTag, "PQC_BENCH,algorithm=%s,iterations=%zu,warmups=%zu,"
                   "public_key_bytes=%zu,secret_key_bytes=%zu,"
                   "ciphertext_bytes=%zu,shared_secret_bytes=%zu,"
                   "preallocated_buffer_bytes=%zu",
             kAlgorithm, kMeasuredIterations, kWarmupIterations,
             kem->length_public_key, kem->length_secret_key,
             kem->length_ciphertext, kem->length_shared_secret, buffer_bytes);
    ESP_LOGI(kTag, "PQC_SAMPLE,operation,iteration,latency_us,cycles,"
                   "heap_free_before,heap_free_after,transient_heap_low_water,"
                   "stack_free_before,stack_free_after");
}

void print_sample(const char* operation, std::size_t iteration,
                  const Sample& sample) {
    ESP_LOGI(kTag, "PQC_SAMPLE,%s,%zu,%llu,%llu,%zu,%zu,%zu,%zu,%zu",
             operation, iteration,
             static_cast<unsigned long long>(sample.latency_us),
             static_cast<unsigned long long>(sample.cycles),
             sample.heap_before, sample.heap_after, sample.heap_low_water,
             sample.stack_free_before, sample.stack_free_after);
}

void print_summary(const char* operation, const Statistics& statistics) {
    ESP_LOGI(kTag, "PQC_SUMMARY,%s,avg_latency_us=%llu,min_latency_us=%llu,"
                   "max_latency_us=%llu,avg_cycles=%llu,"
                   "peak_transient_heap_bytes=%zu,peak_stack_used_bytes=%zu",
             operation,
             static_cast<unsigned long long>(
                 statistics.latency_sum / kMeasuredIterations),
             static_cast<unsigned long long>(statistics.latency_min),
             static_cast<unsigned long long>(statistics.latency_max),
             static_cast<unsigned long long>(
                 statistics.cycles_sum / kMeasuredIterations),
             statistics.transient_heap_max, statistics.stack_used_max);
}

}  // namespace

extern "C" void app_main() {
    ESP_LOGI(kTag, "Starting %s latency/memory benchmark", kAlgorithm);
    OQS_KEM* kem = OQS_KEM_new(kAlgorithm);
    if (kem == nullptr) {
        ESP_LOGE(kTag, "%s is not enabled in liboqs", kAlgorithm);
        return;
    }

    Buffer public_key(kem->length_public_key);
    Buffer secret_key(kem->length_secret_key);
    Buffer ciphertext(kem->length_ciphertext);
    Buffer sender_secret(kem->length_shared_secret);
    Buffer receiver_secret(kem->length_shared_secret);
    const std::size_t buffer_bytes = kem->length_public_key +
        kem->length_secret_key + kem->length_ciphertext +
        2 * kem->length_shared_secret;

    if (!public_key.valid() || !secret_key.valid() || !ciphertext.valid() ||
        !sender_secret.valid() || !receiver_secret.valid()) {
        ESP_LOGE(kTag, "Not enough heap for benchmark buffers");
        OQS_KEM_free(kem);
        return;
    }

    print_csv_header(kem, buffer_bytes);

    const Operation operations[] = {
        keypair_operation, encaps_operation, decaps_operation,
    };
    const char* names[] = {"keypair", "encaps", "decaps"};
    Statistics statistics[3];

    for (std::size_t operation_index = 0; operation_index < 3; ++operation_index) {
        for (std::size_t iteration = 0;
             iteration < kWarmupIterations + kMeasuredIterations; ++iteration) {
            Sample sample{};
            if (operation_index == 0) {
                sample = measure(operations[operation_index], kem,
                                 public_key.data(), secret_key.data(), nullptr,
                                 nullptr);
            } else if (operation_index == 1) {
                sample = measure(operations[operation_index], kem,
                                 ciphertext.data(), sender_secret.data(),
                                 public_key.data(), nullptr);
            } else {
                sample = measure(operations[operation_index], kem,
                                 receiver_secret.data(), ciphertext.data(),
                                 secret_key.data(), nullptr);
            }

            if (sample.latency_us == 0 || sample.cycles == 0) {
                ESP_LOGE(kTag, "%s failed at iteration %zu", names[operation_index],
                         iteration);
                OQS_KEM_free(kem);
                return;
            }
            if (iteration >= kWarmupIterations) {
                const std::size_t measured_iteration =
                    iteration - kWarmupIterations + 1;
                print_sample(names[operation_index], measured_iteration, sample);
                statistics[operation_index].add(sample);
            }
        }
        print_summary(names[operation_index], statistics[operation_index]);
    }

    const bool match =
        std::memcmp(sender_secret.data(), receiver_secret.data(),
                    kem->length_shared_secret) == 0;
    ESP_LOGI(kTag, "PQC_RESULT,shared_secrets_match=%s", match ? "true" : "false");
    OQS_KEM_free(kem);
}

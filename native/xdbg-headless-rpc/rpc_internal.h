#pragma once

#include "jansson.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace headless_re_rpc
{
constexpr const char* ProtocolName = "headless-re-xdbg";
constexpr int ProtocolVersion = 1;
// Frame must fit hex-encoded memory.read payloads (2 MiB -> ~4 MiB hex + envelope).
constexpr std::uint32_t MaxFrameBytes = 8U * 1024U * 1024U;
constexpr std::uint64_t MaxMemoryBytes = 2U * 1024U * 1024U;
// Single modules.dump / region scan hard cap (ADR M4.2). Larger images fail closed.
constexpr std::uint64_t MaxDumpBytes = 64U * 1024U * 1024U;
constexpr std::uint64_t MaxRegionCount = 8192;
constexpr std::uint64_t MaxImportScanBytes = 16U * 1024U * 1024U;
constexpr std::uint64_t MaxImportCandidates = 32;
constexpr std::uint64_t MaxImportApiCatalog = 50000;
constexpr std::uint64_t MaxStackEntries = 256;
constexpr std::uint64_t MaxDisasmInstructions = 256;
constexpr std::uint64_t MaxSymbolEnum = 4096;
constexpr std::uint64_t MaxConditionExprBytes = 512;
constexpr std::uint64_t MaxTraceEvents = 1000000;
constexpr std::uint64_t MaxTraceTimeoutMs = 3600000;
constexpr std::uint64_t MaxTraceFileBytes = 256ULL * 1024ULL * 1024ULL;
constexpr std::size_t DebugEventCapacity = 1024;
constexpr std::uint64_t DefaultDebugEventBatch = 100;
constexpr std::uint64_t MaxDebugEventBatch = 256;
constexpr std::uint32_t DefaultDispatchTimeoutMs = 5000U;
constexpr std::uint32_t MaxDispatchTimeoutMs = 30000U;

class JsonPtr
{
public:
    JsonPtr() = default;
    explicit JsonPtr(json_t* value)
        : value_(value)
    {
    }

    ~JsonPtr()
    {
        json_decref(value_);
    }

    JsonPtr(const JsonPtr&) = delete;
    JsonPtr& operator=(const JsonPtr&) = delete;

    JsonPtr(JsonPtr&& other) noexcept
        : value_(other.release())
    {
    }

    JsonPtr& operator=(JsonPtr&& other) noexcept
    {
        if(this != &other)
        {
            json_decref(value_);
            value_ = other.release();
        }
        return *this;
    }

    json_t* get() const
    {
        return value_;
    }

    json_t* release()
    {
        auto value = value_;
        value_ = nullptr;
        return value;
    }

    explicit operator bool() const
    {
        return value_ != nullptr;
    }

private:
    json_t* value_ = nullptr;
};

inline JsonPtr JsonObject()
{
    return JsonPtr(json_object());
}

inline JsonPtr JsonArray()
{
    return JsonPtr(json_array());
}

inline JsonPtr JsonString(const std::string& value)
{
    return JsonPtr(json_stringn(value.data(), value.size()));
}

inline JsonPtr JsonInteger(std::uint64_t value)
{
    return JsonPtr(json_integer(static_cast<json_int_t>(value)));
}

inline JsonPtr JsonBoolean(bool value)
{
    return JsonPtr(json_boolean(value));
}

inline void JsonSet(json_t* object, const char* key, JsonPtr value)
{
    json_object_set_new(object, key, value.release());
}

inline void JsonAppend(json_t* array, JsonPtr value)
{
    json_array_append_new(array, value.release());
}

struct Outcome
{
    bool ok = false;
    JsonPtr value;
    std::string code;
    std::string message;
    JsonPtr details;
    bool retryable = false;

    static Outcome Success(JsonPtr result)
    {
        Outcome outcome;
        outcome.ok = true;
        outcome.value = std::move(result);
        return outcome;
    }

    static Outcome Failure(
        std::string errorCode,
        std::string errorMessage,
        bool canRetry = false,
        JsonPtr errorDetails = JsonObject())
    {
        Outcome outcome;
        outcome.code = std::move(errorCode);
        outcome.message = std::move(errorMessage);
        outcome.retryable = canRetry;
        outcome.details = std::move(errorDetails);
        return outcome;
    }
};

bool IsDebuggerMethod(const std::string& method);
Outcome DispatchDebuggerMethod(const std::string& method, const json_t* params);
JsonPtr BuildDebuggerState();
bool StartDebugEventCapture();
void StopDebugEventCapture();
Outcome ReadDebugEvents(const json_t* params);

} // namespace headless_re_rpc
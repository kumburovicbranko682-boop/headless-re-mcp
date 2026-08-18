#include "headless_rpc.h"
#include "rpc_internal.h"

#include "bridgemain.h"

#include <Windows.h>
#include <Aclapi.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace headless_re_rpc
{
namespace
{
struct StartupOptions
{
    bool configured = false;
    std::wstring pipeName;
    std::string token;
    std::string error;
};

bool ReadEnvironment(const wchar_t* name, std::wstring& value)
{
    SetLastError(ERROR_SUCCESS);
    auto size = GetEnvironmentVariableW(name, nullptr, 0);
    if(size == 0)
        return GetLastError() != ERROR_ENVVAR_NOT_FOUND;
    std::vector<wchar_t> buffer(size);
    if(GetEnvironmentVariableW(name, buffer.data(), size) == 0)
        return false;
    value.assign(buffer.data());
    return true;
}

bool IsPipeSuffixSafe(const std::wstring& value)
{
    if(value.empty() || value.size() > 200)
        return false;
    for(auto character : value)
    {
        if((character >= L'a' && character <= L'z')
           || (character >= L'A' && character <= L'Z')
           || (character >= L'0' && character <= L'9') || character == L'-'
           || character == L'_' || character == L'.')
            continue;
        return false;
    }
    return true;
}

bool WideToUtf8(const std::wstring& value, std::string& result)
{
    if(value.empty())
    {
        result.clear();
        return true;
    }
    auto size = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if(size <= 0)
        return false;
    result.resize(static_cast<std::size_t>(size));
    return WideCharToMultiByte(
               CP_UTF8,
               WC_ERR_INVALID_CHARS,
               value.data(),
               static_cast<int>(value.size()),
               &result[0],
               size,
               nullptr,
               nullptr)
        == size;
}

StartupOptions ParseStartupOptions()
{
    StartupOptions options;
    std::wstring pipeSuffix;
    std::wstring token;
    auto pipeSeen = ReadEnvironment(L"HEADLESS_RE_XDBG_RPC_PIPE", pipeSuffix);
    auto tokenSeen = ReadEnvironment(L"HEADLESS_RE_XDBG_RPC_TOKEN", token);
    SetEnvironmentVariableW(L"HEADLESS_RE_XDBG_RPC_PIPE", nullptr);
    SetEnvironmentVariableW(L"HEADLESS_RE_XDBG_RPC_TOKEN", nullptr);

    if(!pipeSeen && !tokenSeen)
        return options;
    options.configured = true;
    if(!pipeSeen || !tokenSeen || !IsPipeSuffixSafe(pipeSuffix))
    {
        options.error = "RPC pipe and token environment variables must both be valid";
        return options;
    }
    if(token.size() < 32 || token.size() > 512 || !WideToUtf8(token, options.token))
    {
        options.error = "RPC token must contain 32 to 512 UTF-8 bytes";
        return options;
    }
    options.pipeName = L"\\\\.\\pipe\\" + pipeSuffix;
    return options;
}

bool ConstantTimeEqual(const std::string& left, const std::string& right)
{
    auto difference = left.size() ^ right.size();
    auto count = left.size() > right.size() ? left.size() : right.size();
    for(std::size_t index = 0; index < count; ++index)
    {
        auto leftValue = index < left.size() ? static_cast<unsigned char>(left[index]) : 0;
        auto rightValue = index < right.size() ? static_cast<unsigned char>(right[index]) : 0;
        difference |= leftValue ^ rightValue;
    }
    return difference == 0;
}

class PipeSecurity
{
public:
    PipeSecurity()
    {
        HANDLE rawToken = nullptr;
        if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
            return;
        std::unique_ptr<void, decltype(&CloseHandle)> token(rawToken, CloseHandle);

        DWORD size = 0;
        GetTokenInformation(rawToken, TokenUser, nullptr, 0, &size);
        if(GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0)
            return;
        tokenUser_.resize(size);
        if(!GetTokenInformation(
               rawToken, TokenUser, tokenUser_.data(), size, &size))
            return;

        EXPLICIT_ACCESSW access = {};
        access.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
        access.grfAccessMode = SET_ACCESS;
        access.grfInheritance = NO_INHERITANCE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_USER;
        access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(
            reinterpret_cast<TOKEN_USER*>(tokenUser_.data())->User.Sid);
        if(SetEntriesInAclW(1, &access, nullptr, &acl_) != ERROR_SUCCESS)
            return;

        descriptor_ = static_cast<PSECURITY_DESCRIPTOR>(
            LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH));
        if(descriptor_ == nullptr
           || !InitializeSecurityDescriptor(descriptor_, SECURITY_DESCRIPTOR_REVISION)
           || !SetSecurityDescriptorDacl(descriptor_, TRUE, acl_, FALSE))
            return;

        attributes_.nLength = sizeof(attributes_);
        attributes_.lpSecurityDescriptor = descriptor_;
        attributes_.bInheritHandle = FALSE;
        valid_ = true;
    }

    ~PipeSecurity()
    {
        if(descriptor_ != nullptr)
            LocalFree(descriptor_);
        if(acl_ != nullptr)
            LocalFree(acl_);
    }

    SECURITY_ATTRIBUTES* get()
    {
        return valid_ ? &attributes_ : nullptr;
    }

private:
    bool valid_ = false;
    std::vector<unsigned char> tokenUser_;
    PACL acl_ = nullptr;
    PSECURITY_DESCRIPTOR descriptor_ = nullptr;
    SECURITY_ATTRIBUTES attributes_ = {};
};

bool ReadExact(HANDLE pipe, void* destination, std::uint32_t size)
{
    auto output = static_cast<unsigned char*>(destination);
    std::uint32_t offset = 0;
    while(offset < size)
    {
        DWORD read = 0;
        if(!ReadFile(pipe, output + offset, size - offset, &read, nullptr) || read == 0)
            return false;
        offset += read;
    }
    return true;
}

bool WriteExact(HANDLE pipe, const void* source, std::uint32_t size)
{
    const auto input = static_cast<const unsigned char*>(source);
    std::uint32_t offset = 0;
    while(offset < size)
    {
        DWORD written = 0;
        if(!WriteFile(pipe, input + offset, size - offset, &written, nullptr)
           || written == 0)
            return false;
        offset += written;
    }
    return true;
}

std::uint32_t DecodeFrameLength(const unsigned char header[4])
{
    return static_cast<std::uint32_t>(header[0])
        | (static_cast<std::uint32_t>(header[1]) << 8)
        | (static_cast<std::uint32_t>(header[2]) << 16)
        | (static_cast<std::uint32_t>(header[3]) << 24);
}

void EncodeFrameLength(std::uint32_t length, unsigned char header[4])
{
    header[0] = static_cast<unsigned char>(length & 0xff);
    header[1] = static_cast<unsigned char>((length >> 8) & 0xff);
    header[2] = static_cast<unsigned char>((length >> 16) & 0xff);
    header[3] = static_cast<unsigned char>((length >> 24) & 0xff);
}

JsonPtr ResponseBase(const std::string* requestId)
{
    auto response = JsonObject();
    JsonSet(response.get(), "protocol", JsonString(ProtocolName));
    JsonSet(response.get(), "version", JsonInteger(ProtocolVersion));
    if(requestId == nullptr)
        json_object_set_new(response.get(), "id", json_null());
    else
        JsonSet(response.get(), "id", JsonString(*requestId));
    return response;
}

JsonPtr BuildResponse(const std::string* requestId, Outcome outcome)
{
    auto response = ResponseBase(requestId);
    JsonSet(response.get(), "ok", JsonBoolean(outcome.ok));
    if(outcome.ok)
    {
        JsonSet(
            response.get(),
            "result",
            outcome.value ? std::move(outcome.value) : JsonObject());
        return response;
    }

    auto error = JsonObject();
    JsonSet(error.get(), "code", JsonString(outcome.code));
    JsonSet(error.get(), "message", JsonString(outcome.message));
    JsonSet(error.get(), "retryable", JsonBoolean(outcome.retryable));
    JsonSet(
        error.get(),
        "details",
        outcome.details ? std::move(outcome.details) : JsonObject());
    JsonSet(response.get(), "error", std::move(error));
    return response;
}

int JsonDumpCallback(const char* buffer, size_t size, void* context)
{
    auto encoded = static_cast<std::string*>(context);
    if(size > MaxFrameBytes - encoded->size())
        return -1;
    try
    {
        encoded->append(buffer, size);
    }
    catch(...)
    {
        return -1;
    }
    return 0;
}

bool WriteJsonFrame(HANDLE pipe, const json_t* value)
{
    std::string encoded;
    encoded.reserve(4096);
    if(json_dump_callback(
           value, JsonDumpCallback, &encoded, JSON_COMPACT | JSON_ENSURE_ASCII)
           != 0
       || encoded.empty())
        return false;

    unsigned char header[4] = {};
    EncodeFrameLength(static_cast<std::uint32_t>(encoded.size()), header);
    return WriteExact(pipe, header, sizeof(header))
        && WriteExact(pipe, encoded.data(), static_cast<std::uint32_t>(encoded.size()));
}

struct MainThreadJob
{
    std::string method;
    JsonPtr params;
    std::mutex mutex;
    std::condition_variable completed;
    std::atomic<bool> cancelled{ false };
    bool done = false;
    Outcome outcome;
};

class RpcServer
{
public:
    bool Start()
    {
        std::lock_guard<std::mutex> lock(lifecycleMutex_);
        if(started_)
            return true;

        auto options = ParseStartupOptions();
        if(!options.configured)
        {
            started_ = true;
            return true;
        }
        if(!options.error.empty())
        {
            fprintf(stderr, "[headless-rpc] configuration error: %s\n", options.error.c_str());
            return false;
        }

        pipeName_ = std::move(options.pipeName);
        token_ = std::move(options.token);
        stopping_ = false;
        if(!StartDebugEventCapture())
        {
            token_.clear();
            fprintf(stderr, "[headless-rpc] debugger callback API is unavailable\n");
            return false;
        }
        enabled_ = true;
        try
        {
            thread_ = std::thread([this]()
            {
                Run();
            });
        }
        catch(const std::exception& exception)
        {
            StopDebugEventCapture();
            token_.clear();
            enabled_ = false;
            fprintf(stderr, "[headless-rpc] failed to start transport: %s\n", exception.what());
            return false;
        }
        started_ = true;
        printf("[headless-rpc] protocol v%d ready\n", ProtocolVersion);
        return true;
    }

    void Stop()
    {
        std::unique_lock<std::mutex> lock(lifecycleMutex_);
        if(!started_)
            return;
        if(enabled_)
            StopDebugEventCapture();
        stopping_ = true;
        {
            std::lock_guard<std::mutex> activeLock(activeMutex_);
            if(auto active = activeJob_.lock())
                active->completed.notify_all();
        }
        if(thread_.joinable())
            CancelSynchronousIo(thread_.native_handle());
        lock.unlock();
        if(thread_.joinable())
            thread_.join();
        lock.lock();
        token_.clear();
        enabled_ = false;
        started_ = false;
    }

private:
    void Run()
    {
        while(!stopping_)
        {
            PipeSecurity security;
            if(security.get() == nullptr)
            {
                fprintf(stderr, "[headless-rpc] failed to create owner-only pipe ACL\n");
                if(stopping_.load())
                    return;
                Sleep(1000);
                continue;
            }
            auto pipe = CreateNamedPipeW(
                pipeName_.c_str(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                security.get());
            if(pipe == INVALID_HANDLE_VALUE)
            {
                if(!stopping_.load())
                    fprintf(
                        stderr,
                        "[headless-rpc] CreateNamedPipeW failed: %lu\n",
                        GetLastError());
                if(stopping_.load())
                    return;
                Sleep(1000);
                continue;
            }

            auto connected = ConnectNamedPipe(pipe, nullptr)
                || GetLastError() == ERROR_PIPE_CONNECTED;
            if(connected && !stopping_)
                ServeClient(pipe);
            if(!stopping_)
                FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
    }

    void ServeClient(HANDLE pipe)
    {
        bool authenticated = false;
        while(!stopping_)
        {
            unsigned char header[4] = {};
            if(!ReadExact(pipe, header, sizeof(header)))
                return;
            auto length = DecodeFrameLength(header);
            if(length == 0 || length > MaxFrameBytes)
            {
                auto response = BuildResponse(
                    nullptr,
                    Outcome::Failure("invalid_frame", "frame length is outside protocol limits"));
                WriteJsonFrame(pipe, response.get());
                return;
            }

            std::string payload(length, '\0');
            if(!ReadExact(pipe, &payload[0], length))
                return;
            json_error_t parseError = {};
            JsonPtr request(json_loadb(
                payload.data(),
                payload.size(),
                JSON_REJECT_DUPLICATES,
                &parseError));
            if(!request || !json_is_object(request.get()))
            {
                auto details = JsonObject();
                JsonSet(details.get(), "position", JsonInteger(parseError.position));
                JsonSet(details.get(), "text", JsonString(parseError.text));
                auto response = BuildResponse(
                    nullptr,
                    Outcome::Failure(
                        "invalid_json",
                        "request must be one valid JSON object",
                        false,
                        std::move(details)));
                WriteJsonFrame(pipe, response.get());
                return;
            }

            std::string requestId;
            const std::string* responseId = nullptr;
            auto id = json_object_get(request.get(), "id");
            if(json_is_string(id) && json_string_length(id) > 0
               && json_string_length(id) <= 128)
            {
                requestId.assign(json_string_value(id), json_string_length(id));
                responseId = &requestId;
            }
            else
            {
                auto response = BuildResponse(
                    nullptr,
                    Outcome::Failure("invalid_request", "id must be a non-empty bounded string"));
                if(!WriteJsonFrame(pipe, response.get()))
                    return;
                continue;
            }

            auto outcome = HandleRequest(request.get(), authenticated);
            auto closeAfterResponse = !authenticated && outcome.code == "authentication_failed";
            auto response = BuildResponse(responseId, std::move(outcome));
            if(!WriteJsonFrame(pipe, response.get()) || closeAfterResponse)
                return;
        }
    }

    Outcome HandleRequest(const json_t* request, bool& authenticated)
    {
        auto protocol = json_object_get(request, "protocol");
        auto version = json_object_get(request, "version");
        if(!json_is_string(protocol) || strcmp(json_string_value(protocol), ProtocolName) != 0
           || !json_is_integer(version) || json_integer_value(version) != ProtocolVersion)
        {
            auto details = JsonObject();
            JsonSet(details.get(), "expected_protocol", JsonString(ProtocolName));
            JsonSet(details.get(), "expected_version", JsonInteger(ProtocolVersion));
            return Outcome::Failure(
                "protocol_mismatch",
                "request protocol or version is unsupported",
                false,
                std::move(details));
        }

        auto methodValue = json_object_get(request, "method");
        if(!json_is_string(methodValue) || json_string_length(methodValue) == 0
           || json_string_length(methodValue) > 128)
            return Outcome::Failure("invalid_request", "method must be a bounded string");
        std::string method(json_string_value(methodValue), json_string_length(methodValue));

        JsonPtr emptyParams;
        auto params = json_object_get(request, "params");
        if(params == nullptr)
        {
            emptyParams = JsonObject();
            params = emptyParams.get();
        }
        if(!json_is_object(params))
            return Outcome::Failure("invalid_request", "params must be an object");

        if(!authenticated)
        {
            if(method != "rpc.hello")
                return Outcome::Failure(
                    "authentication_required", "rpc.hello must be the first request");
            auto token = json_object_get(params, "token");
            if(!json_is_string(token)
               || !ConstantTimeEqual(
                   token_,
                   std::string(json_string_value(token), json_string_length(token))))
                return Outcome::Failure(
                    "authentication_failed", "RPC authentication failed");
            authenticated = true;
            return Outcome::Success(BuildHello());
        }

        if(method == "rpc.hello")
            return Outcome::Failure("invalid_request", "RPC connection is already authenticated");
        if(method == "rpc.ping")
        {
            auto result = JsonObject();
            JsonSet(result.get(), "pid", JsonInteger(GetCurrentProcessId()));
            JsonSet(result.get(), "protocol_version", JsonInteger(ProtocolVersion));
            return Outcome::Success(std::move(result));
        }
        const auto eventMethod = method == "events.read";
        if(!eventMethod && !IsDebuggerMethod(method))
            return Outcome::Failure("method_not_found", "RPC method is not supported");

        std::uint32_t timeout = DefaultDispatchTimeoutMs;
        auto timeoutValue = json_object_get(request, "timeout_ms");
        if(timeoutValue != nullptr)
        {
            if(!json_is_integer(timeoutValue) || json_integer_value(timeoutValue) <= 0
               || json_integer_value(timeoutValue) > MaxDispatchTimeoutMs)
                return Outcome::Failure(
                    "invalid_request", "timeout_ms is outside protocol limits");
            timeout = static_cast<std::uint32_t>(json_integer_value(timeoutValue));
        }
        if(eventMethod)
            return ReadDebugEvents(params);
        return Schedule(method, params, timeout);
    }

    JsonPtr BuildHello() const
    {
        auto result = JsonObject();
        JsonSet(result.get(), "server", JsonString("x64dbg-headless-rpc"));
        JsonSet(result.get(), "protocol_version", JsonInteger(ProtocolVersion));
        JsonSet(result.get(), "pid", JsonInteger(GetCurrentProcessId()));
#ifdef _WIN64
        JsonSet(result.get(), "architecture", JsonString("x64"));
#else
        JsonSet(result.get(), "architecture", JsonString("x86"));
#endif
        auto capabilities = JsonArray();
        const char* methods[] = {
            "debug.state",
            "debug.launch",
            "debug.attach",
            "debug.stop",
            "debug.pause",
            "debug.resume",
            "debug.step_into",
            "debug.step_over",
            "registers.read",
            "registers.write",
            "memory.read",
            "memory.write",
            "memory.regions",
            "memory.protect.query",
            "memory.protection",
            "modules.list",
            "modules.dump",
            "pe.headers.runtime",
            "imports.scan",
            "imports.read",
            "imports.rebuild",
            "events.read",
            "threads.list",
            "threads.current",
            "threads.context.read",
            "threads.context.write",
            "stack.read",
            "stack.trace",
            "disassembly.read",
            "symbols.list",
            "symbols.resolve",
            "breakpoints.list",
            "breakpoints.set",
            "breakpoints.remove",
            "breakpoints.hardware.set",
            "breakpoints.hardware.remove",
            "breakpoints.hardware.list",
            "breakpoints.memory.set",
            "breakpoints.memory.remove",
            "breakpoints.memory.list",
            "breakpoints.condition.set",
            "breakpoints.condition.get",
            "patches.list",
            "patches.apply",
            "patches.restore",
            "trace.start",
            "trace.stop",
            "trace.status",
        };
        for(const auto method : methods)
            JsonAppend(capabilities.get(), JsonString(method));
        JsonSet(result.get(), "capabilities", std::move(capabilities));

        auto limits = JsonObject();
        JsonSet(limits.get(), "max_frame_bytes", JsonInteger(MaxFrameBytes));
        JsonSet(limits.get(), "max_memory_bytes", JsonInteger(MaxMemoryBytes));
        JsonSet(limits.get(), "max_dump_bytes", JsonInteger(MaxDumpBytes));
        JsonSet(limits.get(), "max_region_count", JsonInteger(MaxRegionCount));
        JsonSet(limits.get(), "max_import_scan_bytes", JsonInteger(MaxImportScanBytes));
        JsonSet(limits.get(), "max_import_candidates", JsonInteger(MaxImportCandidates));
        JsonSet(limits.get(), "event_capacity", JsonInteger(DebugEventCapacity));
        JsonSet(limits.get(), "default_event_batch", JsonInteger(DefaultDebugEventBatch));
        JsonSet(limits.get(), "max_event_batch", JsonInteger(MaxDebugEventBatch));
        JsonSet(
            limits.get(), "max_dispatch_timeout_ms", JsonInteger(MaxDispatchTimeoutMs));
        JsonSet(result.get(), "limits", std::move(limits));
        return result;
    }

    static void ExecuteOnMainThread(void* context)
    {
        std::unique_ptr<std::shared_ptr<MainThreadJob>> holder(
            static_cast<std::shared_ptr<MainThreadJob>*>(context));
        const auto job = *holder;
        Outcome outcome;
        if(job->cancelled.load())
        {
            auto details = JsonObject();
            JsonSet(details.get(), "method", JsonString(job->method));
            outcome = Outcome::Failure(
                "dispatch_timeout",
                "main command thread cancelled the request after the caller deadline",
                false,
                std::move(details));
            {
                std::lock_guard<std::mutex> lock(job->mutex);
                job->outcome = std::move(outcome);
                job->done = true;
            }
            job->completed.notify_all();
            return;
        }
        try
        {
            outcome = DispatchDebuggerMethod(job->method, job->params.get());
        }
        catch(const std::exception& exception)
        {
            outcome = Outcome::Failure(
                "native_exception",
                std::string("native RPC method failed: ") + exception.what());
        }
        catch(...)
        {
            outcome = Outcome::Failure(
                "native_exception", "native RPC method failed with an unknown exception");
        }
        {
            std::lock_guard<std::mutex> lock(job->mutex);
            job->outcome = std::move(outcome);
            job->done = true;
        }
        job->completed.notify_all();
    }

    Outcome Schedule(const std::string& method, const json_t* params, std::uint32_t timeout)
    {
        auto job = std::make_shared<MainThreadJob>();
        job->method = method;
        job->params = JsonPtr(json_deep_copy(params));
        if(!job->params)
            return Outcome::Failure("internal_error", "could not copy request parameters");
        {
            std::lock_guard<std::mutex> lock(activeMutex_);
            activeJob_ = job;
        }
        auto holder = new std::shared_ptr<MainThreadJob>(job);
        GuiExecuteOnGuiThreadEx(ExecuteOnMainThread, holder);

        std::unique_lock<std::mutex> lock(job->mutex);
        auto completed = job->completed.wait_for(
            lock,
            std::chrono::milliseconds(timeout),
            [this, &job]()
            {
                return job->done || stopping_.load();
            });
        {
            std::lock_guard<std::mutex> activeLock(activeMutex_);
            activeJob_.reset();
        }
        if(!completed || !job->done)
        {
            job->cancelled.store(true);
            auto details = JsonObject();
            JsonSet(details.get(), "method", JsonString(method));
            JsonSet(details.get(), "timeout_ms", JsonInteger(timeout));
            return Outcome::Failure(
                "dispatch_timeout",
                "main command thread did not finish the request before the deadline; completion is unknown",
                false,
                std::move(details));
        }
        return std::move(job->outcome);
    }

    std::mutex lifecycleMutex_;
    bool started_ = false;
    bool enabled_ = false;
    std::atomic<bool> stopping_{ false };
    std::wstring pipeName_;
    std::string token_;
    std::thread thread_;
    std::mutex activeMutex_;
    std::weak_ptr<MainThreadJob> activeJob_;
};

RpcServer& Server()
{
    static RpcServer server;
    return server;
}

} // namespace
} // namespace headless_re_rpc

bool HeadlessReRpcStart()
{
    return headless_re_rpc::Server().Start();
}

void HeadlessReRpcStop()
{
    headless_re_rpc::Server().Stop();
}
#include "rpc_internal.h"

#include "bridgemain.h"
#include "_plugins.h"

#include <Windows.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace headless_re_rpc
{
namespace
{
constexpr int EventCallbackHandle = -0x485245;
constexpr std::size_t EventPathBytes = 1024;
constexpr std::size_t EventNameBytes = 512;

using RegisterCallback = void (*)(int, CBTYPE, CBPLUGIN);
using UnregisterCallback = bool (*)(int, CBTYPE);

RegisterCallback registerCallback = nullptr;
UnregisterCallback unregisterCallback = nullptr;

constexpr std::uint32_t FieldProcessId = 1U << 0;
constexpr std::uint32_t FieldThreadId = 1U << 1;
constexpr std::uint32_t FieldImageBase = 1U << 2;
constexpr std::uint32_t FieldStartAddress = 1U << 3;
constexpr std::uint32_t FieldExitCode = 1U << 4;
constexpr std::uint32_t FieldThreadLocalBase = 1U << 5;
constexpr std::uint32_t FieldBase = 1U << 6;
constexpr std::uint32_t FieldSize = 1U << 7;
constexpr std::uint32_t FieldBreakpointType = 1U << 8;
constexpr std::uint32_t FieldAddress = 1U << 9;
constexpr std::uint32_t FieldExceptionCode = 1U << 10;
constexpr std::uint32_t FieldFirstChance = 1U << 11;

enum class EventKind : std::uint8_t
{
    DebugInit,
    DebugStopping,
    DebugStopped,
    ProcessCreated,
    ProcessExited,
    ThreadCreated,
    ThreadExited,
    ModuleLoaded,
    ModuleUnloaded,
    BreakpointHit,
    Exception,
    SystemBreakpoint,
    DebugPaused,
    DebugResumed,
    DebugStepped,
    DebugAttaching,
    DebugDetaching,
    UnrecoveredGap,
};

template<std::size_t Capacity>
struct EventText
{
    std::array<char, Capacity> value = {};
    bool present = false;
    bool truncated = false;
};

struct EventRecord
{
    std::uint64_t sequence = 0;
    std::uint64_t timestampUnixMs = 0;
    EventKind kind = EventKind::DebugInit;
    std::uint32_t fields = 0;
    std::uint64_t processId = 0;
    std::uint64_t threadId = 0;
    std::uint64_t imageBase = 0;
    std::uint64_t startAddress = 0;
    std::uint64_t exitCode = 0;
    std::uint64_t threadLocalBase = 0;
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::uint64_t breakpointType = 0;
    std::uint64_t address = 0;
    std::uint64_t exceptionCode = 0;
    bool firstChance = false;
    EventText<EventPathBytes> path;
    EventText<EventNameBytes> name;
    EventText<EventNameBytes> module;
};

std::uint64_t TimestampUnixMs() noexcept
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

template<std::size_t Capacity>
void CopyText(EventText<Capacity>& destination, const char* source) noexcept
{
    destination.present = true;
    if(source == nullptr)
        return;

    std::size_t length = 0;
    while(length + 1 < Capacity && source[length] != '\0')
        ++length;
    if(length != 0)
        memcpy(destination.value.data(), source, length);
    destination.value[length] = '\0';
    destination.truncated = source[length] != '\0';
}

std::uint64_t PointerValue(const void* value) noexcept
{
    return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(value));
}

bool HasField(const EventRecord& event, std::uint32_t field) noexcept
{
    return (event.fields & field) != 0;
}

const char* EventKindName(EventKind kind) noexcept
{
    switch(kind)
    {
    case EventKind::DebugInit:
        return "debug.init";
    case EventKind::DebugStopping:
        return "debug.stopping";
    case EventKind::DebugStopped:
        return "debug.stopped";
    case EventKind::ProcessCreated:
        return "process.created";
    case EventKind::ProcessExited:
        return "process.exited";
    case EventKind::ThreadCreated:
        return "thread.created";
    case EventKind::ThreadExited:
        return "thread.exited";
    case EventKind::ModuleLoaded:
        return "module.loaded";
    case EventKind::ModuleUnloaded:
        return "module.unloaded";
    case EventKind::BreakpointHit:
        return "breakpoint.hit";
    case EventKind::Exception:
        return "exception";
    case EventKind::SystemBreakpoint:
        return "debug.system_breakpoint";
    case EventKind::DebugPaused:
        return "debug.paused";
    case EventKind::DebugResumed:
        return "debug.resumed";
    case EventKind::DebugStepped:
        return "debug.stepped";
    case EventKind::DebugAttaching:
        return "debug.attaching";
    case EventKind::DebugDetaching:
        return "debug.detaching";
    case EventKind::UnrecoveredGap:
        return "debug.unrecovered_gap";
    }
    return "unknown";
}

template<std::size_t Capacity>
void SetText(json_t* object, const char* key, const EventText<Capacity>& text)
{
    if(!text.present)
        return;
    JsonSet(object, key, JsonString(text.value.data()));
    if(text.truncated)
    {
        const auto truncatedKey = std::string(key) + "_truncated";
        JsonSet(object, truncatedKey.c_str(), JsonBoolean(true));
    }
}

JsonPtr BuildEventData(const EventRecord& event)
{
    auto data = JsonObject();
    switch(event.kind)
    {
    case EventKind::DebugInit:
        SetText(data.get(), "path", event.path);
        break;
    case EventKind::ProcessCreated:
        if(HasField(event, FieldProcessId))
            JsonSet(data.get(), "process_id", JsonInteger(event.processId));
        if(HasField(event, FieldThreadId))
            JsonSet(data.get(), "thread_id", JsonInteger(event.threadId));
        if(HasField(event, FieldImageBase))
            JsonSet(data.get(), "image_base", JsonInteger(event.imageBase));
        if(HasField(event, FieldStartAddress))
            JsonSet(data.get(), "start_address", JsonInteger(event.startAddress));
        SetText(data.get(), "path", event.path);
        break;
    case EventKind::ProcessExited:
        if(HasField(event, FieldExitCode))
            JsonSet(data.get(), "exit_code", JsonInteger(event.exitCode));
        break;
    case EventKind::ThreadCreated:
        if(HasField(event, FieldThreadId))
            JsonSet(data.get(), "thread_id", JsonInteger(event.threadId));
        if(HasField(event, FieldStartAddress))
            JsonSet(data.get(), "start_address", JsonInteger(event.startAddress));
        if(HasField(event, FieldThreadLocalBase))
            JsonSet(data.get(), "thread_local_base", JsonInteger(event.threadLocalBase));
        break;
    case EventKind::ThreadExited:
        if(HasField(event, FieldThreadId))
            JsonSet(data.get(), "thread_id", JsonInteger(event.threadId));
        if(HasField(event, FieldExitCode))
            JsonSet(data.get(), "exit_code", JsonInteger(event.exitCode));
        break;
    case EventKind::ModuleLoaded:
        if(HasField(event, FieldBase))
            JsonSet(data.get(), "base", JsonInteger(event.base));
        if(HasField(event, FieldSize))
            JsonSet(data.get(), "size", JsonInteger(event.size));
        SetText(data.get(), "name", event.name);
        break;
    case EventKind::ModuleUnloaded:
        if(HasField(event, FieldBase))
            JsonSet(data.get(), "base", JsonInteger(event.base));
        break;
    case EventKind::BreakpointHit:
        if(HasField(event, FieldAddress))
            JsonSet(data.get(), "address", JsonInteger(event.address));
        if(HasField(event, FieldBreakpointType))
            JsonSet(data.get(), "type", JsonInteger(event.breakpointType));
        SetText(data.get(), "name", event.name);
        SetText(data.get(), "module", event.module);
        break;
    case EventKind::Exception:
        if(HasField(event, FieldExceptionCode))
            JsonSet(data.get(), "code", JsonInteger(event.exceptionCode));
        if(HasField(event, FieldAddress))
            JsonSet(data.get(), "address", JsonInteger(event.address));
        if(HasField(event, FieldFirstChance))
            JsonSet(data.get(), "first_chance", JsonBoolean(event.firstChance));
        break;
    case EventKind::DebugAttaching:
    case EventKind::DebugDetaching:
        if(HasField(event, FieldProcessId))
            JsonSet(data.get(), "process_id", JsonInteger(event.processId));
        break;
    case EventKind::DebugStopping:
    case EventKind::DebugStopped:
    case EventKind::SystemBreakpoint:
    case EventKind::DebugPaused:
    case EventKind::DebugResumed:
    case EventKind::DebugStepped:
        break;
    }
    return data;
}

JsonPtr InvalidFieldDetails(const char* field, std::uint64_t value)
{
    auto details = JsonObject();
    JsonSet(details.get(), "field", JsonString(field));
    JsonSet(details.get(), "value", JsonInteger(value));
    return details;
}

class EventJournal
{
public:
    void Start()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.fill(EventRecord());
        first_ = 0;
        size_ = 0;
        nextSequence_ = 1;
        droppedTotal_ = 0;
        capturing_ = true;
    }

    void Stop()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        capturing_ = false;
    }

    void Publish(EventRecord event)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if(!capturing_)
            return;

        event.sequence = nextSequence_++;
        event.timestampUnixMs = TimestampUnixMs();
        if(size_ < DebugEventCapacity)
        {
            const auto index = (first_ + size_) % DebugEventCapacity;
            events_[index] = std::move(event);
            ++size_;
            return;
        }

        events_[first_] = std::move(event);
        first_ = (first_ + 1) % DebugEventCapacity;
        ++droppedTotal_;
    }

    Outcome Read(std::uint64_t cursor, std::size_t limit) const
    {
        std::vector<EventRecord> selected;
        selected.reserve(limit);

        std::uint64_t oldest = 0;
        std::uint64_t latest = 0;
        std::uint64_t dropped = 0;
        std::uint64_t droppedTotal = 0;
        std::uint64_t nextCursor = cursor;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            latest = nextSequence_ - 1;
            if(cursor > latest)
            {
                auto details = JsonObject();
                JsonSet(details.get(), "cursor", JsonInteger(cursor));
                JsonSet(details.get(), "latest_sequence", JsonInteger(latest));
                return Outcome::Failure(
                    "invalid_cursor",
                    "event cursor is ahead of the current stream",
                    false,
                    std::move(details));
            }

            oldest = size_ == 0 ? 0 : events_[first_].sequence;
            dropped = oldest != 0 && cursor + 1 < oldest ? oldest - cursor - 1 : 0;
            droppedTotal = droppedTotal_;
            if(dropped != 0)
                nextCursor = oldest - 1;

            for(std::size_t offset = 0; offset < size_ && selected.size() < limit; ++offset)
            {
                const auto& event = events_[(first_ + offset) % DebugEventCapacity];
                if(event.sequence <= cursor)
                    continue;
                selected.push_back(event);
                nextCursor = event.sequence;
            }
        }

        auto values = JsonArray();
        for(const auto& event : selected)
        {
            auto value = JsonObject();
            JsonSet(value.get(), "sequence", JsonInteger(event.sequence));
            JsonSet(value.get(), "timestamp_unix_ms", JsonInteger(event.timestampUnixMs));
            JsonSet(value.get(), "source", JsonString("x64dbg.plugin_callback"));
            JsonSet(value.get(), "kind", JsonString(EventKindName(event.kind)));
            JsonSet(value.get(), "data", BuildEventData(event));
            JsonAppend(values.get(), std::move(value));
        }

        auto result = JsonObject();
        JsonSet(result.get(), "events", std::move(values));
        JsonSet(result.get(), "count", JsonInteger(selected.size()));
        JsonSet(result.get(), "cursor", JsonInteger(cursor));
        JsonSet(result.get(), "next_cursor", JsonInteger(nextCursor));
        JsonSet(result.get(), "oldest_sequence", JsonInteger(oldest));
        JsonSet(result.get(), "latest_sequence", JsonInteger(latest));
        JsonSet(result.get(), "dropped", JsonInteger(dropped));
        JsonSet(result.get(), "dropped_total", JsonInteger(droppedTotal));
        JsonSet(result.get(), "has_more", JsonBoolean(nextCursor < latest));
        JsonSet(result.get(), "capacity", JsonInteger(DebugEventCapacity));
        return Outcome::Success(std::move(result));
    }

private:
    mutable std::mutex mutex_;
    std::array<EventRecord, DebugEventCapacity> events_ = {};
    std::size_t first_ = 0;
    std::size_t size_ = 0;
    std::uint64_t nextSequence_ = 1;
    std::uint64_t droppedTotal_ = 0;
    bool capturing_ = false;
};

EventJournal& Journal()
{
    static EventJournal journal;
    return journal;
}

void PublishDebugEvent(CBTYPE type, void* callbackInfo) noexcept
{
    try
    {
        EventRecord event;
        switch(type)
        {
        case CB_INITDEBUG:
        {
            event.kind = EventKind::DebugInit;
            const auto info = static_cast<PLUG_CB_INITDEBUG*>(callbackInfo);
            CopyText(event.path, info == nullptr ? nullptr : info->szFileName);
            break;
        }
        case CB_STOPPINGDEBUG:
            event.kind = EventKind::DebugStopping;
            break;
        case CB_STOPDEBUG:
            event.kind = EventKind::DebugStopped;
            break;
        case CB_CREATEPROCESS:
        {
            event.kind = EventKind::ProcessCreated;
            const auto info = static_cast<PLUG_CB_CREATEPROCESS*>(callbackInfo);
            if(info != nullptr)
            {
                if(info->fdProcessInfo != nullptr)
                {
                    event.fields |= FieldProcessId | FieldThreadId;
                    event.processId = info->fdProcessInfo->dwProcessId;
                    event.threadId = info->fdProcessInfo->dwThreadId;
                }
                if(info->CreateProcessInfo != nullptr)
                {
                    event.fields |= FieldImageBase | FieldStartAddress;
                    event.imageBase = PointerValue(info->CreateProcessInfo->lpBaseOfImage);
                    event.startAddress = PointerValue(info->CreateProcessInfo->lpStartAddress);
                }
                CopyText(event.path, info->DebugFileName);
            }
            break;
        }
        case CB_EXITPROCESS:
        {
            event.kind = EventKind::ProcessExited;
            const auto info = static_cast<PLUG_CB_EXITPROCESS*>(callbackInfo);
            if(info != nullptr && info->ExitProcess != nullptr)
            {
                event.fields |= FieldExitCode;
                event.exitCode = info->ExitProcess->dwExitCode;
            }
            break;
        }
        case CB_CREATETHREAD:
        {
            event.kind = EventKind::ThreadCreated;
            const auto info = static_cast<PLUG_CB_CREATETHREAD*>(callbackInfo);
            if(info != nullptr)
            {
                event.fields |= FieldThreadId;
                event.threadId = info->dwThreadId;
                if(info->CreateThread != nullptr)
                {
                    event.fields |= FieldStartAddress | FieldThreadLocalBase;
                    event.startAddress = PointerValue(info->CreateThread->lpStartAddress);
                    event.threadLocalBase = PointerValue(info->CreateThread->lpThreadLocalBase);
                }
            }
            break;
        }
        case CB_EXITTHREAD:
        {
            event.kind = EventKind::ThreadExited;
            const auto info = static_cast<PLUG_CB_EXITTHREAD*>(callbackInfo);
            if(info != nullptr)
            {
                event.fields |= FieldThreadId;
                event.threadId = info->dwThreadId;
                if(info->ExitThread != nullptr)
                {
                    event.fields |= FieldExitCode;
                    event.exitCode = info->ExitThread->dwExitCode;
                }
            }
            break;
        }
        case CB_LOADDLL:
        {
            event.kind = EventKind::ModuleLoaded;
            const auto info = static_cast<PLUG_CB_LOADDLL*>(callbackInfo);
            if(info != nullptr)
            {
                if(info->modInfo != nullptr)
                {
                    event.fields |= FieldBase | FieldSize;
                    event.base = info->modInfo->BaseOfImage;
                    event.size = info->modInfo->ImageSize;
                }
                else if(info->LoadDll != nullptr)
                {
                    event.fields |= FieldBase;
                    event.base = PointerValue(info->LoadDll->lpBaseOfDll);
                }
                CopyText(event.name, info->modname);
            }
            break;
        }
        case CB_UNLOADDLL:
        {
            event.kind = EventKind::ModuleUnloaded;
            const auto info = static_cast<PLUG_CB_UNLOADDLL*>(callbackInfo);
            if(info != nullptr && info->UnloadDll != nullptr)
            {
                event.fields |= FieldBase;
                event.base = PointerValue(info->UnloadDll->lpBaseOfDll);
            }
            break;
        }
        case CB_BREAKPOINT:
        {
            event.kind = EventKind::BreakpointHit;
            const auto info = static_cast<PLUG_CB_BREAKPOINT*>(callbackInfo);
            if(info != nullptr && info->breakpoint != nullptr)
            {
                event.fields |= FieldAddress | FieldBreakpointType;
                event.address = info->breakpoint->addr;
                event.breakpointType = static_cast<std::uint64_t>(info->breakpoint->type);
                CopyText(event.name, info->breakpoint->name);
                CopyText(event.module, info->breakpoint->mod);
            }
            break;
        }
        case CB_EXCEPTION:
        {
            event.kind = EventKind::Exception;
            const auto info = static_cast<PLUG_CB_EXCEPTION*>(callbackInfo);
            if(info != nullptr && info->Exception != nullptr)
            {
                event.fields |= FieldExceptionCode | FieldAddress | FieldFirstChance;
                event.exceptionCode = info->Exception->ExceptionRecord.ExceptionCode;
                event.address = PointerValue(info->Exception->ExceptionRecord.ExceptionAddress);
                event.firstChance = info->Exception->dwFirstChance != 0;
            }
            break;
        }
        case CB_SYSTEMBREAKPOINT:
            event.kind = EventKind::SystemBreakpoint;
            break;
        case CB_PAUSEDEBUG:
            event.kind = EventKind::DebugPaused;
            break;
        case CB_RESUMEDEBUG:
            event.kind = EventKind::DebugResumed;
            break;
        case CB_STEPPED:
            event.kind = EventKind::DebugStepped;
            break;
        case CB_ATTACH:
        {
            event.kind = EventKind::DebugAttaching;
            const auto info = static_cast<PLUG_CB_ATTACH*>(callbackInfo);
            if(info != nullptr)
            {
                event.fields |= FieldProcessId;
                event.processId = info->dwProcessId;
            }
            break;
        }
        case CB_DETACH:
        {
            event.kind = EventKind::DebugDetaching;
            const auto info = static_cast<PLUG_CB_DETACH*>(callbackInfo);
            if(info != nullptr && info->fdProcessInfo != nullptr)
            {
                event.fields |= FieldProcessId;
                event.processId = info->fdProcessInfo->dwProcessId;
            }
            break;
        }
        default:
            return;
        }
        Journal().Publish(std::move(event));
    }
    catch(...)
    {
        try
        {
            EventRecord gap;
            gap.kind = EventKind::UnrecoveredGap;
            Journal().Publish(std::move(gap));
        }
        catch(...)
        {
        }
    }
}

constexpr std::array<CBTYPE, 17> CapturedCallbacks = {
    CB_INITDEBUG,
    CB_STOPDEBUG,
    CB_CREATEPROCESS,
    CB_EXITPROCESS,
    CB_CREATETHREAD,
    CB_EXITTHREAD,
    CB_SYSTEMBREAKPOINT,
    CB_LOADDLL,
    CB_UNLOADDLL,
    CB_EXCEPTION,
    CB_BREAKPOINT,
    CB_PAUSEDEBUG,
    CB_RESUMEDEBUG,
    CB_STEPPED,
    CB_ATTACH,
    CB_DETACH,
    CB_STOPPINGDEBUG,
};

bool ReadOptionalUnsigned(
    const json_t* params,
    const char* key,
    std::uint64_t defaultValue,
    std::uint64_t maximum,
    std::uint64_t& value,
    Outcome& error)
{
    const auto item = json_object_get(params, key);
    if(item == nullptr)
    {
        value = defaultValue;
        return true;
    }
    if(!json_is_integer(item) || json_integer_value(item) < 0)
    {
        error = Outcome::Failure(
            "invalid_params",
            std::string("parameter must be a non-negative integer: ") + key);
        return false;
    }
    const auto raw = static_cast<std::uint64_t>(json_integer_value(item));
    if(raw > maximum)
    {
        error = Outcome::Failure(
            "invalid_params",
            std::string("parameter is out of range: ") + key,
            false,
            InvalidFieldDetails(key, raw));
        return false;
    }
    value = raw;
    return true;
}

} // namespace

bool StartDebugEventCapture()
{
#ifdef _WIN64
    const auto debugger = GetModuleHandleW(L"x64dbg.dll");
#else
    const auto debugger = GetModuleHandleW(L"x32dbg.dll");
#endif
    if(debugger == nullptr)
        return false;

    registerCallback = reinterpret_cast<RegisterCallback>(
        GetProcAddress(debugger, "_plugin_registercallback"));
    unregisterCallback = reinterpret_cast<UnregisterCallback>(
        GetProcAddress(debugger, "_plugin_unregistercallback"));
    if(registerCallback == nullptr || unregisterCallback == nullptr)
    {
        registerCallback = nullptr;
        unregisterCallback = nullptr;
        return false;
    }

    Journal().Start();
    for(const auto type : CapturedCallbacks)
        registerCallback(EventCallbackHandle, type, PublishDebugEvent);
    return true;
}

void StopDebugEventCapture()
{
    if(unregisterCallback != nullptr)
    {
        for(const auto type : CapturedCallbacks)
            unregisterCallback(EventCallbackHandle, type);
    }
    Journal().Stop();
    registerCallback = nullptr;
    unregisterCallback = nullptr;
}

Outcome ReadDebugEvents(const json_t* params)
{
    Outcome error;
    std::uint64_t cursor = 0;
    std::uint64_t limit = 0;
    if(!ReadOptionalUnsigned(
           params,
           "cursor",
           0,
           static_cast<std::uint64_t>(std::numeric_limits<json_int_t>::max()),
           cursor,
           error))
        return error;
    if(!ReadOptionalUnsigned(
           params,
           "limit",
           DefaultDebugEventBatch,
           MaxDebugEventBatch,
           limit,
           error))
        return error;
    if(limit == 0)
        return Outcome::Failure(
            "invalid_params",
            "limit must be positive",
            false,
            InvalidFieldDetails("limit", limit));
    return Journal().Read(cursor, static_cast<std::size_t>(limit));
}

} // namespace headless_re_rpc
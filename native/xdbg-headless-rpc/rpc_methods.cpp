#include "rpc_internal.h"

#include "bridgemain.h"
#include "_dbgfunctions.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <vector>

#ifndef MOVEFILE_WRITE_THROUGH
#define MOVEFILE_WRITE_THROUGH 0x00000008
#endif

namespace headless_re_rpc
{
namespace
{
constexpr const char* DebuggerMethods[] = {
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

JsonPtr ErrorDetails(const char* field)
{
    auto details = JsonObject();
    JsonSet(details.get(), "field", JsonString(field));
    return details;
}

Outcome InvalidField(const char* field, const std::string& message)
{
    return Outcome::Failure("invalid_params", message, false, ErrorDetails(field));
}

const json_t* Param(const json_t* params, const char* key)
{
    return params == nullptr ? nullptr : json_object_get(params, key);
}

bool ReadString(
    const json_t* params,
    const char* key,
    std::string& value,
    Outcome& error,
    bool required = true,
    std::size_t maxLength = 32768)
{
    auto item = Param(params, key);
    if(item == nullptr)
    {
        if(!required)
            return true;
        error = InvalidField(key, std::string("missing string parameter: ") + key);
        return false;
    }
    if(!json_is_string(item))
    {
        error = InvalidField(key, std::string("parameter must be a string: ") + key);
        return false;
    }
    auto text = json_string_value(item);
    auto length = json_string_length(item);
    if(text == nullptr || length == 0 || length > maxLength)
    {
        error = InvalidField(key, std::string("parameter has invalid length: ") + key);
        return false;
    }
    value.assign(text, length);
    return true;
}

bool ReadUnsigned(
    const json_t* params,
    const char* key,
    std::uint64_t& value,
    Outcome& error,
    std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max())
{
    auto item = Param(params, key);
    if(item == nullptr || !json_is_integer(item))
    {
        error = InvalidField(key, std::string("parameter must be an integer: ") + key);
        return false;
    }
    auto raw = json_integer_value(item);
    if(raw < 0 || static_cast<std::uint64_t>(raw) > maximum)
    {
        error = InvalidField(key, std::string("parameter is out of range: ") + key);
        return false;
    }
    value = static_cast<std::uint64_t>(raw);
    return true;
}

bool HasUnsafeCommandText(const std::string& value)
{
    return value.find_first_of("\"\r\n\0") != std::string::npos;
}

std::string HexAddress(duint value)
{
    char buffer[2 + sizeof(duint) * 2 + 1] = {};
    sprintf_s(buffer, "0x%llX", static_cast<unsigned long long>(value));
    return buffer;
}

JsonPtr AddressValue(duint value)
{
    return JsonInteger(static_cast<std::uint64_t>(value));
}

Outcome CommandFailure(const char* method, const char* command)
{
    auto details = JsonObject();
    JsonSet(details.get(), "method", JsonString(method));
    JsonSet(details.get(), "command", JsonString(command));
    return Outcome::Failure(
        "debugger_command_failed",
        std::string("x64dbg rejected command: ") + command,
        false,
        std::move(details));
}

Outcome RequireDebugging()
{
    if(DbgIsDebugging())
        return Outcome::Success(JsonObject());
    return Outcome::Failure("not_debugging", "no debuggee is active");
}

Outcome RequirePaused()
{
    if(!DbgIsDebugging())
        return Outcome::Failure("not_debugging", "no debuggee is active");
    if(DbgIsRunning())
        return Outcome::Failure("debuggee_running", "operation requires a paused debuggee", true);
    return Outcome::Success(JsonObject());
}

Outcome RunControlCommand(const char* method, const char* command, bool requirePaused)
{
    auto ready = requirePaused ? RequirePaused() : RequireDebugging();
    if(!ready.ok)
        return ready;
    if(!DbgCmdExecDirect(command))
        return CommandFailure(method, command);
    return Outcome::Success(BuildDebuggerState());
}

Outcome PauseDebuggee()
{
    auto ready = RequireDebugging();
    if(!ready.ok)
        return ready;
    if(!DbgIsRunning())
        return Outcome::Success(BuildDebuggerState());
    if(!DbgCmdExecDirect("pause"))
        return CommandFailure("debug.pause", "pause");
    return Outcome::Success(BuildDebuggerState());
}

Outcome Launch(const json_t* params)
{
    if(DbgIsDebugging())
        return Outcome::Failure("already_debugging", "stop the active debuggee before launch");

    Outcome error;
    std::string path;
    if(!ReadString(params, "path", path, error, true, 32767))
        return error;
    if(HasUnsafeCommandText(path))
        return InvalidField("path", "path contains characters unsupported by the command boundary");

    std::string arguments;
    auto argumentsItem = Param(params, "arguments");
    if(argumentsItem != nullptr)
    {
        if(!json_is_string(argumentsItem))
            return InvalidField("arguments", "arguments must be a string");
        arguments.assign(json_string_value(argumentsItem), json_string_length(argumentsItem));
        if(arguments.size() > 32767 || HasUnsafeCommandText(arguments))
            return InvalidField(
                "arguments", "arguments contain unsupported characters or exceed the limit");
    }

    std::string workingDirectory;
    auto workingItem = Param(params, "working_directory");
    if(workingItem != nullptr)
    {
        if(!json_is_string(workingItem))
            return InvalidField("working_directory", "working_directory must be a string");
        workingDirectory.assign(json_string_value(workingItem), json_string_length(workingItem));
        if(workingDirectory.size() > 32767 || HasUnsafeCommandText(workingDirectory))
            return InvalidField(
                "working_directory",
                "working_directory contains unsupported characters or exceeds the limit");
    }

    std::string command = "InitDebug \"" + path + "\"";
    if(!arguments.empty() || !workingDirectory.empty())
    {
        command += ", \"" + arguments + "\"";
        if(!workingDirectory.empty())
            command += ", \"" + workingDirectory + "\"";
    }
    if(!DbgCmdExecDirect(command.c_str()))
        return CommandFailure("debug.launch", "InitDebug");
    return Outcome::Success(BuildDebuggerState());
}

Outcome Attach(const json_t* params)
{
    if(DbgIsDebugging())
        return Outcome::Failure("already_debugging", "stop the active debuggee before attach");
    Outcome error;
    std::uint64_t pid = 0;
    if(!ReadUnsigned(params, "pid", pid, error, std::numeric_limits<DWORD>::max()))
        return error;
    if(pid == 0)
        return InvalidField("pid", "pid must be positive");
    auto command = std::string("AttachDebugger ") + std::to_string(pid);
    if(!DbgCmdExecDirect(command.c_str()))
        return CommandFailure("debug.attach", "AttachDebugger");
    return Outcome::Success(BuildDebuggerState());
}

void AddRegister(json_t* registers, const char* name, duint value)
{
    JsonSet(registers, name, AddressValue(value));
}

Outcome ReadRegisters()
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    REGDUMP dump = {};
    if(!DbgGetRegDumpEx(reinterpret_cast<REGDUMP_AVX512*>(&dump), sizeof(dump)))
        return Outcome::Failure("register_read_failed", "x64dbg could not read registers");

    const auto& context = dump.regcontext;
    auto registers = JsonObject();
#ifdef _WIN64
    AddRegister(registers.get(), "rax", context.cax);
    AddRegister(registers.get(), "rcx", context.ccx);
    AddRegister(registers.get(), "rdx", context.cdx);
    AddRegister(registers.get(), "rbx", context.cbx);
    AddRegister(registers.get(), "rsp", context.csp);
    AddRegister(registers.get(), "rbp", context.cbp);
    AddRegister(registers.get(), "rsi", context.csi);
    AddRegister(registers.get(), "rdi", context.cdi);
    AddRegister(registers.get(), "r8", context.r8);
    AddRegister(registers.get(), "r9", context.r9);
    AddRegister(registers.get(), "r10", context.r10);
    AddRegister(registers.get(), "r11", context.r11);
    AddRegister(registers.get(), "r12", context.r12);
    AddRegister(registers.get(), "r13", context.r13);
    AddRegister(registers.get(), "r14", context.r14);
    AddRegister(registers.get(), "r15", context.r15);
    AddRegister(registers.get(), "rip", context.cip);
#else
    AddRegister(registers.get(), "eax", context.cax);
    AddRegister(registers.get(), "ecx", context.ccx);
    AddRegister(registers.get(), "edx", context.cdx);
    AddRegister(registers.get(), "ebx", context.cbx);
    AddRegister(registers.get(), "esp", context.csp);
    AddRegister(registers.get(), "ebp", context.cbp);
    AddRegister(registers.get(), "esi", context.csi);
    AddRegister(registers.get(), "edi", context.cdi);
    AddRegister(registers.get(), "eip", context.cip);
#endif
    AddRegister(registers.get(), "eflags", context.eflags);
    AddRegister(registers.get(), "dr0", context.dr0);
    AddRegister(registers.get(), "dr1", context.dr1);
    AddRegister(registers.get(), "dr2", context.dr2);
    AddRegister(registers.get(), "dr3", context.dr3);
    AddRegister(registers.get(), "dr6", context.dr6);
    AddRegister(registers.get(), "dr7", context.dr7);

    auto result = JsonObject();
    JsonSet(result.get(), "registers", std::move(registers));
    return Outcome::Success(std::move(result));
}

bool IsWritableRegister(const std::string& name)
{
#ifdef _WIN64
    static const std::set<std::string> names = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9",
        "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags", "dr0",
        "dr1", "dr2", "dr3", "dr6", "dr7",
    };
#else
    static const std::set<std::string> names = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip",
        "eflags", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
    };
#endif
    return names.find(name) != names.end();
}

Outcome WriteRegister(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::string name;
    if(!ReadString(params, "name", name, error, true, 16))
        return error;
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char ch)
    {
        return static_cast<char>(std::tolower(ch));
    });
    if(!IsWritableRegister(name))
        return InvalidField("name", "register is not writable or is unavailable on this architecture");

    std::uint64_t value = 0;
    if(!ReadUnsigned(params, "value", value, error, std::numeric_limits<duint>::max()))
        return error;
    if(!DbgValSetScalar(name.c_str(), static_cast<duint>(value)))
        return Outcome::Failure("register_write_failed", "x64dbg rejected the register value");

    auto result = JsonObject();
    JsonSet(result.get(), "name", JsonString(name));
    JsonSet(result.get(), "value", JsonInteger(value));
    return Outcome::Success(std::move(result));
}

char HexDigit(unsigned value)
{
    return static_cast<char>(value < 10 ? '0' + value : 'a' + (value - 10));
}

std::string EncodeHex(const std::vector<unsigned char>& bytes)
{
    std::string encoded(bytes.size() * 2, '0');
    for(std::size_t index = 0; index < bytes.size(); ++index)
    {
        encoded[index * 2] = HexDigit(bytes[index] >> 4);
        encoded[index * 2 + 1] = HexDigit(bytes[index] & 0x0f);
    }
    return encoded;
}

int DecodeNibble(char value)
{
    if(value >= '0' && value <= '9')
        return value - '0';
    if(value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if(value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

bool DecodeHex(const std::string& encoded, std::vector<unsigned char>& bytes)
{
    if(encoded.empty() || encoded.size() % 2 != 0)
        return false;
    bytes.resize(encoded.size() / 2);
    for(std::size_t index = 0; index < bytes.size(); ++index)
    {
        auto high = DecodeNibble(encoded[index * 2]);
        auto low = DecodeNibble(encoded[index * 2 + 1]);
        if(high < 0 || low < 0)
            return false;
        bytes[index] = static_cast<unsigned char>((high << 4) | low);
    }
    return true;
}

Outcome ReadMemory(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;
    Outcome error;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;
    if(!ReadUnsigned(params, "size", size, error, MaxMemoryBytes))
        return error;
    if(size == 0)
        return InvalidField("size", "size must be positive");

    std::vector<unsigned char> bytes(static_cast<std::size_t>(size));
    if(!DbgMemRead(static_cast<duint>(address), bytes.data(), static_cast<duint>(size)))
        return Outcome::Failure("memory_read_failed", "x64dbg could not read the requested range");

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "size", JsonInteger(size));
    JsonSet(result.get(), "encoding", JsonString("hex"));
    JsonSet(result.get(), "data", JsonString(EncodeHex(bytes)));
    return Outcome::Success(std::move(result));
}

Outcome WriteMemory(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;
    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;
    std::string encoded;
    if(!ReadString(params, "data", encoded, error, true, MaxMemoryBytes * 2))
        return error;
    std::vector<unsigned char> bytes;
    if(!DecodeHex(encoded, bytes) || bytes.size() > MaxMemoryBytes)
        return InvalidField("data", "data must be non-empty hexadecimal bytes within the limit");
    if(!DbgMemWrite(
           static_cast<duint>(address), bytes.data(), static_cast<duint>(bytes.size())))
        return Outcome::Failure("memory_write_failed", "x64dbg could not write the requested range");

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "size", JsonInteger(bytes.size()));
    return Outcome::Success(std::move(result));
}

const char* MemoryStateName(DWORD state)
{
    switch(state)
    {
    case MEM_COMMIT:
        return "commit";
    case MEM_RESERVE:
        return "reserve";
    case MEM_FREE:
        return "free";
    default:
        return "unknown";
    }
}

const char* MemoryTypeName(DWORD type)
{
    switch(type)
    {
    case MEM_IMAGE:
        return "image";
    case MEM_MAPPED:
        return "mapped";
    case MEM_PRIVATE:
        return "private";
    default:
        return "unknown";
    }
}

std::string ProtectFlagsName(DWORD protect)
{
    if(protect == 0)
        return "none";
    std::string name;
    auto append = [&](const char* token)
    {
        if(!name.empty())
            name.push_back('|');
        name += token;
    };
    const auto base = protect & 0xFFu;
    switch(base)
    {
    case PAGE_NOACCESS:
        append("noaccess");
        break;
    case PAGE_READONLY:
        append("readonly");
        break;
    case PAGE_READWRITE:
        append("readwrite");
        break;
    case PAGE_WRITECOPY:
        append("writecopy");
        break;
    case PAGE_EXECUTE:
        append("execute");
        break;
    case PAGE_EXECUTE_READ:
        append("execute_read");
        break;
    case PAGE_EXECUTE_READWRITE:
        append("execute_readwrite");
        break;
    case PAGE_EXECUTE_WRITECOPY:
        append("execute_writecopy");
        break;
    default:
        append("other");
        break;
    }
    if(protect & PAGE_GUARD)
        append("guard");
    if(protect & PAGE_NOCACHE)
        append("nocache");
    if(protect & PAGE_WRITECOMBINE)
        append("writecombine");
    return name;
}

JsonPtr MemoryRegionObject(const MEMPAGE& page)
{
    auto value = JsonObject();
    const auto base = reinterpret_cast<duint>(page.mbi.BaseAddress);
    const auto allocationBase = reinterpret_cast<duint>(page.mbi.AllocationBase);
    JsonSet(value.get(), "base", AddressValue(base));
    JsonSet(value.get(), "allocation_base", AddressValue(allocationBase));
    JsonSet(value.get(), "size", AddressValue(static_cast<duint>(page.mbi.RegionSize)));
    JsonSet(value.get(), "protect", JsonInteger(page.mbi.Protect));
    JsonSet(value.get(), "protect_name", JsonString(ProtectFlagsName(page.mbi.Protect)));
    JsonSet(value.get(), "allocation_protect", JsonInteger(page.mbi.AllocationProtect));
    JsonSet(
        value.get(),
        "allocation_protect_name",
        JsonString(ProtectFlagsName(page.mbi.AllocationProtect)));
    JsonSet(value.get(), "state", JsonString(MemoryStateName(page.mbi.State)));
    JsonSet(value.get(), "type", JsonString(MemoryTypeName(page.mbi.Type)));
    JsonSet(value.get(), "info", JsonString(page.info));
    return value;
}

Outcome ListMemoryRegions(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t offset = 0;
    std::uint64_t limit = MaxRegionCount;
    auto offsetItem = Param(params, "offset");
    if(offsetItem != nullptr)
    {
        if(!ReadUnsigned(params, "offset", offset, error, MaxRegionCount))
            return error;
    }
    auto limitItem = Param(params, "limit");
    if(limitItem != nullptr)
    {
        if(!ReadUnsigned(params, "limit", limit, error, MaxRegionCount))
            return error;
        if(limit == 0)
            return InvalidField("limit", "limit must be positive");
    }

    const auto functions = DbgFunctions();
    functions->MemUpdateMap();

    MEMMAP memoryMap = {};
    if(!DbgMemMap(&memoryMap))
        return Outcome::Failure("memory_map_failed", "x64dbg could not read the memory map");

    const auto total = static_cast<std::uint64_t>(memoryMap.count < 0 ? 0 : memoryMap.count);
    auto values = JsonArray();
    std::uint64_t emitted = 0;
    for(std::uint64_t index = offset; index < total && emitted < limit; ++index)
    {
        JsonAppend(values.get(), MemoryRegionObject(memoryMap.page[static_cast<int>(index)]));
        ++emitted;
    }
    if(memoryMap.page != nullptr)
        BridgeFree(memoryMap.page);

    auto result = JsonObject();
    JsonSet(result.get(), "regions", std::move(values));
    JsonSet(result.get(), "count", JsonInteger(emitted));
    JsonSet(result.get(), "total", JsonInteger(total));
    JsonSet(result.get(), "offset", JsonInteger(offset));
    JsonSet(result.get(), "limit", JsonInteger(limit));
    JsonSet(result.get(), "has_more", JsonBoolean(offset + emitted < total));
    return Outcome::Success(std::move(result));
}

Outcome QueryMemoryProtect(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;

    const auto functions = DbgFunctions();
    functions->MemUpdateMap();

    MEMMAP memoryMap = {};
    if(!DbgMemMap(&memoryMap))
        return Outcome::Failure("memory_map_failed", "x64dbg could not read the memory map");

    const MEMPAGE* matched = nullptr;
    for(int index = 0; index < memoryMap.count; ++index)
    {
        const auto& page = memoryMap.page[index];
        const auto base = reinterpret_cast<duint>(page.mbi.BaseAddress);
        const auto end = base + static_cast<duint>(page.mbi.RegionSize);
        if(address >= base && address < end)
        {
            matched = &page;
            break;
        }
    }

    Outcome outcome;
    if(matched == nullptr)
    {
        outcome = Outcome::Failure(
            "region_not_found",
            "no memory region contains the requested address",
            false,
            ErrorDetails("address"));
    }
    else
    {
        auto result = MemoryRegionObject(*matched);
        JsonSet(result.get(), "address", JsonInteger(address));
        outcome = Outcome::Success(std::move(result));
    }
    if(memoryMap.page != nullptr)
        BridgeFree(memoryMap.page);
    return outcome;
}

bool IsAbsoluteWindowsPath(const std::string& path)
{
    if(path.size() >= 3 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':'
       && (path[2] == '\\' || path[2] == '/'))
        return true;
    return path.size() >= 2 && path[0] == '\\' && path[1] == '\\';
}

bool PathContainsDotDot(const std::string& path)
{
    std::size_t index = 0;
    while(index < path.size())
    {
        while(index < path.size() && (path[index] == '\\' || path[index] == '/'))
            ++index;
        if(index >= path.size())
            break;
        const auto start = index;
        while(index < path.size() && path[index] != '\\' && path[index] != '/')
            ++index;
        if(index - start == 2 && path[start] == '.' && path[start + 1] == '.')
            return true;
    }
    return false;
}

std::wstring Utf8ToWide(const std::string& utf8)
{
    if(utf8.empty())
        return {};
    const auto needed = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if(needed <= 0)
        return {};
    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    if(MultiByteToWideChar(
           CP_UTF8,
           MB_ERR_INVALID_CHARS,
           utf8.data(),
           static_cast<int>(utf8.size()),
           &wide[0],
           needed)
       <= 0)
        return {};
    return wide;
}

Outcome DumpModule(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t base = 0;
    if(!ReadUnsigned(params, "base", base, error, std::numeric_limits<duint>::max()))
        return error;
    if(base == 0)
        return InvalidField("base", "base must be a non-zero module base");

    std::string outputPath;
    if(!ReadString(params, "output_path", outputPath, error, true, 32767))
        return error;
    if(!IsAbsoluteWindowsPath(outputPath) || PathContainsDotDot(outputPath)
       || outputPath.find('\0') != std::string::npos)
    {
        return InvalidField(
            "output_path",
            "output_path must be an absolute Windows path without '..' segments");
    }

    const auto functions = DbgFunctions();
    auto dumpSize = static_cast<std::uint64_t>(functions->ModSizeFromAddr(static_cast<duint>(base)));
    auto sizeItem = Param(params, "size");
    if(sizeItem != nullptr)
    {
        std::uint64_t requested = 0;
        if(!ReadUnsigned(params, "size", requested, error, MaxDumpBytes))
            return error;
        if(requested == 0)
            return InvalidField("size", "size must be positive");
        dumpSize = requested;
    }
    if(dumpSize == 0)
        return Outcome::Failure("module_not_found", "module size is zero or base is not a module");
    if(dumpSize > MaxDumpBytes)
    {
        auto details = JsonObject();
        JsonSet(details.get(), "size", JsonInteger(dumpSize));
        JsonSet(details.get(), "max_dump_bytes", JsonInteger(MaxDumpBytes));
        return Outcome::Failure(
            "dump_too_large",
            "requested dump exceeds the configured maximum",
            false,
            std::move(details));
    }

    char name[MAX_MODULE_SIZE] = {};
    char path[MAX_PATH] = {};
    const auto hasName = functions->ModNameFromAddr(static_cast<duint>(base), name, true);
    const auto hasPath = functions->ModPathFromAddr(static_cast<duint>(base), path, _countof(path));
    if(!hasName && !hasPath)
        return Outcome::Failure("module_not_found", "no module is loaded at the requested base");

    const auto widePath = Utf8ToWide(outputPath);
    if(widePath.empty())
        return InvalidField("output_path", "output_path must be valid UTF-8");
    const auto partialPath = outputPath + ".partial";
    const auto widePartial = Utf8ToWide(partialPath);
    if(widePartial.empty())
        return InvalidField("output_path", "output_path must be valid UTF-8");

    HANDLE file = CreateFileW(
        widePartial.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if(file == INVALID_HANDLE_VALUE)
    {
        auto details = JsonObject();
        JsonSet(details.get(), "win32_error", JsonInteger(GetLastError()));
        JsonSet(details.get(), "output_path", JsonString(partialPath));
        return Outcome::Failure(
            "artifact_write_failed",
            "could not create the dump temporary file",
            false,
            std::move(details));
    }

    std::vector<unsigned char> buffer(static_cast<std::size_t>(
        (std::min)(MaxMemoryBytes, static_cast<std::uint64_t>(64U * 1024U))));
    std::uint64_t written = 0;
    while(written < dumpSize)
    {
        const auto chunk = static_cast<duint>((std::min)(
            static_cast<std::uint64_t>(buffer.size()), dumpSize - written));
        if(functions->ModSizeFromAddr(static_cast<duint>(base)) == 0)
        {
            CloseHandle(file);
            DeleteFileW(widePartial.c_str());
            auto details = JsonObject();
            JsonSet(details.get(), "base", JsonInteger(base));
            JsonSet(details.get(), "bytes_written", JsonInteger(written));
            return Outcome::Failure(
                "module_unloaded_during_dump",
                "module was unloaded while dumping",
                true,
                std::move(details));
        }
        if(!DbgMemRead(
               static_cast<duint>(base + written), buffer.data(), chunk))
        {
            CloseHandle(file);
            DeleteFileW(widePartial.c_str());
            auto details = JsonObject();
            JsonSet(details.get(), "address", JsonInteger(base + written));
            JsonSet(details.get(), "size", JsonInteger(chunk));
            if(functions->ModSizeFromAddr(static_cast<duint>(base)) == 0)
            {
                JsonSet(details.get(), "base", JsonInteger(base));
                return Outcome::Failure(
                    "module_unloaded_during_dump",
                    "module was unloaded while dumping",
                    true,
                    std::move(details));
            }
            return Outcome::Failure(
                "memory_read_failed",
                "x64dbg could not read the dump range",
                false,
                std::move(details));
        }
        DWORD bytesWritten = 0;
        if(!WriteFile(file, buffer.data(), static_cast<DWORD>(chunk), &bytesWritten, nullptr)
           || bytesWritten != static_cast<DWORD>(chunk))
        {
            const auto winError = GetLastError();
            CloseHandle(file);
            DeleteFileW(widePartial.c_str());
            auto details = JsonObject();
            JsonSet(details.get(), "win32_error", JsonInteger(winError));
            return Outcome::Failure(
                "artifact_write_failed",
                "could not write dump bytes to the temporary file",
                false,
                std::move(details));
        }
        written += chunk;
    }

    FlushFileBuffers(file);
    CloseHandle(file);

    if(!MoveFileExW(
           widePartial.c_str(),
           widePath.c_str(),
           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        const auto winError = GetLastError();
        DeleteFileW(widePartial.c_str());
        auto details = JsonObject();
        JsonSet(details.get(), "win32_error", JsonInteger(winError));
        JsonSet(details.get(), "output_path", JsonString(outputPath));
        return Outcome::Failure(
            "artifact_rename_failed",
            "could not atomically rename the dump temporary file",
            false,
            std::move(details));
    }

    auto result = JsonObject();
    JsonSet(result.get(), "base", JsonInteger(base));
    JsonSet(result.get(), "size", JsonInteger(dumpSize));
    JsonSet(result.get(), "bytes_written", JsonInteger(written));
    JsonSet(result.get(), "output_path", JsonString(outputPath));
    JsonSet(result.get(), "name", JsonString(hasName ? name : ""));
    JsonSet(result.get(), "path", JsonString(hasPath ? path : ""));
    JsonSet(result.get(), "max_dump_bytes", JsonInteger(MaxDumpBytes));
    return Outcome::Success(std::move(result));
}

Outcome ReadPeHeadersRuntime(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t base = 0;
    if(!ReadUnsigned(params, "base", base, error, std::numeric_limits<duint>::max()))
        return error;
    if(base == 0)
        return InvalidField("base", "base must be a non-zero module base");

    const auto functions = DbgFunctions();
    auto moduleSize = static_cast<std::uint64_t>(functions->ModSizeFromAddr(static_cast<duint>(base)));
    if(moduleSize == 0)
        return Outcome::Failure("module_not_found", "no module is loaded at the requested base");

    // Read a bounded header window (DOS + PE + section table).
    constexpr std::uint64_t kHeaderWindow = 0x1000;
    const auto readSize = static_cast<duint>((std::min)(moduleSize, kHeaderWindow));
    std::vector<unsigned char> image(static_cast<std::size_t>(readSize));
    if(!DbgMemRead(static_cast<duint>(base), image.data(), readSize))
        return Outcome::Failure("memory_read_failed", "x64dbg could not read PE headers");

    if(readSize < 0x40 || image[0] != 'M' || image[1] != 'Z')
        return Outcome::Failure("invalid_pe", "module image does not contain a DOS header");

    std::uint32_t peOffset = 0;
    std::memcpy(&peOffset, image.data() + 0x3C, sizeof(peOffset));
    if(peOffset < 0x40 || peOffset + 24 > readSize)
        return Outcome::Failure("invalid_pe", "PE header offset is outside the header window");
    if(std::memcmp(image.data() + peOffset, "PE\0\0", 4) != 0)
        return Outcome::Failure("invalid_pe", "module image does not contain a PE signature");

    const auto fileHeader = peOffset + 4;
    std::uint16_t machine = 0;
    std::uint16_t sectionCount = 0;
    std::uint16_t optionalSize = 0;
    std::uint16_t characteristics = 0;
    std::memcpy(&machine, image.data() + fileHeader, sizeof(machine));
    std::memcpy(&sectionCount, image.data() + fileHeader + 2, sizeof(sectionCount));
    std::memcpy(&optionalSize, image.data() + fileHeader + 16, sizeof(optionalSize));
    std::memcpy(&characteristics, image.data() + fileHeader + 18, sizeof(characteristics));

    const auto optional = fileHeader + 20;
    if(optional + optionalSize > readSize)
        return Outcome::Failure("invalid_pe", "optional header is truncated");
    std::uint16_t magic = 0;
    std::memcpy(&magic, image.data() + optional, sizeof(magic));
    const bool pe32Plus = magic == 0x20B;
    if(magic != 0x10B && magic != 0x20B)
        return Outcome::Failure("invalid_pe", "unsupported optional header magic");

    std::uint32_t entryPointRva = 0;
    std::uint32_t sectionAlignment = 0;
    std::uint32_t fileAlignment = 0;
    std::uint32_t imageSize = 0;
    std::uint32_t sizeOfHeaders = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t dllCharacteristics = 0;
    std::memcpy(&entryPointRva, image.data() + optional + 16, sizeof(entryPointRva));
    std::memcpy(&sectionAlignment, image.data() + optional + 32, sizeof(sectionAlignment));
    std::memcpy(&fileAlignment, image.data() + optional + 36, sizeof(fileAlignment));
    std::memcpy(&imageSize, image.data() + optional + 56, sizeof(imageSize));
    std::memcpy(&sizeOfHeaders, image.data() + optional + 60, sizeof(sizeOfHeaders));
    std::memcpy(&subsystem, image.data() + optional + 68, sizeof(subsystem));
    std::memcpy(&dllCharacteristics, image.data() + optional + 70, sizeof(dllCharacteristics));

    std::uint64_t imageBase = 0;
    if(pe32Plus)
        std::memcpy(&imageBase, image.data() + optional + 24, sizeof(std::uint64_t));
    else
    {
        std::uint32_t imageBase32 = 0;
        std::memcpy(&imageBase32, image.data() + optional + 28, sizeof(imageBase32));
        imageBase = imageBase32;
    }

    const auto dirCountOff = optional + (pe32Plus ? 108u : 92u);
    const auto dirOff = optional + (pe32Plus ? 112u : 96u);
    std::uint32_t dirCount = 0;
    if(dirCountOff + 4 <= optional + optionalSize)
        std::memcpy(&dirCount, image.data() + dirCountOff, sizeof(dirCount));
    if(dirCount > 16)
        dirCount = 16;

    auto directories = JsonArray();
    for(std::uint32_t index = 0; index < dirCount; ++index)
    {
        const auto entry = dirOff + index * 8;
        if(entry + 8 > readSize)
            break;
        std::uint32_t rva = 0;
        std::uint32_t size = 0;
        std::memcpy(&rva, image.data() + entry, sizeof(rva));
        std::memcpy(&size, image.data() + entry + 4, sizeof(size));
        auto item = JsonObject();
        JsonSet(item.get(), "index", JsonInteger(index));
        JsonSet(item.get(), "rva", JsonInteger(rva));
        JsonSet(item.get(), "size", JsonInteger(size));
        JsonAppend(directories.get(), std::move(item));
    }

    const auto sectionsOffset = optional + optionalSize;
    auto sections = JsonArray();
    for(std::uint16_t index = 0; index < sectionCount; ++index)
    {
        const auto off = sectionsOffset + static_cast<std::uint32_t>(index) * 40u;
        if(off + 40 > readSize)
            return Outcome::Failure("invalid_pe", "section table is truncated");
        char name[9] = {};
        std::memcpy(name, image.data() + off, 8);
        std::uint32_t virtualSize = 0;
        std::uint32_t virtualAddress = 0;
        std::uint32_t rawSize = 0;
        std::uint32_t rawOffset = 0;
        std::uint32_t sectionCharacteristics = 0;
        std::memcpy(&virtualSize, image.data() + off + 8, sizeof(virtualSize));
        std::memcpy(&virtualAddress, image.data() + off + 12, sizeof(virtualAddress));
        std::memcpy(&rawSize, image.data() + off + 16, sizeof(rawSize));
        std::memcpy(&rawOffset, image.data() + off + 20, sizeof(rawOffset));
        std::memcpy(&sectionCharacteristics, image.data() + off + 36, sizeof(sectionCharacteristics));
        auto item = JsonObject();
        JsonSet(item.get(), "index", JsonInteger(index));
        JsonSet(item.get(), "name", JsonString(name));
        JsonSet(item.get(), "virtual_size", JsonInteger(virtualSize));
        JsonSet(item.get(), "virtual_address", JsonInteger(virtualAddress));
        JsonSet(item.get(), "raw_size", JsonInteger(rawSize));
        JsonSet(item.get(), "raw_offset", JsonInteger(rawOffset));
        JsonSet(item.get(), "characteristics", JsonInteger(sectionCharacteristics));
        JsonAppend(sections.get(), std::move(item));
    }

    char moduleName[MAX_MODULE_SIZE] = {};
    char modulePath[MAX_PATH] = {};
    functions->ModNameFromAddr(static_cast<duint>(base), moduleName, true);
    functions->ModPathFromAddr(static_cast<duint>(base), modulePath, _countof(modulePath));

    // Optional header artifact (atomic rename).
    std::string outputPath;
    auto outputItem = Param(params, "output_path");
    if(outputItem != nullptr)
    {
        if(!ReadString(params, "output_path", outputPath, error, true, 32767))
            return error;
        if(!IsAbsoluteWindowsPath(outputPath) || PathContainsDotDot(outputPath)
           || outputPath.find('\0') != std::string::npos)
        {
            return InvalidField(
                "output_path",
                "output_path must be an absolute Windows path without '..' segments");
        }
        const auto headerBytes = static_cast<duint>((std::min)(
            static_cast<std::uint64_t>(sizeOfHeaders ? sizeOfHeaders : readSize),
            static_cast<std::uint64_t>(readSize)));
        const auto widePath = Utf8ToWide(outputPath);
        const auto partialPath = outputPath + ".partial";
        const auto widePartial = Utf8ToWide(partialPath);
        if(widePath.empty() || widePartial.empty())
            return InvalidField("output_path", "output_path must be valid UTF-8");
        HANDLE file = CreateFileW(
            widePartial.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if(file == INVALID_HANDLE_VALUE)
            return Outcome::Failure("artifact_write_failed", "could not create header artifact");
        DWORD written = 0;
        const auto ok = WriteFile(file, image.data(), static_cast<DWORD>(headerBytes), &written, nullptr)
            && written == static_cast<DWORD>(headerBytes);
        FlushFileBuffers(file);
        CloseHandle(file);
        if(!ok)
        {
            DeleteFileW(widePartial.c_str());
            return Outcome::Failure("artifact_write_failed", "could not write header artifact");
        }
        if(!MoveFileExW(
               widePartial.c_str(),
               widePath.c_str(),
               MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            DeleteFileW(widePartial.c_str());
            return Outcome::Failure("artifact_rename_failed", "could not rename header artifact");
        }
    }

    auto result = JsonObject();
    JsonSet(result.get(), "base", JsonInteger(base));
    JsonSet(result.get(), "module_size", JsonInteger(moduleSize));
    JsonSet(result.get(), "name", JsonString(moduleName));
    JsonSet(result.get(), "path", JsonString(modulePath));
    JsonSet(result.get(), "pe_offset", JsonInteger(peOffset));
    JsonSet(result.get(), "machine", JsonInteger(machine));
    JsonSet(result.get(), "architecture", JsonString(pe32Plus ? "x64" : "x86"));
    JsonSet(result.get(), "characteristics", JsonInteger(characteristics));
    JsonSet(result.get(), "subsystem", JsonInteger(subsystem));
    JsonSet(result.get(), "dll_characteristics", JsonInteger(dllCharacteristics));
    JsonSet(result.get(), "image_base", JsonInteger(imageBase));
    JsonSet(result.get(), "image_size", JsonInteger(imageSize));
    JsonSet(result.get(), "entry_point_rva", JsonInteger(entryPointRva));
    JsonSet(result.get(), "section_alignment", JsonInteger(sectionAlignment));
    JsonSet(result.get(), "file_alignment", JsonInteger(fileAlignment));
    JsonSet(result.get(), "size_of_headers", JsonInteger(sizeOfHeaders));
    JsonSet(result.get(), "section_count", JsonInteger(sectionCount));
    JsonSet(result.get(), "directories", std::move(directories));
    JsonSet(result.get(), "sections", std::move(sections));
    if(!outputPath.empty())
        JsonSet(result.get(), "header_artifact", JsonString(outputPath));
    JsonSet(
        result.get(),
        "note",
        JsonString("paused-only runtime PE headers; caller should preserve header artifact before rebuild"));
    return Outcome::Success(std::move(result));
}

struct ModuleRecord
{
    duint base = 0;
    duint size = 0;
    std::string name;
    std::string path;
};

struct ApiCatalogEntry
{
    duint address = 0;
    std::string module;
    std::string name;
    std::uint32_t ordinal = 0;
};

struct SymbolEnumContext
{
    std::map<duint, ApiCatalogEntry>* catalog = nullptr;
    std::string moduleName;
    std::size_t* accepted = nullptr;
};

bool CollectExportSymbol(const SYMBOLPTR* symbol, void* user)
{
    auto* context = static_cast<SymbolEnumContext*>(user);
    if(context == nullptr || context->catalog == nullptr || context->accepted == nullptr)
        return false;
    if(*context->accepted >= MaxImportApiCatalog)
        return false;

    SYMBOLINFO info = {};
    DbgGetSymbolInfo(symbol, &info);
    const auto freeDecorated = info.freeDecorated;
    const auto freeUndecorated = info.freeUndecorated;
    const auto decorated = info.decoratedSymbol;
    const auto undecorated = info.undecoratedSymbol;

    auto release = [&]()
    {
        if(freeDecorated && decorated != nullptr)
            BridgeFree(decorated);
        if(freeUndecorated && undecorated != nullptr)
            BridgeFree(undecorated);
    };

    if(info.type != sym_export || info.addr == 0)
    {
        release();
        return true;
    }

    ApiCatalogEntry entry;
    entry.address = info.addr;
    entry.module = context->moduleName;
    entry.ordinal = info.ordinal;
    if(undecorated != nullptr && undecorated[0] != '\0')
        entry.name = undecorated;
    else if(decorated != nullptr && decorated[0] != '\0')
        entry.name = decorated;
    else if(info.ordinal != 0)
        entry.name = "ordinal_" + std::to_string(info.ordinal);
    else
        entry.name = "export";

    if(context->catalog->emplace(entry.address, std::move(entry)).second)
        ++(*context->accepted);
    release();
    return *context->accepted < MaxImportApiCatalog;
}

Outcome BuildApiCatalog(std::map<duint, ApiCatalogEntry>& catalog, std::size_t& moduleCount)
{
    const auto functions = DbgFunctions();
    functions->MemUpdateMap();

    MEMMAP memoryMap = {};
    if(!DbgMemMap(&memoryMap))
        return Outcome::Failure("memory_map_failed", "x64dbg could not read the memory map");

    std::map<duint, ModuleRecord> modules;
    for(int index = 0; index < memoryMap.count; ++index)
    {
        const auto& page = memoryMap.page[index];
        if(page.mbi.Type != MEM_IMAGE || page.mbi.AllocationBase == nullptr)
            continue;
        auto base = reinterpret_cast<duint>(page.mbi.AllocationBase);
        auto& module = modules[base];
        module.base = base;
        module.size += static_cast<duint>(page.mbi.RegionSize);
    }
    if(memoryMap.page != nullptr)
        BridgeFree(memoryMap.page);

    std::size_t accepted = 0;
    moduleCount = 0;
    for(auto& item : modules)
    {
        auto& module = item.second;
        char name[MAX_MODULE_SIZE] = {};
        if(functions->ModNameFromAddr(module.base, name, true))
            module.name = name;
        auto reportedSize = functions->ModSizeFromAddr(module.base);
        if(reportedSize != 0)
            module.size = reportedSize;
        if(module.name.empty())
            continue;
        ++moduleCount;
        SymbolEnumContext context;
        context.catalog = &catalog;
        context.moduleName = module.name;
        context.accepted = &accepted;
        DbgSymbolEnum(module.base, CollectExportSymbol, &context);
        if(accepted >= MaxImportApiCatalog)
            break;
    }
    return Outcome::Success(JsonObject());
}

struct IatRunCandidate
{
    duint start = 0;
    duint size = 0;
    std::uint64_t matched = 0;
    std::uint64_t slots = 0;
    double confidence = 0.0;
    std::string kind = "consecutive";
    std::vector<std::pair<duint, const ApiCatalogEntry*>> samples;
};

void ClusterApiHits(
    const std::vector<std::pair<duint, const ApiCatalogEntry*>>& hits,
    const char* kind,
    duint maxGap,
    std::uint64_t minMatched,
    std::vector<IatRunCandidate>& out)
{
    if(hits.empty())
        return;
    std::vector<std::pair<duint, const ApiCatalogEntry*>> ordered = hits;
    std::sort(
        ordered.begin(),
        ordered.end(),
        [](const auto& left, const auto& right) { return left.first < right.first; });
    ordered.erase(
        std::unique(
            ordered.begin(),
            ordered.end(),
            [](const auto& left, const auto& right) { return left.first == right.first; }),
        ordered.end());

    IatRunCandidate current;
    current.kind = kind;
    const auto pointerSize = static_cast<duint>(sizeof(duint));
    auto flush = [&]()
    {
        if(current.matched >= minMatched)
        {
            current.slots = (std::max)(current.slots, current.matched);
            current.confidence =
                static_cast<double>(current.matched) / static_cast<double>((std::max)(current.slots, current.matched));
            if(current.matched >= 8)
                current.confidence = (std::min)(1.0, current.confidence + 0.1);
            if(std::strcmp(kind, "call_site") == 0)
                current.confidence = (std::min)(1.0, current.confidence + 0.05);
            out.push_back(current);
        }
        current = IatRunCandidate{};
        current.kind = kind;
    };

    for(const auto& hit : ordered)
    {
        if(current.matched == 0)
        {
            current.start = hit.first;
            current.size = pointerSize;
            current.matched = 1;
            current.slots = 1;
            current.samples.push_back(hit);
            continue;
        }
        const auto prevEnd = current.start + current.size;
        if(hit.first > prevEnd + maxGap)
        {
            flush();
            current.start = hit.first;
            current.size = pointerSize;
            current.matched = 1;
            current.slots = 1;
            current.samples.push_back(hit);
            continue;
        }
        current.matched += 1;
        current.slots = ((hit.first + pointerSize) - current.start) / pointerSize;
        current.size = (hit.first + pointerSize) - current.start;
        if(current.samples.size() < 8)
            current.samples.push_back(hit);
    }
    flush();
}

Outcome ScanImports(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t moduleBase = 0;
    if(!ReadUnsigned(params, "module_base", moduleBase, error, std::numeric_limits<duint>::max()))
        return error;
    if(moduleBase == 0)
        return InvalidField("module_base", "module_base must be a non-zero module base");

    const auto functions = DbgFunctions();
    auto moduleSize = static_cast<std::uint64_t>(functions->ModSizeFromAddr(static_cast<duint>(moduleBase)));
    if(moduleSize == 0)
        return Outcome::Failure("module_not_found", "no module is loaded at module_base");

    std::uint64_t searchStart = moduleBase;
    auto searchStartItem = Param(params, "search_start");
    if(searchStartItem != nullptr)
    {
        if(!ReadUnsigned(params, "search_start", searchStart, error, std::numeric_limits<duint>::max()))
            return error;
    }

    std::uint64_t searchSize = moduleSize;
    auto searchSizeItem = Param(params, "search_size");
    if(searchSizeItem != nullptr)
    {
        if(!ReadUnsigned(params, "search_size", searchSize, error, MaxImportScanBytes))
            return error;
        if(searchSize == 0)
            return InvalidField("search_size", "search_size must be positive");
    }
    if(searchSize > MaxImportScanBytes)
        searchSize = MaxImportScanBytes;

    std::uint64_t maxCandidates = 8;
    auto maxCandidatesItem = Param(params, "max_candidates");
    if(maxCandidatesItem != nullptr)
    {
        if(!ReadUnsigned(params, "max_candidates", maxCandidates, error, MaxImportCandidates))
            return error;
        if(maxCandidates == 0)
            return InvalidField("max_candidates", "max_candidates must be positive");
    }

    // consecutive | sparse | call_site | all (default)
    std::string mode = "all";
    auto modeItem = Param(params, "mode");
    if(modeItem != nullptr)
    {
        if(!json_is_string(modeItem))
            return InvalidField("mode", "mode must be a string");
        mode = json_string_value(modeItem);
        if(mode != "all" && mode != "consecutive" && mode != "sparse" && mode != "call_site")
            return InvalidField("mode", "mode must be consecutive|sparse|call_site|all");
    }
    const bool wantConsecutive = mode == "all" || mode == "consecutive";
    const bool wantSparse = mode == "all" || mode == "sparse";
    const bool wantCallSite = mode == "all" || mode == "call_site";

    std::map<duint, ApiCatalogEntry> catalog;
    std::size_t moduleCount = 0;
    auto catalogOutcome = BuildApiCatalog(catalog, moduleCount);
    if(!catalogOutcome.ok)
        return catalogOutcome;
    if(catalog.empty())
        return Outcome::Failure("api_catalog_empty", "no export symbols were available for IAT matching");

    const auto pointerSize = static_cast<std::uint64_t>(sizeof(duint));
    std::vector<unsigned char> buffer(static_cast<std::size_t>(
        (std::min)(MaxMemoryBytes, searchSize)));
    std::vector<IatRunCandidate> candidates;
    std::vector<std::pair<duint, const ApiCatalogEntry*>> sparseHits;
    std::vector<std::pair<duint, const ApiCatalogEntry*>> callSiteHits;
    IatRunCandidate current;
    current.kind = "consecutive";
    auto flush = [&]()
    {
        if(wantConsecutive && current.matched >= 2 && current.slots >= 2)
        {
            current.confidence = static_cast<double>(current.matched) / static_cast<double>(current.slots);
            if(current.matched >= 8)
                current.confidence = (std::min)(1.0, current.confidence + 0.15);
            candidates.push_back(current);
        }
        current = IatRunCandidate{};
        current.kind = "consecutive";
    };

    std::uint64_t offset = 0;
    while(offset + pointerSize <= searchSize)
    {
        const auto chunk = (std::min)(
            static_cast<std::uint64_t>(buffer.size()),
            searchSize - offset);
        const auto alignedChunk = chunk - (chunk % pointerSize);
        if(alignedChunk < pointerSize)
            break;
        if(!DbgMemRead(
               static_cast<duint>(searchStart + offset),
               buffer.data(),
               static_cast<duint>(alignedChunk)))
        {
            flush();
            offset += alignedChunk;
            continue;
        }
        for(std::uint64_t index = 0; index + pointerSize <= alignedChunk; index += pointerSize)
        {
            duint value = 0;
            std::memcpy(&value, buffer.data() + static_cast<std::size_t>(index), sizeof(duint));
            const auto va = static_cast<duint>(searchStart + offset + index);
            if(value == 0)
            {
                // Null separators commonly appear between DLL groups; keep an open run.
                if(current.slots != 0)
                {
                    current.slots += 1;
                    current.size = (va + static_cast<duint>(pointerSize)) - current.start;
                }
                continue;
            }
            const auto found = catalog.find(value);
            if(found == catalog.end())
            {
                flush();
                continue;
            }
            if(wantSparse)
                sparseHits.emplace_back(va, &found->second);
            if(current.slots == 0)
            {
                current.start = va;
                current.size = static_cast<duint>(pointerSize);
                current.matched = 1;
                current.slots = 1;
                if(current.samples.size() < 8)
                    current.samples.emplace_back(va, &found->second);
            }
            else
            {
                current.matched += 1;
                current.slots += 1;
                current.size = (va + static_cast<duint>(pointerSize)) - current.start;
                if(current.samples.size() < 8)
                    current.samples.emplace_back(va, &found->second);
            }
        }

        if(wantCallSite && alignedChunk >= 6)
        {
            const bool is64 = sizeof(duint) == 8;
            for(std::uint64_t index = 0; index + 6 <= alignedChunk; ++index)
            {
                if(buffer[static_cast<std::size_t>(index)] != 0xFF)
                    continue;
                const auto modrm = buffer[static_cast<std::size_t>(index + 1)];
                if(modrm != 0x15 && modrm != 0x25)
                    continue;
                const auto insnVa = static_cast<duint>(searchStart + offset + index);
                duint slotVa = 0;
                if(is64)
                {
                    std::int32_t rel = 0;
                    std::memcpy(&rel, buffer.data() + static_cast<std::size_t>(index + 2), sizeof(rel));
                    slotVa = insnVa + 6 + static_cast<duint>(rel);
                }
                else
                {
                    std::uint32_t absolute = 0;
                    std::memcpy(&absolute, buffer.data() + static_cast<std::size_t>(index + 2), sizeof(absolute));
                    slotVa = static_cast<duint>(absolute);
                }
                if(slotVa < static_cast<duint>(moduleBase)
                   || slotVa + sizeof(duint) > static_cast<duint>(moduleBase + moduleSize))
                {
                    continue;
                }
                duint pointed = 0;
                if(!DbgMemRead(slotVa, &pointed, sizeof(pointed)))
                    continue;
                const auto found = catalog.find(pointed);
                if(found == catalog.end())
                    continue;
                callSiteHits.emplace_back(slotVa, &found->second);
            }
        }
        offset += alignedChunk;
    }
    flush();

    if(wantSparse)
    {
        // Allow non-API gaps up to 64 pointers (~256B x86 / 512B x64) between hits.
        ClusterApiHits(
            sparseHits,
            "sparse",
            static_cast<duint>(pointerSize * 64),
            3,
            candidates);
    }
    if(wantCallSite)
    {
        ClusterApiHits(
            callSiteHits,
            "call_site",
            static_cast<duint>(pointerSize * 64),
            2,
            candidates);
    }

    std::sort(
        candidates.begin(),
        candidates.end(),
        [](const IatRunCandidate& left, const IatRunCandidate& right)
        {
            if(left.confidence != right.confidence)
                return left.confidence > right.confidence;
            if(left.matched != right.matched)
                return left.matched > right.matched;
            return left.start < right.start;
        });
    if(candidates.size() > maxCandidates)
        candidates.resize(static_cast<std::size_t>(maxCandidates));

    auto values = JsonArray();
    for(const auto& candidate : candidates)
    {
        auto value = JsonObject();
        JsonSet(value.get(), "iat_va", AddressValue(candidate.start));
        JsonSet(value.get(), "iat_rva", AddressValue(candidate.start - static_cast<duint>(moduleBase)));
        JsonSet(value.get(), "size", AddressValue(candidate.size));
        JsonSet(value.get(), "matched_count", JsonInteger(candidate.matched));
        JsonSet(value.get(), "slot_count", JsonInteger(candidate.slots));
        JsonSet(value.get(), "kind", JsonString(candidate.kind));
        JsonSet(
            value.get(),
            "confidence",
            JsonPtr(json_real(candidate.confidence)));
        auto samples = JsonArray();
        for(const auto& sample : candidate.samples)
        {
            auto item = JsonObject();
            JsonSet(item.get(), "thunk_va", AddressValue(sample.first));
            JsonSet(item.get(), "api_va", AddressValue(sample.second->address));
            JsonSet(item.get(), "module", JsonString(sample.second->module));
            JsonSet(item.get(), "name", JsonString(sample.second->name));
            JsonSet(item.get(), "ordinal", JsonInteger(sample.second->ordinal));
            JsonAppend(samples.get(), std::move(item));
        }
        JsonSet(value.get(), "sample_apis", std::move(samples));
        JsonAppend(values.get(), std::move(value));
    }

    auto result = JsonObject();
    JsonSet(result.get(), "module_base", JsonInteger(moduleBase));
    JsonSet(result.get(), "module_size", JsonInteger(moduleSize));
    JsonSet(result.get(), "search_start", JsonInteger(searchStart));
    JsonSet(result.get(), "search_size", JsonInteger(searchSize));
    JsonSet(result.get(), "pointer_size", JsonInteger(pointerSize));
    JsonSet(result.get(), "mode", JsonString(mode));
    JsonSet(result.get(), "api_catalog_count", JsonInteger(catalog.size()));
    JsonSet(result.get(), "api_module_count", JsonInteger(moduleCount));
    JsonSet(result.get(), "candidates", std::move(values));
    JsonSet(result.get(), "candidate_count", JsonInteger(candidates.size()));
    JsonSet(result.get(), "blind_selection", JsonBoolean(false));
    JsonSet(
        result.get(),
        "note",
        JsonString(
            "heuristic IAT candidates: consecutive export-pointer runs, sparse proximity "
            "clusters, and FF15/FF25 call-site slots; caller must confirm"));
    return Outcome::Success(std::move(result));
}

Outcome ReadImports(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t iatVa = 0;
    std::uint64_t size = 0;
    if(!ReadUnsigned(params, "iat_va", iatVa, error, std::numeric_limits<duint>::max()))
        return error;
    if(!ReadUnsigned(params, "size", size, error, MaxImportScanBytes))
        return error;
    if(size == 0 || (size % sizeof(duint)) != 0)
        return InvalidField("size", "size must be a positive multiple of pointer width");

    std::map<duint, ApiCatalogEntry> catalog;
    std::size_t moduleCount = 0;
    auto catalogOutcome = BuildApiCatalog(catalog, moduleCount);
    if(!catalogOutcome.ok)
        return catalogOutcome;

    std::vector<unsigned char> bytes(static_cast<std::size_t>(size));
    if(!DbgMemRead(static_cast<duint>(iatVa), bytes.data(), static_cast<duint>(size)))
        return Outcome::Failure("memory_read_failed", "x64dbg could not read the IAT range");

    auto entries = JsonArray();
    std::uint64_t resolved = 0;
    for(std::uint64_t offset = 0; offset + sizeof(duint) <= size; offset += sizeof(duint))
    {
        duint value = 0;
        std::memcpy(&value, bytes.data() + static_cast<std::size_t>(offset), sizeof(duint));
        auto item = JsonObject();
        JsonSet(item.get(), "thunk_va", AddressValue(static_cast<duint>(iatVa + offset)));
        JsonSet(item.get(), "value", AddressValue(value));
        if(value == 0)
        {
            JsonSet(item.get(), "kind", JsonString("null"));
        }
        else
        {
            const auto found = catalog.find(value);
            if(found == catalog.end())
            {
                JsonSet(item.get(), "kind", JsonString("unresolved"));
            }
            else
            {
                JsonSet(item.get(), "kind", JsonString("api"));
                JsonSet(item.get(), "module", JsonString(found->second.module));
                JsonSet(item.get(), "name", JsonString(found->second.name));
                JsonSet(item.get(), "ordinal", JsonInteger(found->second.ordinal));
                ++resolved;
            }
        }
        JsonAppend(entries.get(), std::move(item));
    }

    auto result = JsonObject();
    JsonSet(result.get(), "iat_va", JsonInteger(iatVa));
    JsonSet(result.get(), "size", JsonInteger(size));
    JsonSet(result.get(), "entries", std::move(entries));
    JsonSet(result.get(), "resolved_count", JsonInteger(resolved));
    JsonSet(result.get(), "api_catalog_count", JsonInteger(catalog.size()));
    return Outcome::Success(std::move(result));
}

Outcome RebuildImports(const json_t* /*params*/)
{
    return Outcome::Failure(
        "not_implemented",
        "imports.rebuild is reserved for a later M4.3/M4.4 milestone and is intentionally unavailable");
}

Outcome ListModules()
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    const auto functions = DbgFunctions();
    functions->MemUpdateMap();

    MEMMAP memoryMap = {};
    if(!DbgMemMap(&memoryMap))
        return Outcome::Failure("module_list_failed", "x64dbg could not read the memory map");

    std::map<duint, ModuleRecord> modules;
    for(int index = 0; index < memoryMap.count; ++index)
    {
        const auto& page = memoryMap.page[index];
        if(page.mbi.Type != MEM_IMAGE || page.mbi.AllocationBase == nullptr)
            continue;
        auto base = reinterpret_cast<duint>(page.mbi.AllocationBase);
        auto& module = modules[base];
        module.base = base;
        module.size += static_cast<duint>(page.mbi.RegionSize);
    }
    if(memoryMap.page != nullptr)
        BridgeFree(memoryMap.page);

    for(auto& item : modules)
    {
        auto& module = item.second;
        char name[MAX_MODULE_SIZE] = {};
        char path[MAX_PATH] = {};
        if(functions->ModNameFromAddr(module.base, name, true))
            module.name = name;
        if(functions->ModPathFromAddr(module.base, path, _countof(path)))
            module.path = path;
        auto reportedSize = functions->ModSizeFromAddr(module.base);
        if(reportedSize != 0)
            module.size = reportedSize;
    }

    auto values = JsonArray();
    std::size_t count = 0;
    for(const auto& item : modules)
    {
        const auto& module = item.second;
        if(module.name.empty() && module.path.empty())
            continue;
        auto value = JsonObject();
        JsonSet(value.get(), "base", AddressValue(module.base));
        JsonSet(value.get(), "size", AddressValue(module.size));
        JsonSet(value.get(), "name", JsonString(module.name));
        JsonSet(value.get(), "path", JsonString(module.path));
        JsonAppend(values.get(), std::move(value));
        ++count;
    }
    auto result = JsonObject();
    JsonSet(result.get(), "modules", std::move(values));
    JsonSet(result.get(), "count", JsonInteger(count));
    return Outcome::Success(std::move(result));
}

const char* BreakpointTypeName(BPXTYPE type)
{
    switch(type)
    {
    case bp_normal:
        return "software";
    case bp_hardware:
        return "hardware";
    case bp_memory:
        return "memory";
    case bp_dll:
        return "dll";
    case bp_exception:
        return "exception";
    default:
        return "unknown";
    }
}

JsonPtr BreakpointObject(const BRIDGEBP& breakpoint)
{
    auto value = JsonObject();
    JsonSet(value.get(), "type", JsonString(BreakpointTypeName(breakpoint.type)));
    JsonSet(value.get(), "address", AddressValue(breakpoint.addr));
    JsonSet(value.get(), "enabled", JsonBoolean(breakpoint.enabled));
    JsonSet(value.get(), "active", JsonBoolean(breakpoint.active));
    JsonSet(value.get(), "single_shot", JsonBoolean(breakpoint.singleshoot));
    JsonSet(value.get(), "hit_count", JsonInteger(breakpoint.hitCount));
    JsonSet(value.get(), "name", JsonString(breakpoint.name));
    JsonSet(value.get(), "module", JsonString(breakpoint.mod));
    JsonSet(value.get(), "condition", JsonString(breakpoint.breakCondition));
    JsonSet(value.get(), "slot", JsonInteger(breakpoint.slot));
    JsonSet(value.get(), "type_ex", JsonInteger(breakpoint.typeEx));
    JsonSet(value.get(), "hw_size", JsonInteger(breakpoint.hwSize));
    return value;
}

Outcome ListBreakpointsFiltered(BPXTYPE typeFilter, const char* key)
{
    auto ready = RequireDebugging();
    if(!ready.ok)
        return ready;

    BPMAP map = {};
    DbgGetBpList(typeFilter, &map);
    auto values = JsonArray();
    for(int index = 0; index < map.count; ++index)
        JsonAppend(values.get(), BreakpointObject(map.bp[index]));
    if(map.bp != nullptr)
        BridgeFree(map.bp);

    auto result = JsonObject();
    JsonSet(result.get(), key, std::move(values));
    JsonSet(result.get(), "count", JsonInteger(static_cast<std::uint64_t>(map.count < 0 ? 0 : map.count)));
    return Outcome::Success(std::move(result));
}

Outcome ListBreakpoints()
{
    return ListBreakpointsFiltered(bp_none, "breakpoints");
}

Outcome ChangeBreakpoint(const json_t* params, bool set)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;
    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;

    auto command = std::string(set ? "SetBPX " : "DeleteBPX ")
        + HexAddress(static_cast<duint>(address));
    if(!DbgCmdExecDirect(command.c_str()))
        return CommandFailure(set ? "breakpoints.set" : "breakpoints.remove", command.c_str());

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "set", JsonBoolean(set));
    return Outcome::Success(std::move(result));
}

bool ReadOptionalUnsigned(
    const json_t* params,
    const char* key,
    std::uint64_t& value,
    Outcome& error,
    std::uint64_t maximum,
    bool& present)
{
    present = false;
    auto item = Param(params, key);
    if(item == nullptr)
        return true;
    present = true;
    return ReadUnsigned(params, key, value, error, maximum);
}

const char* ThreadPriorityName(THREADPRIORITY priority)
{
    switch(priority)
    {
    case _PriorityIdle:
        return "idle";
    case _PriorityAboveNormal:
        return "above_normal";
    case _PriorityBelowNormal:
        return "below_normal";
    case _PriorityHighest:
        return "highest";
    case _PriorityLowest:
        return "lowest";
    case _PriorityNormal:
        return "normal";
    case _PriorityTimeCritical:
        return "time_critical";
    default:
        return "unknown";
    }
}

JsonPtr ThreadObject(const THREADALLINFO& thread, bool current)
{
    auto value = JsonObject();
    JsonSet(value.get(), "number", JsonInteger(static_cast<std::uint64_t>(thread.BasicInfo.ThreadNumber)));
    JsonSet(value.get(), "tid", JsonInteger(thread.BasicInfo.ThreadId));
    JsonSet(value.get(), "entry", AddressValue(thread.BasicInfo.ThreadStartAddress));
    JsonSet(value.get(), "teb", AddressValue(thread.BasicInfo.ThreadLocalBase));
    JsonSet(value.get(), "cip", AddressValue(thread.ThreadCip));
    JsonSet(value.get(), "name", JsonString(thread.BasicInfo.threadName));
    JsonSet(value.get(), "suspend_count", JsonInteger(thread.SuspendCount));
    JsonSet(value.get(), "priority", JsonString(ThreadPriorityName(thread.Priority)));
    JsonSet(value.get(), "priority_raw", JsonInteger(static_cast<std::uint64_t>(thread.Priority)));
    JsonSet(value.get(), "wait_reason", JsonInteger(static_cast<std::uint64_t>(thread.WaitReason)));
    JsonSet(value.get(), "last_error", JsonInteger(thread.LastError));
    JsonSet(value.get(), "cycles", JsonInteger(thread.Cycles));
    JsonSet(value.get(), "current", JsonBoolean(current));
    return value;
}

Outcome ListThreads()
{
    auto ready = RequireDebugging();
    if(!ready.ok)
        return ready;

    THREADLIST list = {};
    DbgGetThreadList(&list);
    auto values = JsonArray();
    for(int index = 0; index < list.count; ++index)
        JsonAppend(values.get(), ThreadObject(list.list[index], index == list.CurrentThread));
    if(list.list != nullptr)
        BridgeFree(list.list);

    auto result = JsonObject();
    JsonSet(result.get(), "threads", std::move(values));
    JsonSet(result.get(), "count", JsonInteger(static_cast<std::uint64_t>(list.count < 0 ? 0 : list.count)));
    JsonSet(result.get(), "current_index", JsonInteger(static_cast<std::uint64_t>(list.CurrentThread)));
    JsonSet(result.get(), "current_tid", JsonInteger(DbgGetThreadId()));
    return Outcome::Success(std::move(result));
}

Outcome CurrentThread()
{
    auto ready = RequireDebugging();
    if(!ready.ok)
        return ready;

    THREADLIST list = {};
    DbgGetThreadList(&list);
    Outcome outcome;
    if(list.count <= 0 || list.CurrentThread < 0 || list.CurrentThread >= list.count)
    {
        outcome = Outcome::Failure("thread_not_found", "no current thread is available");
    }
    else
    {
        auto result = ThreadObject(list.list[list.CurrentThread], true);
        JsonSet(result.get(), "tid", JsonInteger(DbgGetThreadId()));
        outcome = Outcome::Success(std::move(result));
    }
    if(list.list != nullptr)
        BridgeFree(list.list);
    return outcome;
}

bool SwitchThread(DWORD tid, Outcome& error, const char* method)
{
    auto command = std::string("switchthread ") + HexAddress(static_cast<duint>(tid));
    if(!DbgCmdExecDirect(command.c_str()))
    {
        error = CommandFailure(method, command.c_str());
        return false;
    }
    return true;
}

Outcome ReadThreadContext(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t tid = 0;
    if(!ReadUnsigned(params, "tid", tid, error, std::numeric_limits<DWORD>::max()))
        return error;
    if(tid == 0)
        return InvalidField("tid", "tid must be positive");

    const auto previousTid = DbgGetThreadId();
    if(!SwitchThread(static_cast<DWORD>(tid), error, "threads.context.read"))
        return error;

    auto registers = ReadRegisters();
    Outcome restoreError;
    if(!SwitchThread(previousTid, restoreError, "threads.context.read"))
    {
        if(registers.ok)
            return restoreError;
        return registers;
    }
    if(!registers.ok)
        return registers;

    JsonSet(registers.value.get(), "tid", JsonInteger(tid));
    JsonSet(registers.value.get(), "restored_tid", JsonInteger(previousTid));
    return registers;
}

Outcome WriteThreadContext(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t tid = 0;
    if(!ReadUnsigned(params, "tid", tid, error, std::numeric_limits<DWORD>::max()))
        return error;
    if(tid == 0)
        return InvalidField("tid", "tid must be positive");

    const auto previousTid = DbgGetThreadId();
    if(!SwitchThread(static_cast<DWORD>(tid), error, "threads.context.write"))
        return error;

    auto written = WriteRegister(params);
    Outcome restoreError;
    if(!SwitchThread(previousTid, restoreError, "threads.context.write"))
    {
        if(written.ok)
            return restoreError;
        return written;
    }
    if(!written.ok)
        return written;

    JsonSet(written.value.get(), "tid", JsonInteger(tid));
    JsonSet(written.value.get(), "restored_tid", JsonInteger(previousTid));
    return written;
}

Outcome ReadStack(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t count = 32;
    bool countPresent = false;
    if(!ReadOptionalUnsigned(params, "count", count, error, MaxStackEntries, countPresent))
        return error;
    if(count == 0)
        return InvalidField("count", "count must be positive");

    std::uint64_t address = 0;
    bool addressPresent = false;
    if(!ReadOptionalUnsigned(
           params, "address", address, error, std::numeric_limits<duint>::max(), addressPresent))
        return error;
    if(!addressPresent)
        address = static_cast<std::uint64_t>(DbgValFromString("csp"));

    const auto pointerSize = static_cast<std::uint64_t>(sizeof(duint));
    const auto byteCount = count * pointerSize;
    std::vector<unsigned char> bytes(static_cast<std::size_t>(byteCount));
    if(!DbgMemRead(static_cast<duint>(address), bytes.data(), static_cast<duint>(byteCount)))
        return Outcome::Failure("stack_read_failed", "x64dbg could not read the requested stack range");

    auto values = JsonArray();
    for(std::uint64_t index = 0; index < count; ++index)
    {
        duint word = 0;
        std::memcpy(&word, bytes.data() + static_cast<std::size_t>(index * pointerSize), sizeof(duint));
        auto entry = JsonObject();
        JsonSet(entry.get(), "index", JsonInteger(index));
        JsonSet(entry.get(), "address", AddressValue(static_cast<duint>(address + index * pointerSize)));
        JsonSet(entry.get(), "value", AddressValue(word));
        JsonAppend(values.get(), std::move(entry));
    }

    auto result = JsonObject();
    JsonSet(result.get(), "base", JsonInteger(address));
    JsonSet(result.get(), "count", JsonInteger(count));
    JsonSet(result.get(), "pointer_size", JsonInteger(pointerSize));
    JsonSet(result.get(), "entries", std::move(values));
    return Outcome::Success(std::move(result));
}

Outcome TraceStack(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t limit = MaxStackEntries;
    bool limitPresent = false;
    if(!ReadOptionalUnsigned(params, "limit", limit, error, MaxStackEntries, limitPresent))
        return error;
    if(limit == 0)
        return InvalidField("limit", "limit must be positive");

    const auto functions = DbgFunctions();
    DBGCALLSTACK callstack = {};
    if(functions->GetCallStackEx != nullptr)
        functions->GetCallStackEx(&callstack, false);
    else
        functions->GetCallStack(&callstack);

    auto frames = JsonArray();
    const auto total = callstack.total < 0 ? 0 : callstack.total;
    const auto emit = (std::min)(static_cast<std::uint64_t>(total), limit);
    for(std::uint64_t index = 0; index < emit; ++index)
    {
        const auto& frame = callstack.entries[static_cast<int>(index)];
        auto value = JsonObject();
        JsonSet(value.get(), "index", JsonInteger(index));
        JsonSet(value.get(), "addr", AddressValue(frame.addr));
        JsonSet(value.get(), "from", AddressValue(frame.from));
        JsonSet(value.get(), "to", AddressValue(frame.to));
        JsonSet(value.get(), "comment", JsonString(frame.comment));
        JsonAppend(frames.get(), std::move(value));
    }
    if(callstack.entries != nullptr)
        BridgeFree(callstack.entries);

    auto result = JsonObject();
    JsonSet(result.get(), "frames", std::move(frames));
    JsonSet(result.get(), "count", JsonInteger(emit));
    JsonSet(result.get(), "total", JsonInteger(static_cast<std::uint64_t>(total)));
    JsonSet(result.get(), "limit", JsonInteger(limit));
    JsonSet(result.get(), "has_more", JsonBoolean(static_cast<std::uint64_t>(total) > emit));
    return Outcome::Success(std::move(result));
}

Outcome ReadDisassembly(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;

    std::uint64_t count = 32;
    bool countPresent = false;
    if(!ReadOptionalUnsigned(params, "count", count, error, MaxDisasmInstructions, countPresent))
        return error;
    if(count == 0)
        return InvalidField("count", "count must be positive");

    auto instructions = JsonArray();
    auto cursor = static_cast<duint>(address);
    for(std::uint64_t index = 0; index < count; ++index)
    {
        BASIC_INSTRUCTION_INFO info = {};
        DbgDisasmFastAt(cursor, &info);
        if(info.size <= 0)
            break;
        auto value = JsonObject();
        JsonSet(value.get(), "address", AddressValue(cursor));
        JsonSet(value.get(), "size", JsonInteger(static_cast<std::uint64_t>(info.size)));
        JsonSet(value.get(), "instruction", JsonString(info.instruction));
        JsonSet(value.get(), "branch", JsonBoolean(info.branch));
        JsonSet(value.get(), "call", JsonBoolean(info.call));
        if(info.type & TYPE_ADDR)
            JsonSet(value.get(), "target", AddressValue(info.addr));
        JsonAppend(instructions.get(), std::move(value));
        cursor += static_cast<duint>(info.size);
    }

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "count", JsonInteger(static_cast<std::uint64_t>(json_array_size(instructions.get()))));
    JsonSet(result.get(), "instructions", std::move(instructions));
    return Outcome::Success(std::move(result));
}

struct BoundedSymbolContext
{
    json_t* values = nullptr;
    std::uint64_t accepted = 0;
    std::uint64_t limit = 0;
    std::string moduleName;
};

bool CollectBoundedSymbol(const SYMBOLPTR* symbol, void* user)
{
    auto* context = static_cast<BoundedSymbolContext*>(user);
    if(context == nullptr || context->values == nullptr)
        return false;
    if(context->accepted >= context->limit)
        return false;

    SYMBOLINFO info = {};
    DbgGetSymbolInfo(symbol, &info);
    const auto freeDecorated = info.freeDecorated;
    const auto freeUndecorated = info.freeUndecorated;
    const auto decorated = info.decoratedSymbol;
    const auto undecorated = info.undecoratedSymbol;
    auto release = [&]()
    {
        if(freeDecorated && decorated != nullptr)
            BridgeFree(decorated);
        if(freeUndecorated && undecorated != nullptr)
            BridgeFree(undecorated);
    };

    if(info.addr == 0)
    {
        release();
        return true;
    }

    std::string name;
    if(undecorated != nullptr && undecorated[0] != '\0')
        name = undecorated;
    else if(decorated != nullptr && decorated[0] != '\0')
        name = decorated;
    else if(info.ordinal != 0)
        name = "ordinal_" + std::to_string(info.ordinal);
    else
        name = "symbol";

    auto value = JsonObject();
    JsonSet(value.get(), "address", AddressValue(info.addr));
    JsonSet(value.get(), "name", JsonString(name));
    JsonSet(value.get(), "module", JsonString(context->moduleName));
    JsonSet(value.get(), "ordinal", JsonInteger(info.ordinal));
    JsonSet(value.get(), "type", JsonInteger(static_cast<std::uint64_t>(info.type)));
    JsonAppend(context->values, std::move(value));
    ++context->accepted;
    release();
    return context->accepted < context->limit;
}

Outcome ListSymbols(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t moduleBase = 0;
    if(!ReadUnsigned(params, "module_base", moduleBase, error, std::numeric_limits<duint>::max()))
        return error;
    if(moduleBase == 0)
        return InvalidField("module_base", "module_base must be a non-zero module base");

    std::uint64_t limit = 256;
    bool limitPresent = false;
    if(!ReadOptionalUnsigned(params, "limit", limit, error, MaxSymbolEnum, limitPresent))
        return error;
    if(limit == 0)
        return InvalidField("limit", "limit must be positive");

    const auto functions = DbgFunctions();
    char moduleName[MAX_MODULE_SIZE] = {};
    functions->ModNameFromAddr(static_cast<duint>(moduleBase), moduleName, true);

    auto values = JsonArray();
    BoundedSymbolContext context;
    context.values = values.get();
    context.limit = limit;
    context.moduleName = moduleName;
    DbgSymbolEnum(static_cast<duint>(moduleBase), CollectBoundedSymbol, &context);

    auto result = JsonObject();
    JsonSet(result.get(), "module_base", JsonInteger(moduleBase));
    JsonSet(result.get(), "module", JsonString(moduleName));
    JsonSet(result.get(), "symbols", std::move(values));
    JsonSet(result.get(), "count", JsonInteger(context.accepted));
    JsonSet(result.get(), "limit", JsonInteger(limit));
    JsonSet(result.get(), "truncated", JsonBoolean(context.accepted >= limit));
    return Outcome::Success(std::move(result));
}

Outcome ResolveSymbol(const json_t* params)
{
    auto ready = RequireDebugging();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::string expression;
    if(!ReadString(params, "expression", expression, error, true, 512))
        return error;
    if(HasUnsafeCommandText(expression)
       || expression.find_first_of(";|&") != std::string::npos)
        return InvalidField("expression", "expression contains unsupported characters");

    const auto value = DbgValFromString(expression.c_str());
    SYMBOLINFO info = {};
    const auto hasInfo = DbgGetSymbolInfoAt(value, &info);
    auto freeDecorated = info.freeDecorated;
    auto freeUndecorated = info.freeUndecorated;
    auto decorated = info.decoratedSymbol;
    auto undecorated = info.undecoratedSymbol;
    auto release = [&]()
    {
        if(freeDecorated && decorated != nullptr)
            BridgeFree(decorated);
        if(freeUndecorated && undecorated != nullptr)
            BridgeFree(undecorated);
    };

    auto result = JsonObject();
    JsonSet(result.get(), "expression", JsonString(expression));
    JsonSet(result.get(), "value", AddressValue(value));
    JsonSet(result.get(), "resolved", JsonBoolean(value != 0 || expression == "0" || expression == "0x0"));
    if(hasInfo)
    {
        std::string name;
        if(undecorated != nullptr && undecorated[0] != '\0')
            name = undecorated;
        else if(decorated != nullptr && decorated[0] != '\0')
            name = decorated;
        JsonSet(result.get(), "symbol", JsonString(name));
        JsonSet(result.get(), "symbol_address", AddressValue(info.addr));
        JsonSet(result.get(), "symbol_type", JsonInteger(static_cast<std::uint64_t>(info.type)));
        JsonSet(result.get(), "ordinal", JsonInteger(info.ordinal));
    }
    release();
    return Outcome::Success(std::move(result));
}

bool ParseHardwareType(const std::string& text, char& typeChar, Outcome& error)
{
    std::string normalized = text;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch)
    {
        return static_cast<char>(std::tolower(ch));
    });
    if(normalized == "r" || normalized == "rw" || normalized == "access")
    {
        typeChar = 'r';
        return true;
    }
    if(normalized == "w" || normalized == "write")
    {
        typeChar = 'w';
        return true;
    }
    if(normalized == "x" || normalized == "execute")
    {
        typeChar = 'x';
        return true;
    }
    error = InvalidField("type", "type must be one of r|w|x");
    return false;
}

bool ParseHardwareSize(std::uint64_t size, Outcome& error)
{
    switch(size)
    {
    case 1:
    case 2:
    case 4:
#ifdef _WIN64
    case 8:
#endif
        return true;
    default:
        error = InvalidField("size", "size must be one of 1|2|4|8 for this architecture");
        return false;
    }
}

Outcome SetHardwareBreakpointRpc(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;
    std::string typeText = "x";
    auto typeItem = Param(params, "type");
    if(typeItem != nullptr)
    {
        if(!ReadString(params, "type", typeText, error, true, 16))
            return error;
    }
    char typeChar = 'x';
    if(!ParseHardwareType(typeText, typeChar, error))
        return error;

    std::uint64_t size = 1;
    bool sizePresent = false;
    if(!ReadOptionalUnsigned(params, "size", size, error, 8, sizePresent))
        return error;
    if(!ParseHardwareSize(size, error))
        return error;
    if((address % size) != 0)
        return InvalidField("address", "address must be aligned to size");

    char command[160] = {};
    sprintf_s(
        command,
        "SetHardwareBreakpoint %s, %c, %llu",
        HexAddress(static_cast<duint>(address)).c_str(),
        typeChar,
        static_cast<unsigned long long>(size));
    if(!DbgCmdExecDirect(command))
        return CommandFailure("breakpoints.hardware.set", command);

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "type", JsonString(std::string(1, typeChar)));
    JsonSet(result.get(), "size", JsonInteger(size));
    JsonSet(result.get(), "set", JsonBoolean(true));
    return Outcome::Success(std::move(result));
}

Outcome RemoveHardwareBreakpointRpc(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;
    auto command = std::string("DeleteHardwareBreakpoint ") + HexAddress(static_cast<duint>(address));
    if(!DbgCmdExecDirect(command.c_str()))
        return CommandFailure("breakpoints.hardware.remove", command.c_str());

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "removed", JsonBoolean(true));
    return Outcome::Success(std::move(result));
}

Outcome ListHardwareBreakpoints()
{
    return ListBreakpointsFiltered(bp_hardware, "breakpoints");
}

bool ParseMemoryBreakpointType(const std::string& text, char& typeChar, Outcome& error)
{
    std::string normalized = text;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch)
    {
        return static_cast<char>(std::tolower(ch));
    });
    if(normalized == "a" || normalized == "access" || normalized == "rwx")
    {
        typeChar = 'a';
        return true;
    }
    if(normalized == "r" || normalized == "read")
    {
        typeChar = 'r';
        return true;
    }
    if(normalized == "w" || normalized == "write")
    {
        typeChar = 'w';
        return true;
    }
    if(normalized == "x" || normalized == "execute")
    {
        typeChar = 'x';
        return true;
    }
    error = InvalidField("type", "type must be one of a|r|w|x");
    return false;
}

Outcome SetMemoryBreakpointRpc(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;
    std::string typeText = "a";
    auto typeItem = Param(params, "type");
    if(typeItem != nullptr)
    {
        if(!ReadString(params, "type", typeText, error, true, 16))
            return error;
    }
    char typeChar = 'a';
    if(!ParseMemoryBreakpointType(typeText, typeChar, error))
        return error;

    char command[160] = {};
    sprintf_s(
        command,
        "SetMemoryBPX %s, 0, %c",
        HexAddress(static_cast<duint>(address)).c_str(),
        typeChar);
    if(!DbgCmdExecDirect(command))
        return CommandFailure("breakpoints.memory.set", command);

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "type", JsonString(std::string(1, typeChar)));
    JsonSet(result.get(), "set", JsonBoolean(true));
    return Outcome::Success(std::move(result));
}

Outcome RemoveMemoryBreakpointRpc(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;
    auto command = std::string("DeleteMemoryBPX ") + HexAddress(static_cast<duint>(address));
    if(!DbgCmdExecDirect(command.c_str()))
        return CommandFailure("breakpoints.memory.remove", command.c_str());

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "removed", JsonBoolean(true));
    return Outcome::Success(std::move(result));
}

Outcome ListMemoryBreakpoints()
{
    return ListBreakpointsFiltered(bp_memory, "breakpoints");
}

bool SanitizeConditionExpression(const std::string& expression, Outcome& error)
{
    if(expression.size() > MaxConditionExprBytes)
    {
        error = InvalidField("expression", "expression exceeds 512 bytes");
        return false;
    }
    if(expression.find_first_of(";|&\n\r\"\\") != std::string::npos)
    {
        error = InvalidField("expression", "expression contains unsupported characters (;|&\\n\\\"\\\\)");
        return false;
    }
    return true;
}

bool LookupBridgeBreakpoint(duint address, BRIDGEBP& breakpoint, BPXTYPE& type)
{
    const auto functions = DbgFunctions();
    const BPXTYPE candidates[] = {bp_normal, bp_hardware, bp_memory};
    for(const auto candidate : candidates)
    {
        BRIDGEBP current = {};
        if(functions->GetBridgeBp(candidate, address, &current))
        {
            breakpoint = current;
            type = candidate;
            return true;
        }
    }
    return false;
}

const char* ConditionCommandForType(BPXTYPE type)
{
    switch(type)
    {
    case bp_hardware:
        return "SetHardwareBreakpointCondition";
    case bp_memory:
        return "SetMemoryBreakpointCondition";
    case bp_normal:
    default:
        return "SetBreakpointCondition";
    }
}

Outcome SetBreakpointConditionRpc(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;
    std::string expression;
    if(!ReadString(params, "expression", expression, error, true, MaxConditionExprBytes))
        return error;
    if(!SanitizeConditionExpression(expression, error))
        return error;

    BRIDGEBP breakpoint = {};
    BPXTYPE type = bp_none;
    if(!LookupBridgeBreakpoint(static_cast<duint>(address), breakpoint, type))
        return Outcome::Failure("breakpoint_not_found", "no breakpoint exists at the requested address");

    auto command = std::string(ConditionCommandForType(type)) + " "
        + HexAddress(static_cast<duint>(address)) + ", \"" + expression + "\"";
    if(!DbgCmdExecDirect(command.c_str()))
        return CommandFailure("breakpoints.condition.set", command.c_str());

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "type", JsonString(BreakpointTypeName(type)));
    JsonSet(result.get(), "expression", JsonString(expression));
    return Outcome::Success(std::move(result));
}

Outcome GetBreakpointConditionRpc(const json_t* params)
{
    auto ready = RequireDebugging();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;

    BRIDGEBP breakpoint = {};
    BPXTYPE type = bp_none;
    if(!LookupBridgeBreakpoint(static_cast<duint>(address), breakpoint, type))
        return Outcome::Failure("breakpoint_not_found", "no breakpoint exists at the requested address");

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "type", JsonString(BreakpointTypeName(type)));
    JsonSet(result.get(), "expression", JsonString(breakpoint.breakCondition));
    return Outcome::Success(std::move(result));
}

Outcome ListPatches()
{
    auto ready = RequireDebugging();
    if(!ready.ok)
        return ready;

    const auto functions = DbgFunctions();
    size_t bytes = 0;
    if(!functions->PatchEnum(nullptr, &bytes))
        return Outcome::Failure("patch_enum_failed", "x64dbg could not enumerate patches");
    const auto count = bytes / sizeof(DBGPATCHINFO);
    std::vector<DBGPATCHINFO> patches(count);
    if(count != 0 && !functions->PatchEnum(patches.data(), &bytes))
        return Outcome::Failure("patch_enum_failed", "x64dbg could not read patch entries");

    auto values = JsonArray();
    for(const auto& patch : patches)
    {
        auto value = JsonObject();
        JsonSet(value.get(), "address", AddressValue(patch.addr));
        JsonSet(value.get(), "module", JsonString(patch.mod));
        JsonSet(value.get(), "old_byte", JsonInteger(patch.oldbyte));
        JsonSet(value.get(), "new_byte", JsonInteger(patch.newbyte));
        JsonAppend(values.get(), std::move(value));
    }

    auto result = JsonObject();
    JsonSet(result.get(), "patches", std::move(values));
    JsonSet(result.get(), "count", JsonInteger(static_cast<std::uint64_t>(patches.size())));
    return Outcome::Success(std::move(result));
}

Outcome ApplyPatch(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;
    std::string encoded;
    if(!ReadString(params, "data", encoded, error, true, 512))
        return error;
    std::vector<unsigned char> bytes;
    if(!DecodeHex(encoded, bytes) || bytes.empty() || bytes.size() > 256)
        return InvalidField("data", "data must be 1..256 hexadecimal bytes");

    const auto functions = DbgFunctions();
    if(!functions->MemPatch(static_cast<duint>(address), bytes.data(), static_cast<duint>(bytes.size())))
        return Outcome::Failure("patch_apply_failed", "x64dbg could not apply the memory patch");

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "size", JsonInteger(bytes.size()));
    JsonSet(result.get(), "applied", JsonBoolean(true));
    return Outcome::Success(std::move(result));
}

Outcome RestorePatch(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;

    const auto functions = DbgFunctions();
    if(!functions->PatchRestore(static_cast<duint>(address)))
        return Outcome::Failure("patch_restore_failed", "x64dbg could not restore the patch");

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "restored", JsonBoolean(true));
    return Outcome::Success(std::move(result));
}

struct TraceQuotaState
{
    bool initialized = false;
    bool active = false;
    bool cancel_requested = false;
    std::string path;
    std::uint64_t max_events = 0;
    std::uint64_t timeout_ms = 0;
    std::uint64_t max_file_bytes = 0;
    std::uint64_t available_disk_bytes_at_start = 0;
    ULONGLONG started_tick = 0;
    std::string terminal_reason = "not_started";
};

TraceQuotaState& TraceState()
{
    static TraceQuotaState state;
    return state;
}

struct TraceTelemetry
{
    bool recording = false;
    std::uint64_t events_written = 0;
    std::uint64_t file_bytes = 0;
    std::uint64_t stop_reason = 0;
};

bool ReadTraceExpression(const char* expression, std::uint64_t& value)
{
    const auto functions = DbgFunctions();
    if(functions == nullptr || functions->ValFromString == nullptr)
        return false;
    duint raw = 0;
    if(!functions->ValFromString(expression, &raw))
        return false;
    value = static_cast<std::uint64_t>(raw);
    return true;
}

bool ReadTraceTelemetry(TraceTelemetry& telemetry)
{
    std::uint64_t recording = 0;
    if(!ReadTraceExpression("tr.runtraceenabled()", recording)
       || !ReadTraceExpression("tr.runtracecount()", telemetry.events_written)
       || !ReadTraceExpression("tr.runtracefilesize()", telemetry.file_bytes)
       || !ReadTraceExpression("tr.runtracestopreason()", telemetry.stop_reason))
        return false;
    telemetry.recording = recording != 0;
    return true;
}

bool ReadFileSize(const std::string& path, std::uint64_t& size)
{
    const auto widePath = Utf8ToWide(path);
    if(widePath.empty())
        return false;
    WIN32_FILE_ATTRIBUTE_DATA attributes = {};
    if(!GetFileAttributesExW(widePath.c_str(), GetFileExInfoStandard, &attributes))
        return false;
    ULARGE_INTEGER combined = {};
    combined.HighPart = attributes.nFileSizeHigh;
    combined.LowPart = attributes.nFileSizeLow;
    size = combined.QuadPart;
    return true;
}

bool AvailableDiskBytes(const std::string& path, std::uint64_t& available)
{
    const auto widePath = Utf8ToWide(path);
    if(widePath.empty())
        return false;
    const auto separator = widePath.find_last_of(L"\\/");
    if(separator == std::wstring::npos)
        return false;
    const auto directory = widePath.substr(0, separator + 1);
    ULARGE_INTEGER availableToCaller = {};
    if(!GetDiskFreeSpaceExW(directory.c_str(), &availableToCaller, nullptr, nullptr))
        return false;
    available = availableToCaller.QuadPart;
    return true;
}

const char* TraceStopReasonName(std::uint64_t reason)
{
    switch(reason)
    {
    case 0:
        return "none";
    case 1:
        return "cancelled";
    case 2:
        return "max_events";
    case 3:
        return "timeout";
    case 4:
        return "max_file_bytes";
    case 5:
        return "write_error";
    case 6:
        return "target_exited";
    default:
        return "unknown";
    }
}

bool IsTraceRecordingActive()
{
    TraceTelemetry telemetry;
    if(ReadTraceTelemetry(telemetry))
        return telemetry.recording;
    // This fallback is used only to decide whether a best-effort stop is
    // needed. StartTrace fails closed if the quota telemetry is unavailable.
    return TraceState().active;
}

Outcome TraceResult(bool enforceQuotas)
{
    auto& state = TraceState();
    if(!state.initialized)
    {
        auto result = JsonObject();
        JsonSet(result.get(), "recording", JsonBoolean(false));
        JsonSet(result.get(), "initialized", JsonBoolean(false));
        JsonSet(result.get(), "stop_reason", JsonString("not_started"));
        return Outcome::Success(std::move(result));
    }
    TraceTelemetry telemetry;
    if(!ReadTraceTelemetry(telemetry))
    {
        state.active = false;
        state.terminal_reason = "telemetry_unavailable";
        auto details = JsonObject();
        JsonSet(details.get(), "path", JsonString(state.path));
        return Outcome::Failure(
            "trace_telemetry_unavailable",
            "run-trace quota telemetry is unavailable; trace state is not trusted",
            false,
            std::move(details));
    }

    const auto elapsed = state.started_tick == 0 ? 0 : GetTickCount64() - state.started_tick;
    std::uint64_t actualFileBytes = telemetry.file_bytes;
    std::uint64_t diskFileBytes = 0;
    if(state.initialized && ReadFileSize(state.path, diskFileBytes))
        actualFileBytes = (std::max)(actualFileBytes, diskFileBytes);

    const auto deadlineReached = state.timeout_ms != 0 && elapsed >= state.timeout_ms;
    const auto eventLimitReached =
        state.max_events != 0 && telemetry.events_written >= state.max_events;
    const auto fileLimitReached =
        state.max_file_bytes != 0 && actualFileBytes >= state.max_file_bytes;
    if(enforceQuotas && telemetry.recording
       && (deadlineReached || eventLimitReached || fileLimitReached))
    {
        // StopTraceRecording flushes the pending one-instruction-late record.
        // The patched TraceRecord writer checks all quotas before that flush,
        // so it cannot push the artifact beyond the requested boundary.
        if(!DbgCmdExecDirect("StopTraceRecording"))
            return CommandFailure("trace.status", "StopTraceRecording");
        if(!ReadTraceTelemetry(telemetry))
            return Outcome::Failure(
                "trace_telemetry_unavailable",
                "run-trace telemetry disappeared after quota enforcement");
        actualFileBytes = telemetry.file_bytes;
        if(ReadFileSize(state.path, diskFileBytes))
            actualFileBytes = (std::max)(actualFileBytes, diskFileBytes);
    }

    auto reasonCode = telemetry.stop_reason;
    std::string reason = TraceStopReasonName(reasonCode);
    if(!telemetry.recording && !state.active && state.terminal_reason != "none")
    {
        // Terminal reasons are latched. x64dbg cleanup historically replaced
        // target-exit with the generic manual reason, and repeated status calls
        // must not turn a previously observed exit/quota failure into cancel.
        reason = state.terminal_reason;
    }
    else if(!telemetry.recording && state.active && !DbgIsDebugging()
       && (reasonCode == 0 || reasonCode == 1))
    {
        reason = "target_exited";
    }
    else if(!telemetry.recording && state.cancel_requested && reasonCode == 1)
    {
        reason = "cancelled";
    }
    else if(!telemetry.recording && reasonCode == 0 && state.initialized)
    {
        reason = state.terminal_reason == "not_started" ? "stopped" : state.terminal_reason;
    }

    if(!telemetry.recording)
    {
        state.active = false;
        state.terminal_reason = reason;
    }

    const auto quotaStopped = reasonCode >= 2 && reasonCode <= 4;
    const auto failed = reasonCode == 5 || reason == "telemetry_unavailable";
    const auto quotaViolation =
        (state.max_events != 0 && telemetry.events_written > state.max_events)
        || (state.max_file_bytes != 0 && actualFileBytes > state.max_file_bytes);

    auto result = JsonObject();
    JsonSet(result.get(), "initialized", JsonBoolean(state.initialized));
    JsonSet(result.get(), "recording", JsonBoolean(telemetry.recording));
    JsonSet(result.get(), "terminal", JsonBoolean(state.initialized && !telemetry.recording));
    JsonSet(result.get(), "path", JsonString(state.path));
    JsonSet(result.get(), "max_events", JsonInteger(state.max_events));
    JsonSet(result.get(), "timeout_ms", JsonInteger(state.timeout_ms));
    JsonSet(result.get(), "max_file_bytes", JsonInteger(state.max_file_bytes));
    JsonSet(result.get(), "events_written", JsonInteger(telemetry.events_written));
    JsonSet(result.get(), "file_bytes", JsonInteger(actualFileBytes));
    JsonSet(result.get(), "elapsed_ms", JsonInteger(elapsed));
    JsonSet(result.get(), "stop_reason_code", JsonInteger(reasonCode));
    JsonSet(result.get(), "stop_reason", JsonString(reason));
    JsonSet(result.get(), "quota_stopped", JsonBoolean(quotaStopped));
    JsonSet(result.get(), "quota_violation", JsonBoolean(quotaViolation));
    JsonSet(result.get(), "failed", JsonBoolean(failed || quotaViolation));
    JsonSet(result.get(), "target_active", JsonBoolean(DbgIsDebugging()));
    JsonSet(result.get(), "timeout_exceeded", JsonBoolean(deadlineReached));
    JsonSet(
        result.get(),
        "available_disk_bytes_at_start",
        JsonInteger(state.available_disk_bytes_at_start));
    return Outcome::Success(std::move(result));
}

Outcome StartTrace(const json_t* params)
{
    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::string path;
    if(!ReadString(params, "path", path, error, true, 32767))
        return error;
    if(!IsAbsoluteWindowsPath(path) || PathContainsDotDot(path)
       || HasUnsafeCommandText(path) || path.find('\0') != std::string::npos)
        return InvalidField(
            "path",
            "path must be an absolute Windows path without '..', quotes, or line breaks");

    std::uint64_t maxEvents = 10000;
    bool maxEventsPresent = false;
    if(!ReadOptionalUnsigned(params, "max_events", maxEvents, error, MaxTraceEvents, maxEventsPresent))
        return error;
    if(maxEvents == 0)
        return InvalidField("max_events", "max_events must be positive");

    std::uint64_t timeoutMs = 60000;
    bool timeoutPresent = false;
    if(!ReadOptionalUnsigned(params, "timeout_ms", timeoutMs, error, MaxTraceTimeoutMs, timeoutPresent))
        return error;
    if(timeoutMs == 0)
        return InvalidField("timeout_ms", "timeout_ms must be positive");

    std::uint64_t maxFileBytes = 16ULL * 1024ULL * 1024ULL;
    bool maxFilePresent = false;
    if(!ReadOptionalUnsigned(
           params, "max_file_bytes", maxFileBytes, error, MaxTraceFileBytes, maxFilePresent))
        return error;
    if(maxFileBytes == 0)
        return InvalidField("max_file_bytes", "max_file_bytes must be positive");

    if(IsTraceRecordingActive())
        return Outcome::Failure("already_tracing", "stop the active trace before starting another");

    const auto widePath = Utf8ToWide(path);
    if(widePath.empty())
        return InvalidField("path", "path must be valid UTF-8");
    WIN32_FILE_ATTRIBUTE_DATA attributes = {};
    if(GetFileAttributesExW(widePath.c_str(), GetFileExInfoStandard, &attributes))
    {
        ULARGE_INTEGER existingSize = {};
        existingSize.HighPart = attributes.nFileSizeHigh;
        existingSize.LowPart = attributes.nFileSizeLow;
        if((attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
           || existingSize.QuadPart != 0)
        {
            return InvalidField(
                "path",
                "trace path must be a new file or an existing empty file");
        }
    }
    else if(GetLastError() != ERROR_FILE_NOT_FOUND)
    {
        auto details = JsonObject();
        JsonSet(details.get(), "path", JsonString(path));
        JsonSet(details.get(), "win32_error", JsonInteger(GetLastError()));
        return Outcome::Failure(
            "trace_path_unavailable",
            "trace path could not be inspected before recording",
            false,
            std::move(details));
    }

    std::uint64_t availableDiskBytes = 0;
    if(!AvailableDiskBytes(path, availableDiskBytes))
    {
        auto details = JsonObject();
        JsonSet(details.get(), "path", JsonString(path));
        JsonSet(details.get(), "win32_error", JsonInteger(GetLastError()));
        return Outcome::Failure(
            "disk_quota_check_failed",
            "available disk space could not be verified for the trace artifact",
            false,
            std::move(details));
    }
    if(availableDiskBytes < maxFileBytes)
    {
        auto details = JsonObject();
        JsonSet(details.get(), "available_disk_bytes", JsonInteger(availableDiskBytes));
        JsonSet(details.get(), "required_disk_bytes", JsonInteger(maxFileBytes));
        return Outcome::Failure(
            "insufficient_disk_space",
            "available disk space is smaller than the requested trace file quota",
            true,
            std::move(details));
    }

    auto command = std::string("StartTraceRecording \"") + path + "\", "
        + std::to_string(maxEvents) + ", " + std::to_string(timeoutMs) + ", "
        + std::to_string(maxFileBytes);
    if(!DbgCmdExecDirect(command.c_str()))
        return CommandFailure("trace.start", "StartTraceRecording");

    TraceTelemetry telemetry;
    if(!ReadTraceTelemetry(telemetry) || !telemetry.recording)
    {
        DbgCmdExecDirect("StopTraceRecording");
        auto details = JsonObject();
        JsonSet(details.get(), "path", JsonString(path));
        JsonSet(details.get(), "quota_command", JsonString(command));
        return Outcome::Failure(
            "trace_quota_unavailable",
            "x64dbg did not expose active run-trace quota telemetry after start",
            false,
            std::move(details));
    }

    auto& state = TraceState();
    state.initialized = true;
    state.active = true;
    state.cancel_requested = false;
    state.path = path;
    state.max_events = maxEvents;
    state.timeout_ms = timeoutMs;
    state.max_file_bytes = maxFileBytes;
    state.available_disk_bytes_at_start = availableDiskBytes;
    state.started_tick = GetTickCount64();
    state.terminal_reason = "none";
    return TraceResult(false);
}

Outcome StopTrace()
{
    auto& state = TraceState();
    state.cancel_requested = true;
    if(IsTraceRecordingActive() && !DbgCmdExecDirect("StopTraceRecording"))
        return CommandFailure("trace.stop", "StopTraceRecording");
    return TraceResult(false);
}

Outcome TraceStatus()
{
    return TraceResult(true);
}

bool IsAllowedPageRights(const std::string& rights)
{
    static const std::set<std::string> allowed = {
        "Execute",
        "ExecuteRead",
        "ExecuteReadWrite",
        "ExecuteWriteCopy",
        "NoAccess",
        "ReadOnly",
        "ReadWrite",
        "WriteCopy",
        "GExecute",
        "GExecuteRead",
        "GExecuteReadWrite",
        "GExecuteWriteCopy",
        "GNoAccess",
        "GReadOnly",
        "GReadWrite",
        "GWriteCopy",
    };
    return allowed.find(rights) != allowed.end();
}

Outcome MemoryProtection(const json_t* params)
{
    auto rightsItem = Param(params, "rights");
    if(rightsItem == nullptr)
        return QueryMemoryProtect(params);

    auto ready = RequirePaused();
    if(!ready.ok)
        return ready;

    Outcome error;
    std::uint64_t address = 0;
    if(!ReadUnsigned(params, "address", address, error, std::numeric_limits<duint>::max()))
        return error;
    std::string rights;
    if(!ReadString(params, "rights", rights, error, true, 32))
        return error;
    if(!IsAllowedPageRights(rights))
        return InvalidField("rights", "rights string is not in the allowlist");

    const auto functions = DbgFunctions();
    if(!functions->SetPageRights(static_cast<duint>(address), rights.c_str()))
        return Outcome::Failure("memory_protect_set_failed", "x64dbg rejected SetPageRights");

    functions->MemUpdateMap();
    char current[16] = {};
    if(functions->GetPageRights != nullptr)
        functions->GetPageRights(static_cast<duint>(address), current);

    auto result = JsonObject();
    JsonSet(result.get(), "address", JsonInteger(address));
    JsonSet(result.get(), "rights", JsonString(rights));
    JsonSet(result.get(), "rights_now", JsonString(current));
    JsonSet(result.get(), "set", JsonBoolean(true));
    return Outcome::Success(std::move(result));
}

} // namespace

bool IsDebuggerMethod(const std::string& method)
{
    return std::find(
               std::begin(DebuggerMethods), std::end(DebuggerMethods), method)
        != std::end(DebuggerMethods);
}

JsonPtr BuildDebuggerState()
{
    auto result = JsonObject();
    auto debugging = DbgIsDebugging();
    auto running = debugging && DbgIsRunning();
    JsonSet(result.get(), "debugging", JsonBoolean(debugging));
    JsonSet(result.get(), "running", JsonBoolean(running));
    JsonSet(
        result.get(),
        "state",
        JsonString(!debugging ? "idle" : (running ? "running" : "paused")));
    JsonSet(result.get(), "process_id", JsonInteger(debugging ? DbgGetProcessId() : 0));
    JsonSet(result.get(), "thread_id", JsonInteger(debugging ? DbgGetThreadId() : 0));
    return result;
}

Outcome DispatchDebuggerMethod(const std::string& method, const json_t* params)
{
    if(method == "debug.state")
        return Outcome::Success(BuildDebuggerState());
    if(method == "debug.launch")
        return Launch(params);
    if(method == "debug.attach")
        return Attach(params);
    if(method == "debug.stop")
        return RunControlCommand(method.c_str(), "StopDebug", false);
    if(method == "debug.pause")
        return PauseDebuggee();
    if(method == "debug.resume")
        return RunControlCommand(method.c_str(), "run", true);
    if(method == "debug.step_into")
        return RunControlCommand(method.c_str(), "StepInto", true);
    if(method == "debug.step_over")
        return RunControlCommand(method.c_str(), "StepOver", true);
    if(method == "registers.read")
        return ReadRegisters();
    if(method == "registers.write")
        return WriteRegister(params);
    if(method == "memory.read")
        return ReadMemory(params);
    if(method == "memory.write")
        return WriteMemory(params);
    if(method == "memory.regions")
        return ListMemoryRegions(params);
    if(method == "memory.protect.query")
        return QueryMemoryProtect(params);
    if(method == "memory.protection")
        return MemoryProtection(params);
    if(method == "modules.list")
        return ListModules();
    if(method == "modules.dump")
        return DumpModule(params);
    if(method == "pe.headers.runtime")
        return ReadPeHeadersRuntime(params);
    if(method == "imports.scan")
        return ScanImports(params);
    if(method == "imports.read")
        return ReadImports(params);
    if(method == "imports.rebuild")
        return RebuildImports(params);
    if(method == "threads.list")
        return ListThreads();
    if(method == "threads.current")
        return CurrentThread();
    if(method == "threads.context.read")
        return ReadThreadContext(params);
    if(method == "threads.context.write")
        return WriteThreadContext(params);
    if(method == "stack.read")
        return ReadStack(params);
    if(method == "stack.trace")
        return TraceStack(params);
    if(method == "disassembly.read")
        return ReadDisassembly(params);
    if(method == "symbols.list")
        return ListSymbols(params);
    if(method == "symbols.resolve")
        return ResolveSymbol(params);
    if(method == "breakpoints.list")
        return ListBreakpoints();
    if(method == "breakpoints.set")
        return ChangeBreakpoint(params, true);
    if(method == "breakpoints.remove")
        return ChangeBreakpoint(params, false);
    if(method == "breakpoints.hardware.set")
        return SetHardwareBreakpointRpc(params);
    if(method == "breakpoints.hardware.remove")
        return RemoveHardwareBreakpointRpc(params);
    if(method == "breakpoints.hardware.list")
        return ListHardwareBreakpoints();
    if(method == "breakpoints.memory.set")
        return SetMemoryBreakpointRpc(params);
    if(method == "breakpoints.memory.remove")
        return RemoveMemoryBreakpointRpc(params);
    if(method == "breakpoints.memory.list")
        return ListMemoryBreakpoints();
    if(method == "breakpoints.condition.set")
        return SetBreakpointConditionRpc(params);
    if(method == "breakpoints.condition.get")
        return GetBreakpointConditionRpc(params);
    if(method == "patches.list")
        return ListPatches();
    if(method == "patches.apply")
        return ApplyPatch(params);
    if(method == "patches.restore")
        return RestorePatch(params);
    if(method == "trace.start")
        return StartTrace(params);
    if(method == "trace.stop")
        return StopTrace();
    if(method == "trace.status")
        return TraceStatus();
    return Outcome::Failure("method_not_found", "unknown debugger method");
}

} // namespace headless_re_rpc

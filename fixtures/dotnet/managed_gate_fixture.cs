/*
 * Source for managed_gate.exe, the real .NET assembly the dotnet read gate
 * (tests/integration/test_dotnet_read_gate.py) analyses. Unlike
 * minimal_clr_hint.exe next to it -- a deliberately unverifiable stub used only
 * to prove dotnet.inspect refuses it -- this is a genuine, verifiable ECMA-335
 * assembly with recoverable types, methods, fields, IL and MemberRefs.
 *
 * Rebuild it with the Mono C# compiler (produces a stable, tool-independent
 * assembly the pure-Python reader can parse on Linux with no .NET runtime):
 *
 *   mcs -optimize- -debug- -target:exe \
 *       -out:fixtures/dotnet/managed_gate.exe \
 *       fixtures/dotnet/managed_gate_fixture.cs
 *
 * It is shaped so every dotnet.* read has something real to recover:
 *   - a namespaced type HeadlessRe.DotnetGate.GateFixture (dotnet.enumerate types),
 *   - methods GetMarker / ComputeChecksum / Announce / Main (dotnet.enumerate methods),
 *   - a static field Marker (dotnet.enumerate fields),
 *   - GetMarker's body is `ldstr <marker>; ret` (dotnet.il opcode subset),
 *   - ComputeChecksum has a loop, so its IL carries branch + arithmetic opcodes,
 *   - Announce calls System.Console.WriteLine, a MemberRef (dotnet.xrefs).
 */
using System;

namespace HeadlessRe.DotnetGate
{
    public class GateFixture
    {
        public static readonly string Marker = "headless-re dotnet gate fixture";

        public static string GetMarker()
        {
            return "headless-re dotnet gate fixture";
        }

        public static int ComputeChecksum(string text)
        {
            int sum = 0;
            for (int index = 0; index < text.Length; index++)
            {
                sum = (sum * 31) + (int)text[index];
            }
            return sum;
        }

        public static void Announce()
        {
            Console.WriteLine(GetMarker());
        }

        public static int Main()
        {
            Announce();
            return ComputeChecksum(GetMarker());
        }
    }
}

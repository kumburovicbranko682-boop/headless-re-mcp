using System;

namespace GateFixture
{
    public static class Calculator
    {
        public static readonly int Version = 7;
        private static int _lastResult;

        public static int Add(int a, int b)
        {
            _lastResult = a + b;
            return _lastResult;
        }

        public static int LastResult()
        {
            return _lastResult;
        }
    }

    public static class Program
    {
        public static void Main()
        {
            int total = Calculator.Add(40, 2);
            Console.WriteLine("H3adl3ss-managed:" + total);
        }
    }
}

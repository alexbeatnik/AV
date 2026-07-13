// Minimal zero-dependency test runner, in the spirit of the project: no NuGet,
// no MSTest/xUnit — compiled by the same built-in csc.exe together with src\*.cs
// into AVUI.Tests.exe (see test.ps1). Discovers every public static method
// named Test* in every class named *Tests, runs them all, and exits non-zero if
// anything failed — which is what the CI workflow keys off.
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace AVUI.Tests
{
    static class Program
    {
        static int Main()
        {
            int passed = 0;
            var failures = new List<string>();
            foreach (Type t in Assembly.GetExecutingAssembly().GetTypes())
            {
                if (!t.Name.EndsWith("Tests")) continue;
                foreach (MethodInfo m in t.GetMethods(BindingFlags.Public | BindingFlags.Static))
                {
                    if (!m.Name.StartsWith("Test") || m.GetParameters().Length != 0) continue;
                    string name = t.Name + "." + m.Name;
                    try
                    {
                        m.Invoke(null, null);
                        passed++;
                        Console.WriteLine("  ok  " + name);
                    }
                    catch (TargetInvocationException ex)
                    {
                        string msg = ex.InnerException != null ? ex.InnerException.Message : ex.Message;
                        failures.Add(name + ": " + msg);
                        Console.WriteLine("FAIL  " + name + ": " + msg);
                    }
                }
            }
            Console.WriteLine();
            Console.WriteLine(passed + " passed, " + failures.Count + " failed");
            return failures.Count == 0 ? 0 : 1;
        }
    }

    static class Assert
    {
        public static void True(bool condition, string message)
        {
            if (!condition) throw new Exception(message);
        }

        public static void False(bool condition, string message)
        {
            if (condition) throw new Exception(message);
        }

        public static void Equal(object expected, object actual, string message)
        {
            if (!object.Equals(expected, actual))
                throw new Exception(message + " — expected <" + expected + ">, got <" + actual + ">");
        }

        public static void Throws<T>(Action action, string message) where T : Exception
        {
            try { action(); }
            catch (T) { return; }
            catch (Exception ex)
            {
                throw new Exception(message + " — expected " + typeof(T).Name + ", got " + ex.GetType().Name);
            }
            throw new Exception(message + " — expected " + typeof(T).Name + ", nothing was thrown");
        }
    }

    // Per-test scratch folder that cleans up after itself
    sealed class TempDir : IDisposable
    {
        public readonly string Path;
        public TempDir()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
                "av-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }
        public string File(string name) { return System.IO.Path.Combine(Path, name); }
        public void Dispose()
        {
            try { Directory.Delete(Path, true); } catch { }
        }
    }
}

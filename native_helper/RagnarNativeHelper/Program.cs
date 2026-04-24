using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.Json;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    internal static readonly HashSet<string> SuspiciousTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "vssadmin.exe",
        "wbadmin.exe",
        "bcdedit.exe",
        "wevtutil.exe",
        "wmic.exe",
        "diskshadow.exe",
        "cipher.exe",
        "schtasks.exe",
        "reg.exe",
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe"
    };

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0)
            {
                return WriteError("missing command");
            }

            return args[0].ToLowerInvariant() switch
            {
                "watch" => RunWatch(),
                "suspend" => WithPid(args, SuspendProcessByPid),
                "resume" => WithPid(args, ResumeProcessByPid),
                "terminate" => WithPid(args, TerminateProcessByPid),
                "sandbox" => RunSandbox(args.Skip(1).ToArray()),
                _ => WriteError($"unknown command: {args[0]}")
            };
        }
        catch (Exception exc)
        {
            return WriteJson(new { success = false, error = exc.Message }, stderr: true);
        }
    }

    private static int RunWatch()
    {
        return RunPollingWatch();
    }

    private static int RunPollingWatch()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    seen.Add($"{process.Id}:{process.StartTime.ToUniversalTime().Ticks}");
                }
                catch
                {
                }
                finally
                {
                    process.Dispose();
                }
            }
        }
        catch
        {
        }
        using var exitEvent = new ManualResetEvent(false);
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            exitEvent.Set();
        };
        while (!exitEvent.WaitOne(150))
        {
            try
            {
                foreach (var process in Process.GetProcesses())
                {
                    try
                    {
                        var key = $"{process.Id}:{process.StartTime.ToUniversalTime().Ticks}";
                        if (!seen.Add(key))
                        {
                            continue;
                        }
                        var processName = process.ProcessName + ".exe";
                        EmitProcessEvent(process.Id, processName);
                    }
                    catch
                    {
                    }
                    finally
                    {
                        process.Dispose();
                    }
                }
            }
            catch
            {
            }
        }
        return 0;
    }

    private static void EmitProcessEvent(int processId, string processName)
    {
        var executablePath = ResolveExecutablePath(processId);
        if (string.IsNullOrWhiteSpace(executablePath) || !ShouldMonitorPath(executablePath))
        {
            return;
        }
        var suspended = TrySuspendProcessByPid(processId);
        var createdAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        WriteJson(new
        {
            @event = "process_started",
            pid = processId,
            processName,
            executablePath,
            suspended,
            createdAt
        });
    }

    private static int RunSandbox(string[] args)
    {
        var options = ParseArgs(args);
        if (!options.TryGetValue("path", out var samplePath) || string.IsNullOrWhiteSpace(samplePath))
        {
            return WriteError("sandbox requires --path");
        }

        if (!File.Exists(samplePath))
        {
            return WriteError($"sample not found: {samplePath}");
        }

        var mode = options.GetValueOrDefault("mode", "quick");
        var timeoutSeconds = int.TryParse(options.GetValueOrDefault("timeout", mode == "deep" ? "30" : "6"), out var parsedTimeout)
            ? parsedTimeout
            : (mode == "deep" ? 30 : 6);
        var resultsRoot = options.GetValueOrDefault("results", Path.Combine(Path.GetTempPath(), "ragnar-native-sandbox"));
        Directory.CreateDirectory(resultsRoot);
        var report = SandboxRunner.Run(samplePath, resultsRoot, timeoutSeconds, mode);
        return WriteJson(report);
    }

    private static int WithPid(string[] args, Func<int, int> action)
    {
        var options = ParseArgs(args.Skip(1).ToArray());
        if (!options.TryGetValue("pid", out var pidText) || !int.TryParse(pidText, out var pid))
        {
            return WriteError("command requires --pid");
        }
        return action(pid);
    }

    private static Dictionary<string, string> ParseArgs(string[] args)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index++)
        {
            var current = args[index];
            if (!current.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }
            var key = current[2..];
            var value = index + 1 < args.Length && !args[index + 1].StartsWith("--", StringComparison.Ordinal)
                ? args[++index]
                : "true";
            result[key] = value;
        }
        return result;
    }

    private static bool ShouldMonitorPath(string executablePath)
    {
        var normalized = executablePath.ToLowerInvariant();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).ToLowerInvariant();
        var tempPath = Path.GetTempPath().ToLowerInvariant();
        var allowedRoots = new[]
        {
            userProfile,
            tempPath
        };
        var extension = Path.GetExtension(normalized);
        if (extension is not ".exe" and not ".scr")
        {
            return false;
        }
        if (normalized.Contains("\\ragnarprotect\\") || normalized.EndsWith("\\ragnarnativehelper.exe", StringComparison.Ordinal))
        {
            return false;
        }
        return allowedRoots.Any(root => normalized.StartsWith(root, StringComparison.Ordinal));
    }

    private static string ResolveExecutablePath(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.MainModule?.FileName ?? "";
        }
        catch
        {
            try
            {
                using var searcher = new ManagementObjectSearcher($"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject process in searcher.Get())
                {
                    return Convert.ToString(process["ExecutablePath"] ?? "") ?? "";
                }
            }
            catch
            {
            }
        }
        return "";
    }

    private static int SuspendProcessByPid(int pid)
    {
        return TrySuspendProcessByPid(pid)
            ? WriteJson(new { success = true, pid, action = "suspend" })
            : WriteJson(new { success = false, pid, error = "suspend failed" }, stderr: true);
    }

    private static bool TrySuspendProcessByPid(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            foreach (ProcessThread thread in process.Threads)
            {
                var threadHandle = NativeMethods.OpenThread(NativeMethods.ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                if (threadHandle == IntPtr.Zero)
                {
                    continue;
                }
                try
                {
                    NativeMethods.SuspendThread(threadHandle);
                }
                finally
                {
                    NativeMethods.CloseHandle(threadHandle);
                }
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int ResumeProcessByPid(int pid)
    {
        return TryResumeProcessByPid(pid)
            ? WriteJson(new { success = true, pid, action = "resume" })
            : WriteJson(new { success = false, pid, error = "resume failed" }, stderr: true);
    }

    private static bool TryResumeProcessByPid(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            foreach (ProcessThread thread in process.Threads)
            {
                var threadHandle = NativeMethods.OpenThread(NativeMethods.ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                if (threadHandle == IntPtr.Zero)
                {
                    continue;
                }
                try
                {
                    while (NativeMethods.ResumeThread(threadHandle) > 0)
                    {
                    }
                }
                finally
                {
                    NativeMethods.CloseHandle(threadHandle);
                }
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int TerminateProcessByPid(int pid)
    {
        return TryTerminateProcessByPid(pid)
            ? WriteJson(new { success = true, pid, action = "terminate" })
            : WriteJson(new { success = false, pid, error = "terminate failed" }, stderr: true);
    }

    private static bool TryTerminateProcessByPid(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            process.Kill(entireProcessTree: true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int WriteError(string message) => WriteJson(new { success = false, error = message }, stderr: true);

    private static int WriteJson(object payload, bool stderr = false)
    {
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        if (stderr)
        {
            Console.Error.WriteLine(json);
            Console.Error.Flush();
        }
        else
        {
            Console.WriteLine(json);
            Console.Out.Flush();
        }
        return payload is { } && json.Contains("\"success\":false", StringComparison.Ordinal) ? 1 : 0;
    }
}

internal static class SandboxRunner
{
    public static object Run(string samplePath, string resultsRoot, int timeoutSeconds, string mode)
    {
        var sample = Path.GetFullPath(samplePath);
        var sampleName = Path.GetFileName(sample);
        var sessionRoot = Path.Combine(resultsRoot, $"{Path.GetFileNameWithoutExtension(sample)}_{Guid.NewGuid():N}");
        var workDir = Path.Combine(sessionRoot, "work");
        var logsDir = Path.Combine(sessionRoot, "logs");
        Directory.CreateDirectory(workDir);
        Directory.CreateDirectory(logsDir);
        var copiedSample = Path.Combine(workDir, sampleName);
        File.Copy(sample, copiedSample, overwrite: true);

        var runKeys = new[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        };
        var startupDirs = BuildStartupDirectories();
        var beforeRunKeys = SnapshotRunKeys(runKeys);
        var beforeStartup = SnapshotDirectories(startupDirs);
        var beforeWallpaper = ReadWallpaper();
        var beforeFiles = SnapshotDirectory(workDir);
        var monitoredDirs = BuildMonitoredDirectories(startupDirs);
        var beforeExternal = SnapshotDirectories(monitoredDirs);
        var observedProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var backend = "job-object-fallback";
        var firewallIsolation = ApplyFirewallIsolation(copiedSample);
        var launch = LaunchRestrictedOrFallback(copiedSample, workDir, mode);
        backend = firewallIsolation.Applied ? $"{launch.Backend}+firewall" : launch.Backend;
        var childCount = 0;
        var processStarted = launch.ProcessId > 0;
        string? launchError = launch.Error;
        var startedAt = DateTime.UtcNow;
        try
        {
            if (processStarted)
            {
                childCount = MonitorProcess(launch.ProcessId, timeoutSeconds, observedProcessNames);
            }
        }
        finally
        {
            launch.Dispose();
            RemoveFirewallIsolation(firewallIsolation);
        }
        var afterRunKeys = SnapshotRunKeys(runKeys);
        var afterStartup = SnapshotDirectories(startupDirs);
        var afterWallpaper = ReadWallpaper();
        var afterFiles = SnapshotDirectory(workDir);
        var afterExternal = SnapshotDirectories(monitoredDirs);
        var droppedFiles = afterFiles.Keys.Where(path => !beforeFiles.ContainsKey(path)).ToList();
        var droppedExecutables = droppedFiles.Where(path => IsExecutableLike(path)).ToList();
        var startupDrops = afterStartup.Keys.Where(path => !beforeStartup.ContainsKey(path)).ToList();
        var externalDrops = afterExternal.Keys.Where(path => !beforeExternal.ContainsKey(path)).ToList();
        var runKeyChanges = afterRunKeys.Except(beforeRunKeys, StringComparer.OrdinalIgnoreCase).ToList();
        var wallpaperChanged = !string.Equals(beforeWallpaper, afterWallpaper, StringComparison.OrdinalIgnoreCase);
        var destructiveToolSeen = observedProcessNames.Any(name => SuspiciousToolSeen(name));
        var verdict = "clean";
        if (launchError is not null)
        {
            verdict = "unknown";
        }
        else if (childCount > 0 || droppedExecutables.Count > 0 || startupDrops.Count > 0 || externalDrops.Count > 0 || runKeyChanges.Count > 0 || wallpaperChanged || destructiveToolSeen)
        {
            verdict = "malicious";
        }
        else if (droppedFiles.Count > 0 || observedProcessNames.Count > 1)
        {
            verdict = "suspicious";
        }

        var report = new
        {
            success = true,
            samplePath = sample,
            copiedSample,
            mode,
            backend,
            verdict,
            durationSeconds = (int)Math.Max(1, Math.Round((DateTime.UtcNow - startedAt).TotalSeconds)),
            processStarted,
            processId = launch.ProcessId,
            launchError,
            childCount,
            observedProcessNames = observedProcessNames.OrderBy(value => value).ToArray(),
            droppedFiles,
            droppedExecutableCount = droppedExecutables.Count,
            startupDropCount = startupDrops.Count,
            externalDropCount = externalDrops.Count,
            externalDrops,
            runKeyChangeCount = runKeyChanges.Count,
            wallpaperChanged,
            destructiveToolSeen,
            firewallIsolated = firewallIsolation.Applied,
            firewallRuleErrors = firewallIsolation.Errors,
            sessionRoot,
            workDir,
            logsDir,
            observedAt = DateTimeOffset.UtcNow.ToString("O")
        };

        var reportPath = Path.Combine(logsDir, "sandbox-report.json");
        File.WriteAllText(reportPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        return report;
    }

    private static LaunchContext LaunchRestrictedOrFallback(string copiedSample, string workDir, string mode)
    {
        var restricted = TryLaunchRestricted(copiedSample, workDir, mode);
        if (restricted.ProcessId > 0)
        {
            return restricted;
        }
        return TryLaunchWithJob(copiedSample, workDir, "job-object-fallback", mode, restricted.Error);
    }

    private static LaunchContext TryLaunchRestricted(string executablePath, string workDir, string mode)
    {
        try
        {
            if (!NativeMethods.OpenProcessToken(Process.GetCurrentProcess().Handle, NativeMethods.TokenAccess.TOKEN_ALL_ACCESS, out var currentToken))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            using var tokenHandle = new SafeHandleWrapper(currentToken);
            if (!NativeMethods.CreateRestrictedToken(currentToken, NativeMethods.DISABLE_MAX_PRIVILEGE, 0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out var restrictedToken))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            using var restrictedHandle = new SafeHandleWrapper(restrictedToken);
            return CreateProcessInJob(executablePath, workDir, restrictedToken, "restricted-token", mode);
        }
        catch (Exception exc)
        {
            return new LaunchContext { Error = exc.Message };
        }
    }

    private static LaunchContext TryLaunchWithJob(string executablePath, string workDir, string backend, string mode, string? priorError)
    {
        try
        {
            return CreateProcessInJob(executablePath, workDir, IntPtr.Zero, backend, mode, priorError);
        }
        catch (Exception exc)
        {
            return new LaunchContext { Error = exc.Message };
        }
    }

    private static LaunchContext CreateProcessInJob(string executablePath, string workDir, IntPtr token, string backend, string mode, string? priorError = null)
    {
        var startupInfo = new NativeMethods.STARTUPINFO();
        startupInfo.cb = Marshal.SizeOf<NativeMethods.STARTUPINFO>();
        startupInfo.dwFlags = NativeMethods.STARTF_USESHOWWINDOW;
        startupInfo.wShowWindow = 0;
        var processInfo = new NativeMethods.PROCESS_INFORMATION();
        var commandLine = $"\"{executablePath}\"";
        var created = token != IntPtr.Zero
            ? NativeMethods.CreateProcessAsUserW(token, null, commandLine, IntPtr.Zero, IntPtr.Zero, false, NativeMethods.CREATE_SUSPENDED | NativeMethods.CREATE_NO_WINDOW, IntPtr.Zero, workDir, ref startupInfo, out processInfo)
            : NativeMethods.CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, false, NativeMethods.CREATE_SUSPENDED | NativeMethods.CREATE_NO_WINDOW, IntPtr.Zero, workDir, ref startupInfo, out processInfo);
        if (!created)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var deepMode = string.Equals(mode, "deep", StringComparison.OrdinalIgnoreCase);
        var activeProcessLimit = deepMode ? 12u : 6u;
        var processMemoryLimit = deepMode ? 768UL * 1024 * 1024 : 384UL * 1024 * 1024;
        var job = NativeMethods.CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        var info = new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new NativeMethods.JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags = NativeMethods.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                    | NativeMethods.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                    | NativeMethods.JOB_OBJECT_LIMIT_PROCESS_MEMORY,
                ActiveProcessLimit = activeProcessLimit
            },
            ProcessMemoryLimit = (UIntPtr)processMemoryLimit
        };
        var length = Marshal.SizeOf<NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        var memory = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(info, memory, false);
            if (!NativeMethods.SetInformationJobObject(job, NativeMethods.JobObjectInfoType.ExtendedLimitInformation, memory, (uint)length))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(memory);
        }
        if (!NativeMethods.AssignProcessToJobObject(job, processInfo.hProcess))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        NativeMethods.ResumeThread(processInfo.hThread);
        return new LaunchContext
        {
            Backend = backend,
            ProcessId = (int)processInfo.dwProcessId,
            JobHandle = new SafeHandleWrapper(job),
            ProcessHandle = new SafeHandleWrapper(processInfo.hProcess),
            ThreadHandle = new SafeHandleWrapper(processInfo.hThread),
            Error = priorError
        };
    }

    private static int MonitorProcess(int processId, int timeoutSeconds, HashSet<string> observedProcessNames)
    {
        var deadline = DateTime.UtcNow.AddSeconds(Math.Max(3, timeoutSeconds));
        var observedChildren = new HashSet<int>();
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                observedProcessNames.Add(process.ProcessName + ".exe");
                foreach (var child in FindDescendants(processId))
                {
                    observedProcessNames.Add(child.ProcessName + ".exe");
                    observedChildren.Add(child.Id);
                    child.Dispose();
                }
                if (process.HasExited)
                {
                    break;
                }
            }
            catch
            {
                break;
            }
            Thread.Sleep(400);
        }
        foreach (var child in FindDescendants(processId))
        {
            observedChildren.Add(child.Id);
            child.Dispose();
        }
        return observedChildren.Count;
    }

    private static List<Process> FindDescendants(int parentPid)
    {
        var result = new List<Process>();
        var pending = new Queue<int>();
        var seen = new HashSet<int>();
        pending.Enqueue(parentPid);
        seen.Add(parentPid);
        while (pending.Count > 0)
        {
            var currentParent = pending.Dequeue();
            foreach (var child in FindDirectChildren(currentParent))
            {
                if (!seen.Add(child.Id))
                {
                    child.Dispose();
                    continue;
                }
                result.Add(child);
                pending.Enqueue(child.Id);
            }
        }
        return result;
    }

    private static List<Process> FindDirectChildren(int parentPid)
    {
        var result = new List<Process>();
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT ProcessId FROM Win32_Process WHERE ParentProcessId = {parentPid}");
            foreach (ManagementObject child in searcher.Get())
            {
                var pid = Convert.ToInt32(child["ProcessId"] ?? 0);
                if (pid <= 0)
                {
                    continue;
                }
                try
                {
                    result.Add(Process.GetProcessById(pid));
                }
                catch
                {
                }
            }
        }
        catch
        {
        }
        return result;
    }

    private static Dictionary<string, long> SnapshotDirectories(IEnumerable<string> directories)
    {
        var result = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var directory in directories)
        {
            foreach (var entry in SnapshotDirectory(directory))
            {
                result[entry.Key] = entry.Value;
            }
        }
        return result;
    }

    private static List<string> BuildMonitoredDirectories(IEnumerable<string> startupDirs)
    {
        var paths = new List<string>();
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(profile, "Downloads");
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var systemTasks = string.IsNullOrWhiteSpace(systemRoot) ? "" : Path.Combine(systemRoot, "System32", "Tasks");
        foreach (var candidate in startupDirs.Concat(new[] { desktop, documents, downloads, roaming, local, systemTasks }))
        {
            if (!string.IsNullOrWhiteSpace(candidate) && Directory.Exists(candidate))
            {
                paths.Add(candidate);
            }
        }
        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static FirewallIsolationResult ApplyFirewallIsolation(string executablePath)
    {
        var token = Guid.NewGuid().ToString("N");
        var inboundName = $"RagnarSandbox-{token}-In";
        var outboundName = $"RagnarSandbox-{token}-Out";
        var applied = true;
        var errors = new List<string>();
        foreach (var args in new[]
        {
            $"advfirewall firewall add rule name=\"{inboundName}\" dir=in action=block program=\"{executablePath}\" enable=yes",
            $"advfirewall firewall add rule name=\"{outboundName}\" dir=out action=block program=\"{executablePath}\" enable=yes",
        })
        {
            if (!RunNetsh(args, out var error))
            {
                applied = false;
                if (!string.IsNullOrWhiteSpace(error))
                {
                    errors.Add(error);
                }
            }
        }
        return new FirewallIsolationResult
        {
            Applied = applied,
            RuleNames = new[] { inboundName, outboundName },
            Errors = errors.ToArray(),
        };
    }

    private static void RemoveFirewallIsolation(FirewallIsolationResult result)
    {
        foreach (var ruleName in result.RuleNames)
        {
            RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\"", out _);
        }
    }

    private static bool RunNetsh(string arguments, out string error)
    {
        error = "";
        try
        {
            using var process = new Process();
            process.StartInfo.FileName = "netsh.exe";
            process.StartInfo.Arguments = arguments;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.Start();
            process.WaitForExit(15000);
            if (process.ExitCode == 0)
            {
                return true;
            }
            error = (process.StandardError.ReadToEnd() + process.StandardOutput.ReadToEnd()).Trim();
            return false;
        }
        catch (Exception exc)
        {
            error = exc.Message;
            return false;
        }
    }

    private static Dictionary<string, long> SnapshotDirectory(string path)
    {
        var result = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
        {
            return result;
        }
        try
        {
            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories).Take(256))
            {
                try
                {
                    result[file] = new FileInfo(file).Length;
                }
                catch
                {
                }
            }
        }
        catch
        {
        }
        return result;
    }

    private static HashSet<string> SnapshotRunKeys(IEnumerable<string> subKeys)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var subKey in subKeys)
        {
            foreach (var value in SnapshotRunKey(subKey))
            {
                result.Add(value);
            }
        }
        return result;
    }

    private static HashSet<string> SnapshotRunKey(string subKey)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(subKey);
            if (key is null)
            {
                return result;
            }
            foreach (var name in key.GetValueNames())
            {
                result.Add(name);
            }
        }
        catch
        {
        }
        return result;
    }

    private static string[] BuildStartupDirectories()
    {
        var directories = new List<string>();
        foreach (var candidate in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        })
        {
            if (!string.IsNullOrWhiteSpace(candidate) && Directory.Exists(candidate))
            {
                directories.Add(candidate);
            }
        }
        return directories.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string ReadWallpaper()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop");
            return Convert.ToString(key?.GetValue("Wallpaper") ?? "") ?? "";
        }
        catch
        {
            return "";
        }
    }

    private static bool IsExecutableLike(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        return extension is ".exe" or ".dll" or ".bat" or ".cmd" or ".ps1" or ".js" or ".vbs" or ".msi" or ".scr";
    }

    private static bool SuspiciousToolSeen(string name) => Program.SuspiciousTools.Contains(name);
}

internal sealed class LaunchContext : IDisposable
{
    public int ProcessId { get; init; }
    public string Backend { get; init; } = "job-object-fallback";
    public string? Error { get; init; }
    public SafeHandleWrapper? JobHandle { get; init; }
    public SafeHandleWrapper? ProcessHandle { get; init; }
    public SafeHandleWrapper? ThreadHandle { get; init; }

    public void Dispose()
    {
        ThreadHandle?.Dispose();
        ProcessHandle?.Dispose();
        JobHandle?.Dispose();
    }
}

internal sealed class FirewallIsolationResult
{
    public bool Applied { get; init; }
    public string[] RuleNames { get; init; } = Array.Empty<string>();
    public string[] Errors { get; init; } = Array.Empty<string>();
}

internal sealed class SafeHandleWrapper : IDisposable
{
    private IntPtr _handle;

    public SafeHandleWrapper(IntPtr handle) => _handle = handle;

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            NativeMethods.CloseHandle(_handle);
            _handle = IntPtr.Zero;
        }
    }
}

internal static class NativeMethods
{
    [Flags]
    public enum ThreadAccess : uint
    {
        SUSPEND_RESUME = 0x0002
    }

    [Flags]
    public enum TokenAccess : uint
    {
        TOKEN_ASSIGN_PRIMARY = 0x0001,
        TOKEN_DUPLICATE = 0x0002,
        TOKEN_IMPERSONATE = 0x0004,
        TOKEN_QUERY = 0x0008,
        TOKEN_ADJUST_PRIVILEGES = 0x0020,
        TOKEN_ADJUST_DEFAULT = 0x0080,
        TOKEN_ADJUST_SESSIONID = 0x0100,
        TOKEN_ALL_ACCESS = 0x000F01FF
    }

    public enum JobObjectInfoType
    {
        ExtendedLimitInformation = 9
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public long Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint CREATE_NO_WINDOW = 0x08000000;
    public const int STARTF_USESHOWWINDOW = 0x00000001;
    public const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    public const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    public const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
    public const uint DISABLE_MAX_PRIVILEGE = 0x1;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(
        string? lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessAsUserW(
        IntPtr hToken,
        string? lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetInformationJobObject(IntPtr hJob, JobObjectInfoType infoType, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr processHandle, TokenAccess desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CreateRestrictedToken(
        IntPtr existingTokenHandle,
        uint flags,
        uint disableSidCount,
        IntPtr sidsToDisable,
        uint deletePrivilegeCount,
        IntPtr privilegesToDelete,
        uint restrictedSidCount,
        IntPtr sidsToRestrict,
        out IntPtr newTokenHandle);
}

using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

// Classe para manter um "dossiê" sobre a atividade de cada processo.
public class ProcessActivity
{
    public uint ProcessId { get; set; }
    public int WriteCount { get; set; }
    public DateTime FirstWriteTime { get; set; }
    public Queue<string> RecentFiles { get; } = new Queue<string>(10);
}

public static class WatchdogService
{
    // --- P/Invoke: Interface com o sistema ---
    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(string lpPortName, uint dwOptions, IntPtr lpContext, uint dwSizeOfContext, IntPtr lpSecurityAttributes, out IntPtr hPort);

    [DllImport("fltlib.dll", SetLastError = true)]
    private static extern int FilterGetMessage(IntPtr hPort, IntPtr lpMessageBuffer, uint dwMessageBufferSize, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    // --- Estruturas ---
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct KernelToUserMessage
    {
        public uint ProcessId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string ProcessName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string FileName;
        public uint OperationType; // 0=Write, 1=Create, 2=SetInfo
        [MarshalAs(UnmanagedType.Bool)]
        public bool IsSuspicious;
        [MarshalAs(UnmanagedType.Bool)]
        public bool IsFastWrite;
        [MarshalAs(UnmanagedType.Bool)]
        public bool IsCriticalFile;
        public long Timestamp; // LARGE_INTEGER como long
    }

    // --- Configurações ---
    private static readonly ConcurrentDictionary<uint, ProcessActivity> _processActivities = new ConcurrentDictionary<uint, ProcessActivity>();
    private static IntPtr _hPort = IntPtr.Zero;
    private static readonly HashSet<uint> _protectedPids = new HashSet<uint> { 0, 4 }; // System Idle e System

    // --- Heurísticas Ajustadas (alinhadas com driver) ---
    private const int MAX_RECENT_FILES = 10;
    private const int THRESHOLD_WRITE_COUNT = 5;
    private const int THRESHOLD_TIME_SECONDS = 5; // Alinhado com HEURISTIC_WINDOW_MS/1000
    private static readonly HashSet<string> RansomwareExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".encrypted", ".locky", ".crypto", ".locked", ".wanna", ".aesir", ".vault", ".crypt",
        ".rzp", ".locked", ".cryptolocker", ".tesla"
    };

    public static async Task Main(string[] args)
    {
        Console.WriteLine("Iniciando EDR Watchdog Service v2.2 (Modo Agressivo) - Matheus FIAP...");
        string[] portNames = new[] { "\\RansomwareFilterPort" }; // Foco na porta definida
        int retryCount = 0;
        const int maxRetries = 10; // Mais tentativas pra garantir conexão

        foreach (var portName in portNames)
        {
            retryCount = 0;
            while (retryCount < maxRetries)
            {
                int status = FilterConnectCommunicationPort(portName, 0, IntPtr.Zero, 0, IntPtr.Zero, out _hPort);
                if (status == 0)
                {
                    Console.WriteLine($"Conectado ao driver via porta {portName} com sucesso. Monitorando atividades...");
                    goto Connected;
                }
                else
                {
                    Console.WriteLine($"Erro de conexão com {portName} (Tentativa {retryCount + 1}/{maxRetries}): {new Win32Exception(status).Message}. Tentando novamente em 2s...");
                    retryCount++;
                    if (retryCount == maxRetries)
                    {
                        Console.WriteLine($"Falha ao conectar com {portName} após {maxRetries} tentativas.");
                        break;
                    }
                    Thread.Sleep(2000); // 2s pra agilizar
                }
            }
        }
        Console.WriteLine("Falha ao conectar. Verifique o driver.");
        return;

    Connected:
        await Task.Run(() => MessageLoop());
    }

    private static void MessageLoop()
    {
        int bufferSize = Marshal.SizeOf<KernelToUserMessage>() + 1024; // Alinhado com MAX_MSG_SIZE
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

        try
        {
            while (_hPort != IntPtr.Zero)
            {
                int result = FilterGetMessage(_hPort, buffer, (uint)bufferSize, IntPtr.Zero);
                if (result == 0)
                {
                    KernelToUserMessage msg = Marshal.PtrToStructure<KernelToUserMessage>(buffer);
                    if (!_protectedPids.Contains(msg.ProcessId) && !string.IsNullOrEmpty(msg.FileName))
                    {
                        ThreadPool.QueueUserWorkItem(_ => AnalyzeActivity(msg));
                    }
                }
                else if (Marshal.GetLastWin32Error() != 0xEA) // Ignora ERROR_IO_PENDING
                {
                    Console.WriteLine($"Erro ao receber mensagem: {new Win32Exception(Marshal.GetLastWin32Error()).Message}. Tentando continuar...");
                    Thread.Sleep(1000);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro crítico no MessageLoop: {ex.Message}");
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (_hPort != IntPtr.Zero) CloseHandle(_hPort);
        }
    }

    private static void AnalyzeActivity(KernelToUserMessage msg)
    {
        var activity = _processActivities.GetOrAdd(msg.ProcessId, pid => new ProcessActivity { ProcessId = pid, WriteCount = 0, FirstWriteTime = DateTime.UtcNow });

        lock (activity)
        {
            if ((DateTime.UtcNow - activity.FirstWriteTime).TotalSeconds > THRESHOLD_TIME_SECONDS)
            {
                activity.WriteCount = 1;
                activity.FirstWriteTime = DateTime.UtcNow;
                activity.RecentFiles.Clear();
            }
            else
            {
                activity.WriteCount++;
            }
            activity.RecentFiles.Enqueue(msg.FileName);
            while (activity.RecentFiles.Count > MAX_RECENT_FILES) activity.RecentFiles.Dequeue();
        }

        Console.WriteLine($"[ATIVIDADE] PID={msg.ProcessId}, Processo='{msg.ProcessName}', Ficheiro='{msg.FileName}', Operacao={msg.OperationType}, Contagem={activity.WriteCount}");

        bool isSuspicious = msg.IsSuspicious; // Usa flag do driver
        string detectionReason = "";

        if (isSuspicious)
        {
            if (msg.IsFastWrite) detectionReason = "Velocidade: Escrita rápida detectada.";
            else if (RansomwareExtensions.Contains(Path.GetExtension(msg.FileName).ToLower())) detectionReason = $"Extensão: '{Path.GetExtension(msg.FileName)}' detectada.";
            else if (msg.IsCriticalFile) detectionReason = "Arquivo em diretório crítico.";
        }
        else if (activity.WriteCount > THRESHOLD_WRITE_COUNT)
        {
            isSuspicious = true;
            detectionReason = $"Velocidade: {activity.WriteCount} escritas em {THRESHOLD_TIME_SECONDS}s.";
        }
        else if (activity.RecentFiles.Count == MAX_RECENT_FILES)
        {
            int distinctFiles = activity.RecentFiles.Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (distinctFiles >= MAX_RECENT_FILES * 0.8)
            {
                isSuspicious = true;
                detectionReason = $"Comportamento: {distinctFiles} arquivos distintos.";
            }
        }

        if (isSuspicious)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\nAMEAÇA DETETADA! PID={msg.ProcessId}, Processo='{msg.ProcessName}'");
            Console.WriteLine($"MOTIVO: {detectionReason}");
            Console.WriteLine("NEUTRALIZANDO PROCESSO...");
            Console.ResetColor();

            if (TerminateProcessSafely(msg.ProcessId))
            {
                _processActivities.TryRemove(msg.ProcessId, out _);
            }
        }
    }

    private static bool TerminateProcessSafely(uint pid)
    {
        if (pid == Process.GetCurrentProcess().Id)
        {
            Console.WriteLine("[AVISO] Auto-terminação evitada.");
            return false;
        }

        IntPtr hProcess = OpenProcess(0x0001 | 0x0400, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine($"[ERRO] Falha ao abrir PID {pid}: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
            return false;
        }

        bool success = false;
        try
        {
            success = TerminateProcess(hProcess, 1);
            if (success) Console.WriteLine($"[SUCESSO] PID {pid} neutralizado.");
            else Console.WriteLine($"[ERRO] Falha ao terminar PID {pid}: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
        }
        finally
        {
            CloseHandle(hProcess);
        }
        return success;
    }
}
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;

namespace AppWatch;

public partial class MainWindow : Window
{
    private const string EtwSessionName = "AppWatchSession";
    private const string FirewallRuleName = "AppWatch_Block";
    private const int MaxLogEntries = 5000;

    private readonly ObservableCollection<LogEntry> _logEntries = new();
    private readonly ConcurrentQueue<PendingEvent> _pendingEntries = new();
    // ファイルパス → 表示中のログ行(O/R/W を1行に集約するため)
    private readonly Dictionary<string, LogEntry> _fileEntries = new(StringComparer.OrdinalIgnoreCase);
    private readonly DispatcherTimer _uiFlushTimer;

    private TraceEventSession? _session;
    private Task? _etwTask;

    // ETW スレッドから参照するため volatile 的に扱う
    private string _targetProcessName = "";   // 拡張子なし・小文字
    private HashSet<int> _targetPids = new();
    private DateTime _pidsRefreshedAt = DateTime.MinValue;
    private readonly object _pidLock = new();

    public MainWindow()
    {
        InitializeComponent();
        LogListView.ItemsSource = _logEntries;

        _uiFlushTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(200)
        };
        _uiFlushTimer.Tick += (_, _) => FlushPendingEntries();
        _uiFlushTimer.Start();

        bool isAdmin = IsRunAsAdmin();
        AdminStatusText.Text = isAdmin ? "管理者権限: あり" : "管理者権限: なし";
        if (!isAdmin)
        {
            AddLog("ERR", "管理者権限がありません。ETW 監視と通信ブロックは動作しません。");
        }
    }

    // ---------------- UI イベント ----------------

    private void BrowseButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "実行ファイル (*.exe)|*.exe",
            Title = "監視対象の EXE を選択"
        };
        if (dialog.ShowDialog() == true)
        {
            TargetExeTextBox.Text = dialog.FileName;
        }
    }

    private void TargetExeTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        bool hasTarget = !string.IsNullOrWhiteSpace(TargetExeTextBox.Text);
        // 監視/ブロック中はターゲット変更を反映しない(トグルを一度 OFF にする運用)
        if (MonitorToggle.IsChecked != true)
            MonitorToggle.IsEnabled = hasTarget;
        if (BlockToggle.IsChecked != true)
            BlockToggle.IsEnabled = hasTarget;
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        _logEntries.Clear();
        _fileEntries.Clear();
        while (_pendingEntries.TryDequeue(out _)) { }
    }

    private void MonitorToggle_Checked(object sender, RoutedEventArgs e)
    {
        StartMonitoring();
    }

    private void MonitorToggle_Unchecked(object sender, RoutedEventArgs e)
    {
        StopMonitoring();
        MonitorToggle.IsEnabled = !string.IsNullOrWhiteSpace(TargetExeTextBox.Text);
    }

    private void BlockToggle_Checked(object sender, RoutedEventArgs e)
    {
        EnableFirewallBlock();
    }

    private void BlockToggle_Unchecked(object sender, RoutedEventArgs e)
    {
        DisableFirewallBlock();
        BlockToggle.IsEnabled = !string.IsNullOrWhiteSpace(TargetExeTextBox.Text);
    }

    private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        // ETW セッションを確実に終了させる
        StopMonitoring();
        _uiFlushTimer.Stop();
    }

    // ---------------- ETW 監視 ----------------

    private void StartMonitoring()
    {
        string exePath = TargetExeTextBox.Text.Trim();
        if (string.IsNullOrEmpty(exePath))
        {
            MonitorToggle.IsChecked = false;
            return;
        }

        _targetProcessName = Path.GetFileNameWithoutExtension(exePath).ToLowerInvariant();
        lock (_pidLock)
        {
            _targetPids = GetTargetPids();
            _pidsRefreshedAt = DateTime.UtcNow;
        }

        try
        {
            // 同名セッションが残っていれば TraceEventSession が引き継いで停止する
            _session = new TraceEventSession(EtwSessionName)
            {
                StopOnDispose = true
            };

            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.NetworkTCPIP |
                KernelTraceEventParser.Keywords.FileIO |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.Process);

            var kernel = _session.Source.Kernel;

            kernel.TcpIpConnect += data =>
            {
                if (IsTarget(data.ProcessID, data.ProcessName))
                    Enqueue("NET", $"{data.daddr}:{data.dport}");
            };
            kernel.TcpIpConnectIPV6 += data =>
            {
                if (IsTarget(data.ProcessID, data.ProcessName))
                    Enqueue("NET", $"[{data.daddr}]:{data.dport}");
            };
            kernel.FileIOCreate += data =>
            {
                if (IsTarget(data.ProcessID, data.ProcessName) && !string.IsNullOrEmpty(data.FileName))
                    EnqueueFile('O', data.FileName);
            };
            kernel.FileIORead += data =>
            {
                if (IsTarget(data.ProcessID, data.ProcessName) && !string.IsNullOrEmpty(data.FileName))
                    EnqueueFile('R', data.FileName);
            };
            kernel.FileIOWrite += data =>
            {
                if (IsTarget(data.ProcessID, data.ProcessName) && !string.IsNullOrEmpty(data.FileName))
                    EnqueueFile('W', data.FileName);
            };

            // Process() はセッション停止までブロックするため別スレッドで実行
            var session = _session;
            _etwTask = Task.Run(() =>
            {
                try
                {
                    session.Source.Process();
                }
                catch (Exception ex)
                {
                    Enqueue("ERR", $"ETW 処理スレッドで例外: {ex.Message}");
                }
            });

            AddLog("INFO", $"監視を開始しました: {_targetProcessName}.exe");
        }
        catch (Exception ex)
        {
            AddLog("ERR", $"監視の開始に失敗: {ex.Message}");
            CleanupSession();
            MonitorToggle.IsChecked = false;
        }
    }

    private void StopMonitoring()
    {
        if (_session == null) return;
        CleanupSession();
        AddLog("INFO", "監視を停止しました。");
    }

    private void CleanupSession()
    {
        try
        {
            _session?.Stop();   // Process() が戻り、バックグラウンドスレッドが終了する
            _session?.Dispose();
        }
        catch (Exception ex)
        {
            AddLog("ERR", $"セッション停止時に例外: {ex.Message}");
        }
        finally
        {
            _session = null;
        }

        try
        {
            _etwTask?.Wait(TimeSpan.FromSeconds(3));
        }
        catch { /* 停止待ちの例外は無視 */ }
        _etwTask = null;
    }

    // 対象プロセス判定。ETW 側の ProcessName が空のことがあるため PID でも照合する
    private bool IsTarget(int pid, string etwProcessName)
    {
        if (!string.IsNullOrEmpty(etwProcessName) &&
            etwProcessName.Equals(_targetProcessName, StringComparison.OrdinalIgnoreCase))
            return true;

        lock (_pidLock)
        {
            if ((DateTime.UtcNow - _pidsRefreshedAt).TotalSeconds > 2)
            {
                _targetPids = GetTargetPids();
                _pidsRefreshedAt = DateTime.UtcNow;
            }
            return _targetPids.Contains(pid);
        }
    }

    private HashSet<int> GetTargetPids()
    {
        var pids = new HashSet<int>();
        try
        {
            foreach (var p in Process.GetProcessesByName(_targetProcessName))
            {
                pids.Add(p.Id);
                p.Dispose();
            }
        }
        catch { /* プロセス列挙失敗は無視 */ }
        return pids;
    }

    // ---------------- 通信ブロック (Windows Defender Firewall) ----------------

    private void EnableFirewallBlock()
    {
        string exePath = TargetExeTextBox.Text.Trim();
        if (string.IsNullOrEmpty(exePath))
        {
            BlockToggle.IsChecked = false;
            return;
        }

        // 二重登録を避けるため既存ルールを先に削除(存在しなくてもよい)
        RunNetsh($"advfirewall firewall delete rule name=\"{FirewallRuleName}\"", logFailure: false);

        var (ok, output) = RunNetsh(
            $"advfirewall firewall add rule name=\"{FirewallRuleName}\" dir=out program=\"{exePath}\" action=block enable=yes");

        if (ok)
        {
            AddLog("INFO", $"通信ブロックを有効にしました: {exePath}");
        }
        else
        {
            AddLog("ERR", $"ファイアウォールルールの追加に失敗: {output}");
            BlockToggle.IsChecked = false;
        }
    }

    private void DisableFirewallBlock()
    {
        var (ok, output) = RunNetsh($"advfirewall firewall delete rule name=\"{FirewallRuleName}\"");
        if (ok)
        {
            AddLog("INFO", "通信ブロックを解除しました。");
        }
        else
        {
            AddLog("ERR", $"ファイアウォールルールの削除に失敗: {output}");
        }
    }

    private (bool ok, string output) RunNetsh(string arguments, bool logFailure = true)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi)!;
            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(10000);

            bool ok = proc.ExitCode == 0;
            string output = (stdout + stderr).Trim().Replace("\r\n", " / ");
            if (!ok && logFailure)
                AddLog("ERR", $"netsh 失敗 (code={proc.ExitCode}): {output}");
            return (ok, output);
        }
        catch (Exception ex)
        {
            if (logFailure)
                AddLog("ERR", $"netsh 実行に失敗: {ex.Message}");
            return (false, ex.Message);
        }
    }

    // ---------------- ログ ----------------

    // ETW スレッドから呼ばれる。UI 反映はタイマーでまとめて行う
    private void Enqueue(string kind, string detail)
    {
        _pendingEntries.Enqueue(new PendingEvent(DateTime.Now.ToString("HH:mm:ss"), kind, detail, null));
    }

    private void EnqueueFile(char flag, string path)
    {
        _pendingEntries.Enqueue(new PendingEvent(DateTime.Now.ToString("HH:mm:ss"), "FILE", path, flag));
    }

    // UI スレッド専用
    private void AddLog(string kind, string detail)
    {
        _logEntries.Add(new LogEntry(DateTime.Now.ToString("HH:mm:ss"), kind, detail));
        TrimLog();
    }

    private void FlushPendingEntries()
    {
        if (_pendingEntries.IsEmpty) return;

        // 1回のTickで反映する件数を制限してUIフリーズを防ぐ
        int budget = 2000;
        while (budget-- > 0 && _pendingEntries.TryDequeue(out var ev))
        {
            if (ev.FileFlag is char flag)
            {
                // 同一パスは1行に集約し、O/R/W フラグと時刻だけ更新する
                if (_fileEntries.TryGetValue(ev.Detail, out var existing))
                {
                    existing.MergeFileFlag(flag, ev.Time);
                }
                else
                {
                    var entry = new LogEntry(ev.Time, "FILE", ev.Detail);
                    entry.MergeFileFlag(flag, ev.Time);
                    _fileEntries[ev.Detail] = entry;
                    _logEntries.Add(entry);
                }
            }
            else
            {
                _logEntries.Add(new LogEntry(ev.Time, ev.Kind, ev.Detail));
            }
        }
        TrimLog();

        if (_logEntries.Count > 0)
            LogListView.ScrollIntoView(_logEntries[^1]);
    }

    private void TrimLog()
    {
        while (_logEntries.Count > MaxLogEntries)
        {
            var oldest = _logEntries[0];
            _logEntries.RemoveAt(0);
            // 集約辞書からも外す(同じ行インスタンスの場合のみ)
            if (oldest.Kind.StartsWith("FILE") &&
                _fileEntries.TryGetValue(oldest.Detail, out var mapped) &&
                ReferenceEquals(mapped, oldest))
            {
                _fileEntries.Remove(oldest.Detail);
            }
        }
    }

    private static bool IsRunAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private record PendingEvent(string Time, string Kind, string Detail, char? FileFlag);

    private sealed class LogEntry : INotifyPropertyChanged
    {
        private bool _open, _read, _write;

        public LogEntry(string time, string kind, string detail)
        {
            Time = time;
            Kind = kind;
            Detail = detail;
        }

        public string Time { get; private set; }
        public string Kind { get; private set; }
        public string Detail { get; }

        public event PropertyChangedEventHandler? PropertyChanged;

        // O/R/W を累積して "FILE ORW" のように表示を更新する
        public void MergeFileFlag(char flag, string time)
        {
            bool changed = flag switch
            {
                'O' => !_open && (_open = true),
                'R' => !_read && (_read = true),
                'W' => !_write && (_write = true),
                _ => false
            };

            if (changed)
            {
                Kind = "FILE " + (_open ? "O" : "") + (_read ? "R" : "") + (_write ? "W" : "");
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Kind)));
            }

            if (time != Time)
            {
                Time = time;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Time)));
            }
        }
    }
}

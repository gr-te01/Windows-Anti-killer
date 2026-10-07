using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Windows_Anti_killer.Controller;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;

// MainWindow.xaml.cs
namespace Windows_Anti_killer
{
    public sealed partial class MainWindow : Window
    {
        private enum ProcessSortMode
        {
            PidAscending,
            PidDescending,
            NameAscending,
            NameDescending
        }

        private readonly ProtectionState _protectionState = new();

        private readonly SelfProtectionManager
            _selfProtectionManager = new();

        private readonly OperationManager
            _operationManager = new();

        private readonly ProcessScanner
            _processScanner = new();

        private readonly ProcessClassifier
            _processClassifier = new();

        private CancellationTokenSource?
            _processScanCancellation;

        private ListView? _processListView;
        private TextBlock? _processScanStatus;
        private Button? _processRefreshButton;
        private TextBox? _processSearchBox;
        private ComboBox? _processSortComboBox;

        private IReadOnlyList<ProcessInfo>? _allProcesses;
        private string _searchQuery = string.Empty;
        private ProcessSortMode _sortMode = ProcessSortMode.PidAscending;

        // 当前被选中的进程（由 ListView.SelectionChanged 同步）
        private ProcessInfo? _selectedProcess;

        public MainWindow()
        {
            InitializeComponent();

            MainNavigation.SelectedItem =
                MainNavigation.MenuItems[0];

            ShowPage("Overview");

            ProtectionModeSwitch.IsOn = false;

            InitializeProtection();

            UpdateProtectionMode(false);
        }

        private void MainNavigation_SelectionChanged(
            NavigationView sender,
            NavigationViewSelectionChangedEventArgs args)
        {
            if (args.SelectedItem
                is NavigationViewItem item)
            {
                string? tag =
                    item.Tag?.ToString();

                if (!string.IsNullOrEmpty(tag))
                {
                    ShowPage(tag);
                }
            }
        }

        private void ProtectionModeSwitch_Toggled(
            object sender,
            RoutedEventArgs e)
        {
            UpdateProtectionMode(
                ProtectionModeSwitch.IsOn);
        }

        private void UpdateProtectionMode(
            bool advanced)
        {
            if (advanced)
            {
                ProtectionModeText.Text =
                    "ADVANCED PROTECTION";

                ProtectionModeText.Opacity =
                    1.0;

                if (Content
                    is FrameworkElement root)
                {
                    root.RequestedTheme =
                        ElementTheme.Dark;
                }
            }
            else
            {
                ProtectionModeText.Text =
                    "BASIC PROTECTION";

                ProtectionModeText.Opacity =
                    0.7;

                if (Content
                    is FrameworkElement root)
                {
                    root.RequestedTheme =
                        ElementTheme.Light;
                }
            }

            if (MainNavigation.SelectedItem
                is NavigationViewItem item &&
                item.Tag?.ToString() ==
                "Overview")
            {
                ShowPage("Overview");
            }
        }

        private void InitializeProtection()
        {
            _selfProtectionManager.Initialize();

            _protectionState.SelfProtection =
                _selfProtectionManager.Status;

            OperationResult operationResult =
                _operationManager.CheckOperation(
                    OperationType.ViewProcess);

            _protectionState.OperationSecurity =
                operationResult.Success
                    ? ProtectionModuleStatus.Active
                    : ProtectionModuleStatus.Warning;
        }

        private void ShowPage(string page)
        {
            switch (page)
            {
                case "Overview":
                    ContentFrame.Content =
                        BuildOverviewPage();
                    break;

                case "Processes":
                    ContentFrame.Content =
                        BuildProcessesPage();
                    break;

                case "SystemProtection":
                    ContentFrame.Content =
                        BuildSystemProtectionPage();
                    break;

                case "Logs":
                    ContentFrame.Content =
                        BuildLogsPage();
                    break;

                case "Settings":
                    ContentFrame.Content =
                        BuildSettingsPage();
                    break;

                default:
                    ContentFrame.Content =
                        BuildUnknownPage();
                    break;
            }
        }

        private UIElement BuildOverviewPage()
        {
            StackPanel panel =
                new StackPanel
                {
                    Spacing = 16,
                    Padding = new Thickness(32)
                };

            panel.Children.Add(
                new TextBlock
                {
                    Text = "概览",
                    FontSize = 32,
                    FontWeight =
                        FontWeights.SemiBold
                });

            panel.Children.Add(
                new TextBlock
                {
                    Text =
                        "Windows-Anti-killer 当前防护状态",
                    FontSize = 14,
                    Opacity = 0.7
                });

            string protectionMode =
                ProtectionModeSwitch.IsOn
                    ? "ADVANCED PROTECTION"
                    : "BASIC PROTECTION";

            ProtectionModuleStatus basicStatus =
                _protectionState.BasicProtection;

            panel.Children.Add(
                CreateStatusCard(
                    "基础防护",
                    $"当前 {protectionMode} 防护状态为：" +
                    $"{GetStatusDescription(basicStatus)}",
                    GetStatusText(basicStatus)));

            panel.Children.Add(
                CreateStatusCard(
                    "自身保护",
                    "保护 Windows-Anti-killer 自身，" +
                    "防止受到普通进程干扰。",
                    GetStatusText(
                        _protectionState.SelfProtection)));

            panel.Children.Add(
                CreateStatusCard(
                    "注入防护",
                    "检测并限制针对 " +
                    "Windows-Anti-killer 的异常进程注入行为。",
                    GetStatusText(
                        _protectionState.AntiInjection)));

            panel.Children.Add(
                CreateStatusCard(
                    "完整性保护",
                    "检查 Windows-Anti-killer 关键组件的完整性。",
                    GetStatusText(
                        _protectionState.Integrity)));

            panel.Children.Add(
                CreateStatusCard(
                    "操作安全",
                    "确保高风险操作经过统一的安全检查与授权。",
                    GetStatusText(
                        _protectionState.OperationSecurity)));

            return new ScrollViewer
            {
                Content = panel
            };
        }

        private UIElement BuildProcessesPage()
        {
            Grid layout = new Grid
            {
                Padding = new Thickness(32, 32, 32, 0)
            };

            layout.RowDefinitions.Add(
                new RowDefinition { Height = GridLength.Auto });
            layout.RowDefinitions.Add(
                new RowDefinition { Height = GridLength.Auto });
            layout.RowDefinitions.Add(
                new RowDefinition { Height = GridLength.Auto });
            layout.RowDefinitions.Add(
                new RowDefinition { Height = GridLength.Auto });
            layout.RowDefinitions.Add(
                new RowDefinition
                {
                    Height = new GridLength(1, GridUnitType.Star)
                });

            TextBlock title = new TextBlock
            {
                Text = "进程",
                FontSize = 32,
                FontWeight = FontWeights.SemiBold
            };
            Grid.SetRow(title, 0);
            layout.Children.Add(title);

            TextBlock description = new TextBlock
            {
                Text = "只读扫描当前运行中的 Windows 进程。" +
                       "本阶段不会终止或修改任何进程。",
                FontSize = 14,
                Opacity = 0.7,
                Margin = new Thickness(0, 8, 0, 16)
            };
            Grid.SetRow(description, 1);
            layout.Children.Add(description);

            StackPanel toolbar = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 12,
                Margin = new Thickness(0, 0, 0, 16)
            };

            _processRefreshButton = new Button
            {
                Content = "刷新进程",
                Padding = new Thickness(16, 8, 16, 8)
            };

            _processRefreshButton.Click += async (_, _) =>
            {
                await ScanProcessesAsync();
            };

            // === 搜索框（粗略包含匹配，实时过滤） ===
            _processSearchBox = new TextBox
            {
                PlaceholderText = "搜索进程名…",
                Width = 200
            };

            _processSearchBox.TextChanged +=
                ProcessSearchBox_TextChanged;

            // === 排序 ComboBox ===
            _processSortComboBox = new ComboBox
            {
                Width = 150,
                SelectedIndex = 0
            };

            _processSortComboBox.Items.Add("PID ↑");
            _processSortComboBox.Items.Add("PID ↓");
            _processSortComboBox.Items.Add("名称 A-Z");
            _processSortComboBox.Items.Add("名称 Z-A");

            _processSortComboBox.SelectionChanged +=
                ProcessSortComboBox_SelectionChanged;

            _processScanStatus = new TextBlock
            {
                Text = "等待扫描……",
                VerticalAlignment = VerticalAlignment.Center,
                Opacity = 0.7
            };

            toolbar.Children.Add(_processRefreshButton);
            toolbar.Children.Add(_processSearchBox);
            toolbar.Children.Add(_processSortComboBox);
            toolbar.Children.Add(_processScanStatus);

            Grid.SetRow(toolbar, 2);
            layout.Children.Add(toolbar);

            Grid header = CreateProcessHeader();
            Grid.SetRow(header, 3);
            layout.Children.Add(header);

            _processListView = new ListView
            {
                SelectionMode = ListViewSelectionMode.Single,
                IsItemClickEnabled = false
            };

            // 单击选中时，把 ProcessInfo 同步到字段，供后续操作使用
            _processListView.SelectionChanged +=
                ProcessListView_SelectionChanged;

            Grid.SetRow(_processListView, 4);
            layout.Children.Add(_processListView);

            _ = ScanProcessesAsync();

            return layout;
        }

        private void ProcessListView_SelectionChanged(
            object sender,
            SelectionChangedEventArgs e)
        {
            // 从 ListView 的选中项反查 ProcessInfo。
            // ListView 里装的元素是 Grid，Grid.Tag 存了 ProcessInfo。
            if (e.AddedItems.Count > 0 &&
                e.AddedItems[0] is Grid selectedGrid &&
                selectedGrid.Tag is ProcessInfo selected)
            {
                _selectedProcess = selected;
            }
            else
            {
                _selectedProcess = null;
            }
        }

        private void ProcessSearchBox_TextChanged(
            object sender,
            TextChangedEventArgs e)
        {
            _searchQuery =
                _processSearchBox?.Text?.Trim()
                ?? string.Empty;

            RefreshProcessView();
        }

        private void ProcessSortComboBox_SelectionChanged(
            object sender,
            SelectionChangedEventArgs e)
        {
            _sortMode =
                _processSortComboBox?.SelectedIndex switch
                {
                    1 => ProcessSortMode.PidDescending,
                    2 => ProcessSortMode.NameAscending,
                    3 => ProcessSortMode.NameDescending,
                    _ => ProcessSortMode.PidAscending
                };

            RefreshProcessView();
        }

        private async Task ScanProcessesAsync()
        {
            TextBlock? status =
                _processScanStatus;

            Button? refreshButton =
                _processRefreshButton;

            if (status is null ||
                refreshButton is null)
            {
                return;
            }

            _processScanCancellation?.Cancel();
            _processScanCancellation?.Dispose();

            CancellationTokenSource cancellation =
                new CancellationTokenSource();

            _processScanCancellation =
                cancellation;

            refreshButton.IsEnabled = false;

            status.Text =
                "正在扫描进程……";

            try
            {
                var processes =
                    await _processScanner.ScanAsync(
                        cancellation.Token);

                _allProcesses = processes;

                RefreshProcessView();
            }
            catch (OperationCanceledException)
            {
                status.Text =
                    "扫描已取消。";
            }
            catch (Exception ex)
            {
                status.Text =
                    $"扫描失败：{ex.Message}";
            }
            finally
            {
                if (ReferenceEquals(
                        refreshButton,
                        _processRefreshButton))
                {
                    refreshButton.IsEnabled = true;
                }
            }
        }

        // === 缓存 → 搜索 → 排序 → 生成 UI ===
        private void RefreshProcessView()
        {
            ListView? listView = _processListView;
            TextBlock? status = _processScanStatus;

            if (listView is null ||
                status is null ||
                _allProcesses is null)
            {
                return;
            }

            IEnumerable<ProcessInfo> filtered =
                _allProcesses;

            // 搜索：粗略包含匹配（OrdinalIgnoreCase）
            if (!string.IsNullOrEmpty(_searchQuery))
            {
                filtered = filtered.Where(p =>
                    p.Name.Contains(
                        _searchQuery,
                        StringComparison.OrdinalIgnoreCase));
            }

            // 排序
            filtered = _sortMode switch
            {
                ProcessSortMode.PidDescending =>
                    filtered.OrderByDescending(
                        p => p.ProcessId),

                ProcessSortMode.NameAscending =>
                    filtered.OrderBy(
                        p => p.Name,
                        StringComparer.OrdinalIgnoreCase),

                ProcessSortMode.NameDescending =>
                    filtered.OrderByDescending(
                        p => p.Name,
                        StringComparer.OrdinalIgnoreCase),

                _ =>
                    filtered.OrderBy(p => p.ProcessId)
            };

            List<ProcessInfo> toRender =
                filtered.ToList();

            listView.Items.Clear();

            // 重新生成 UI 后，选中状态作废，需要重置
            _selectedProcess = null;

            foreach (ProcessInfo process in toRender)
            {
                listView.Items.Add(
                    CreateProcessRow(process));
            }

            if (string.IsNullOrEmpty(_searchQuery))
            {
                status.Text =
                    $"已扫描 {_allProcesses.Count} 个进程";
            }
            else
            {
                status.Text =
                    $"已扫描 {_allProcesses.Count} 个进程，" +
                    $"筛选出 {toRender.Count} 个";
            }
        }

        // === 公共列定义（header 和 row 共享，避免失配） ===
        private static void SetupProcessColumns(Grid grid)
        {
            grid.ColumnDefinitions.Add(
                new ColumnDefinition
                {
                    Width = new GridLength(80)
                });

            grid.ColumnDefinitions.Add(
                new ColumnDefinition
                {
                    Width = new GridLength(180)
                });

            grid.ColumnDefinitions.Add(
                new ColumnDefinition
                {
                    Width = new GridLength(160)
                });

            grid.ColumnDefinitions.Add(
                new ColumnDefinition
                {
                    Width = new GridLength(120)
                });

            grid.ColumnDefinitions.Add(
                new ColumnDefinition
                {
                    Width = new GridLength(120)
                });

            grid.ColumnDefinitions.Add(
                new ColumnDefinition
                {
                    Width = new GridLength(120)
                });

            grid.ColumnDefinitions.Add(
                new ColumnDefinition
                {
                    Width = new GridLength(280)
                });

            grid.ColumnDefinitions.Add(
                new ColumnDefinition
                {
                    Width = new GridLength(1, GridUnitType.Star)
                });
        }

        private Grid CreateProcessHeader()
        {
            Grid grid =
                new Grid
                {
                    Padding =
                        new Thickness(12, 8, 12, 8)
                };

            SetupProcessColumns(grid);

            AddHeaderText(grid, "PID", 0);
            AddHeaderText(grid, "进程名称", 1);
            AddHeaderText(grid, "用户", 2);
            AddHeaderText(grid, "完整性", 3);
            AddHeaderText(grid, "保护", 4);
            AddHeaderText(grid, "分类", 5);
            AddHeaderText(grid, "原因", 6);
            AddHeaderText(grid, "路径", 7);

            return grid;
        }

        private static void AddHeaderText(
            Grid grid,
            string text,
            int column)
        {
            TextBlock block =
                new TextBlock
                {
                    Text = text,
                    FontWeight =
                        FontWeights.SemiBold,
                    Opacity = 0.7
                };

            Grid.SetColumn(block, column);

            grid.Children.Add(block);
        }

        // =============================================================
        // 交互层：进程行（Tag / 右键菜单 / 双击 / 整行 Tooltip）
        // =============================================================
        private Grid CreateProcessRow(
            ProcessInfo process)
        {
            Grid grid =
                new Grid
                {
                    Padding =
                        new Thickness(12, 8, 12, 8),
                    // 把 ProcessInfo 存到 Tag，后续选中/双击/右键都能反查
                    Tag = process
                };

            SetupProcessColumns(grid);

            ProcessClassification classification =
                _processClassifier.Classify(process);

            AddProcessText(
                grid,
                process.ProcessId.ToString(),
                0);

            AddProcessText(
                grid,
                process.Name,
                1);

            AddProcessText(
                grid,
                FormatField(process.UserName),
                2);

            AddProcessText(
                grid,
                FormatField(process.IntegrityLevel),
                3);

            AddProcessText(
                grid,
                GetProcessProtectionText(
                    process.ProtectionState),
                4);

            AddProcessText(
                grid,
                GetProcessCategoryText(
                    classification.Category),
                5);

            TextBlock reason =
                AddProcessText(
                    grid,
                    classification.Reason,
                    6);

            reason.TextTrimming =
                TextTrimming.CharacterEllipsis;

            ToolTipService.SetToolTip(
                reason,
                classification.Reason);

            TextBlock path =
                AddProcessText(
                    grid,
                    FormatField(process.ExecutablePath),
                    7);

            path.TextTrimming =
                TextTrimming.CharacterEllipsis;

            ToolTipService.SetToolTip(
                path,
                FormatField(process.ExecutablePath));

            // 整行悬停 Tooltip
            ToolTipService.SetToolTip(
                grid,
                BuildProcessTooltipText(
                    process,
                    classification));

            // 双击整行 → 查看详情
            grid.DoubleTapped +=
                ProcessRow_DoubleTapped;

            // 右键整行 → 上下文菜单
            grid.ContextFlyout =
                BuildProcessContextFlyout(
                    process,
                    classification);

            return grid;
        }

        private static TextBlock AddProcessText(
            Grid grid,
            string text,
            int column)
        {
            TextBlock block =
                new TextBlock
                {
                    Text = text,
                    VerticalAlignment =
                        VerticalAlignment.Center,
                    TextWrapping =
                        TextWrapping.NoWrap
                };

            Grid.SetColumn(block, column);

            grid.Children.Add(block);

            return block;
        }

        // ---- 双击处理 ----
        private async void ProcessRow_DoubleTapped(
            object sender,
            DoubleTappedRoutedEventArgs e)
        {
            if (sender is Grid grid &&
                grid.Tag is ProcessInfo process)
            {
                ProcessClassification classification =
                    _processClassifier.Classify(process);

                await ShowProcessDetailsAsync(
                    process,
                    classification);
            }
        }

        // ---- 右键菜单构建 ----
        private MenuFlyout BuildProcessContextFlyout(
            ProcessInfo process,
            ProcessClassification classification)
        {
            MenuFlyout flyout = new MenuFlyout();

            // 1. 查看详情
            MenuFlyoutItem viewDetails =
                new MenuFlyoutItem
                {
                    Text = "查看详情"
                };
            viewDetails.Click += async (_, _) =>
            {
                await ShowProcessDetailsAsync(
                    process,
                    classification);
            };
            flyout.Items.Add(viewDetails);

            // 2. 打开文件位置
            MenuFlyoutItem openLocation =
                new MenuFlyoutItem
                {
                    Text = "打开文件位置"
                };
            openLocation.Click += async (_, _) =>
            {
                await ShowNotImplementedAsync(
                    "打开文件位置",
                    process);
            };
            flyout.Items.Add(openLocation);

            // 3. 查看数字签名
            MenuFlyoutItem viewSignature =
                new MenuFlyoutItem
                {
                    Text = "查看数字签名"
                };
            viewSignature.Click += async (_, _) =>
            {
                await ShowNotImplementedAsync(
                    "查看数字签名",
                    process);
            };
            flyout.Items.Add(viewSignature);

            // 4. 查看父进程
            MenuFlyoutItem viewParent =
                new MenuFlyoutItem
                {
                    Text = "查看父进程"
                };
            viewParent.Click += async (_, _) =>
            {
                await ShowNotImplementedAsync(
                    "查看父进程",
                    process);
            };
            flyout.Items.Add(viewParent);

            // 5. 查看进程树
            MenuFlyoutItem viewTree =
                new MenuFlyoutItem
                {
                    Text = "查看进程树"
                };
            viewTree.Click += async (_, _) =>
            {
                await ShowNotImplementedAsync(
                    "查看进程树",
                    process);
            };
            flyout.Items.Add(viewTree);

            flyout.Items.Add(new MenuFlyoutSeparator());

            // 6. 普通终止（占位，不执行终止）
            MenuFlyoutItem terminate =
                new MenuFlyoutItem
                {
                    Text = "普通终止（尚未实现）"
                };
            terminate.Click += async (_, _) =>
            {
                await ShowTerminatePlaceholderAsync(
                    process,
                    force: false);
            };
            flyout.Items.Add(terminate);

            // 7. 强制终止（占位，不执行终止）
            MenuFlyoutItem forceTerminate =
                new MenuFlyoutItem
                {
                    Text = "强制终止（尚未实现）"
                };
            forceTerminate.Click += async (_, _) =>
            {
                await ShowTerminatePlaceholderAsync(
                    process,
                    force: true);
            };
            flyout.Items.Add(forceTerminate);

            return flyout;
        }

        // ---- 详情弹窗 ----
        private async Task ShowProcessDetailsAsync(
            ProcessInfo process,
            ProcessClassification classification)
        {
            StackPanel content =
                new StackPanel
                {
                    Spacing = 8
                };

            content.Children.Add(
                CreateDetailRow("PID",
                    process.ProcessId.ToString()));

            content.Children.Add(
                CreateDetailRow("父进程 PID",
                    process.ParentProcessId.ToString()));

            content.Children.Add(
                CreateDetailRow("进程名",
                    FormatField(process.Name)));

            content.Children.Add(
                CreateDetailRow("用户",
                    FormatField(process.UserName)));

            content.Children.Add(
                CreateDetailRow("完整性",
                    FormatField(process.IntegrityLevel)));

            content.Children.Add(
                CreateDetailRow("保护状态",
                    GetProcessProtectionText(
                        process.ProtectionState)));

            content.Children.Add(
                CreateDetailRow("分类",
                    GetProcessCategoryText(
                        classification.Category)));

            content.Children.Add(
                CreateDetailRow("分类原因",
                    classification.Reason));

            content.Children.Add(
                CreateDetailRow("路径",
                    FormatField(process.ExecutablePath)));

            ScrollViewer scroll =
                new ScrollViewer
                {
                    Content = content,
                    MaxHeight = 400
                };

            ContentDialog dialog =
                new ContentDialog
                {
                    Title = $"进程详情 — {FormatField(process.Name)}",
                    Content = scroll,
                    CloseButtonText = "关闭"
                };

            XamlRoot? xamlRoot =
                Content?.XamlRoot ??
                _processListView?.XamlRoot;

            if (xamlRoot is null)
            {
                return;
            }

            dialog.XamlRoot = xamlRoot;

            await dialog.ShowAsync();
        }

        private static Grid CreateDetailRow(
            string label,
            string value)
        {
            Grid row = new Grid
            {
                ColumnSpacing = 12
            };

            row.ColumnDefinitions.Add(
                new ColumnDefinition
                {
                    Width = new GridLength(100)
                });

            row.ColumnDefinitions.Add(
                new ColumnDefinition
                {
                    Width = new GridLength(1, GridUnitType.Star)
                });

            TextBlock labelBlock =
                new TextBlock
                {
                    Text = label,
                    FontWeight = FontWeights.SemiBold,
                    Opacity = 0.7
                };
            Grid.SetColumn(labelBlock, 0);
            row.Children.Add(labelBlock);

            TextBlock valueBlock =
                new TextBlock
                {
                    Text = value,
                    TextWrapping = TextWrapping.Wrap
                };
            Grid.SetColumn(valueBlock, 1);
            row.Children.Add(valueBlock);

            return row;
        }

        // ---- 未实现功能提示 ----
        private async Task ShowNotImplementedAsync(
            string featureName,
            ProcessInfo process)
        {
            ContentDialog dialog =
                new ContentDialog
                {
                    Title = featureName,
                    Content =
                        $"{featureName} 功能尚未实现。\n\n" +
                        $"目标进程：{FormatField(process.Name)} " +
                        $"(PID: {process.ProcessId})",
                    CloseButtonText = "关闭"
                };

            XamlRoot? xamlRoot =
                Content?.XamlRoot ??
                _processListView?.XamlRoot;

            if (xamlRoot is null)
            {
                return;
            }

            dialog.XamlRoot = xamlRoot;

            await dialog.ShowAsync();
        }

        // ---- 终止占位（走 OperationManager 预检查，但不执行任何终止） ----
        private async Task ShowTerminatePlaceholderAsync(
            ProcessInfo process,
            bool force)
        {
            OperationType operationType =
                force
                    ? OperationType.ForceTerminateProcess
                    : OperationType.TerminateProcess;

            OperationResult result =
                _operationManager.CheckOperation(
                    operationType,
                    userConfirmed: false);

            string authText = result.Authorization switch
            {
                OperationAuthorization.Allowed => "允许",
                OperationAuthorization.RequiresConfirmation => "需要用户确认",
                OperationAuthorization.Denied => "拒绝",
                _ => "未知"
            };

            string title = force
                ? "强制终止（尚未实现）"
                : "普通终止（尚未实现）";

            ContentDialog dialog =
                new ContentDialog
                {
                    Title = title,
                    Content =
                        "该功能尚未实现。\n\n" +
                        $"操作管理器预检查结果：\n" +
                        $"  授权状态：{authText}\n" +
                        $"  说明：{result.Message}\n\n" +
                        $"目标进程：{FormatField(process.Name)} " +
                        $"(PID: {process.ProcessId})\n\n" +
                        "后续版本接入 Native Core 后，" +
                        "此操作将通过 OperationManager 统一管线执行。",
                    CloseButtonText = "关闭"
                };

            XamlRoot? xamlRoot =
                Content?.XamlRoot ??
                _processListView?.XamlRoot;

            if (xamlRoot is null)
            {
                return;
            }

            dialog.XamlRoot = xamlRoot;

            await dialog.ShowAsync();
        }

        // ---- 整行 Tooltip 文本 ----
        private static string BuildProcessTooltipText(
            ProcessInfo process,
            ProcessClassification classification)
        {
            return
                $"PID：{process.ProcessId}\n" +
                $"父进程 PID：{process.ParentProcessId}\n" +
                $"进程名：{FormatField(process.Name)}\n" +
                $"用户：{FormatField(process.UserName)}\n" +
                $"完整性：{FormatField(process.IntegrityLevel)}\n" +
                $"保护状态：{GetProcessProtectionText(process.ProtectionState)}\n" +
                $"分类：{GetProcessCategoryText(classification.Category)}\n" +
                $"分类原因：{classification.Reason}\n" +
                $"路径：{FormatField(process.ExecutablePath)}";
        }

        // ---- 把上游的 UNKNOWN / 空值显示为"未知" ----
        // 注意：这里只影响显示，不影响 ProcessClassification 的结果
        private static string FormatField(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "未知";
            }

            if (string.Equals(
                    value,
                    "UNKNOWN",
                    StringComparison.OrdinalIgnoreCase))
            {
                return "未知";
            }

            return value;
        }

        private static string GetProcessProtectionText(
            ProcessProtectionState state)
        {
            return state switch
            {
                ProcessProtectionState.Protected =>
                    "PROTECTED",

                ProcessProtectionState.Unprotected =>
                    "NONE",

                _ =>
                    "UNKNOWN"
            };
        }

        private static string GetProcessCategoryText(
            ProcessCategory category)
        {
            return category switch
            {
                ProcessCategory.SystemComponent =>
                    "系统组件",

                ProcessCategory.Neutral =>
                    "普通",

                ProcessCategory.Suspicious =>
                    "可疑",

                ProcessCategory.Unknown =>
                    "未知",

                _ =>
                    "未知"
            };
        }

        private string GetStatusText(
            ProtectionModuleStatus status)
        {
            return status switch
            {
                ProtectionModuleStatus.Active =>
                    "准备就绪",

                ProtectionModuleStatus.NotReady =>
                    "没有就位",

                ProtectionModuleStatus.Disabled =>
                    "DISABLED",

                ProtectionModuleStatus.Warning =>
                    "WARNING",

                ProtectionModuleStatus.Error =>
                    "ERROR",

                _ =>
                    "UNKNOWN"
            };
        }

        private string GetStatusDescription(
            ProtectionModuleStatus status)
        {
            return status switch
            {
                ProtectionModuleStatus.Active =>
                    "准备就绪",

                ProtectionModuleStatus.NotReady =>
                    "没有就位",

                ProtectionModuleStatus.Disabled =>
                    "已禁用",

                ProtectionModuleStatus.Warning =>
                    "存在警告",

                ProtectionModuleStatus.Error =>
                    "发生错误",

                _ =>
                    "未知"
            };
        }

        private UIElement BuildSystemProtectionPage()
        {
            return BuildSimplePage(
                "系统保护",
                "这里将显示 Windows 系统关键区域的保护状态。",
                "SYSTEM PROTECTION\n" +
                "MBR / PBR / GPT / ESP / Boot Manager");
        }

        private UIElement BuildLogsPage()
        {
            return BuildSimplePage(
                "日志",
                "这里将显示 Windows-Anti-killer 的操作与安全日志。",
                "LOGGING\n日志系统尚未连接。");
        }

        private UIElement BuildSettingsPage()
        {
            return BuildSimplePage(
                "设置",
                "Windows-Anti-killer 的行为与防护选项。",
                "SETTINGS\n更多设置将在后续版本加入。");
        }

        private UIElement BuildUnknownPage()
        {
            return BuildSimplePage(
                "未知页面",
                "无法识别当前页面。",
                "UNKNOWN");
        }

        private UIElement BuildSimplePage(
            string title,
            string description,
            string status)
        {
            StackPanel panel =
                new StackPanel
                {
                    Spacing = 16,
                    Padding = new Thickness(32)
                };

            panel.Children.Add(
                new TextBlock
                {
                    Text = title,
                    FontSize = 32,
                    FontWeight =
                        FontWeights.SemiBold
                });

            panel.Children.Add(
                new TextBlock
                {
                    Text = description,
                    FontSize = 14,
                    Opacity = 0.7
                });

            panel.Children.Add(
                CreateStatusCard(
                    "模块状态",
                    status,
                    "PLACEHOLDER"));

            return new ScrollViewer
            {
                Content = panel
            };
        }

        private Border CreateStatusCard(
            string title,
            string description,
            string status)
        {
            StackPanel content =
                new StackPanel
                {
                    Spacing = 6
                };

            content.Children.Add(
                new TextBlock
                {
                    Text = title,
                    FontSize = 18,
                    FontWeight =
                        FontWeights.SemiBold
                });

            content.Children.Add(
                new TextBlock
                {
                    Text = description,
                    FontSize = 14,
                    Opacity = 0.7
                });

            content.Children.Add(
                new TextBlock
                {
                    Text = status,
                    FontSize = 12,
                    FontWeight =
                        FontWeights.SemiBold,
                    Opacity = 0.85
                });

            return new Border
            {
                Padding = new Thickness(20),
                CornerRadius =
                    new CornerRadius(8),

                Background =
                    new SolidColorBrush(
                        Windows.UI.Color.FromArgb(
                            25,
                            128,
                            128,
                            128)),

                Child = content
            };
        }
    }
}
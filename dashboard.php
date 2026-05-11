<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) { header("Location: index.php"); exit; }
require 'includes/db.php';

// Fetch Analytics
$totalLogs = $pdo->query("SELECT COUNT(*) FROM syslogs")->fetchColumn();
$arpFloods = $pdo->query("SELECT COUNT(*) FROM syslogs WHERE module = 'ARP' AND event_type = 'DUPADDR'")->fetchColumn();

$topModules = $pdo->query("SELECT module, COUNT(*) as count FROM syslogs GROUP BY module ORDER BY count DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC);

$labels = [];
$data = [];
foreach ($topModules as $mod) {
    $labels[] = $mod['module'];
    $data[] = $mod['count'];
}

// Fetch recent logs
$recentLogs = $pdo->query("SELECT * FROM syslogs ORDER BY id DESC LIMIT 50")->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-gray-50 flex h-screen overflow-hidden">
    <?php include 'includes/sidebar.php'; ?>

    <main class="flex-1 p-4 md:p-8 overflow-y-auto w-full">
        <button onclick="toggleSidebar()" class="md:hidden mb-4 p-2 bg-blue-600 text-white rounded">☰ Menu</button>
        <h1 class="text-3xl font-bold text-gray-800 mb-6">Network Analytics Dashboard</h1>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
                <h3 class="text-gray-500 font-semibold mb-1">Total Logs Processed</h3>
                <p class="text-4xl font-bold text-gray-800"><?= number_format($totalLogs) ?></p>
            </div>
            <div class="bg-white p-6 rounded-xl shadow-sm border border-red-200">
                <h3 class="text-red-500 font-semibold mb-1">Detected ARP Conflicts</h3>
                <p class="text-4xl font-bold text-red-600"><?= number_format($arpFloods) ?></p>
            </div>
            <div class="bg-white p-4 rounded-xl shadow-sm border border-gray-200 flex justify-center items-center">
                <canvas id="moduleChart" style="max-height: 120px;"></canvas>
            </div>
        </div>

        <div class="bg-white rounded-xl shadow-sm border overflow-hidden">
            <div class="p-6 border-b border-gray-200 bg-gray-50">
                <h2 class="text-xl font-bold text-gray-800">Recent Network Events</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-gray-100 text-gray-600 text-sm uppercase tracking-wide">
                            <th class="p-4 border-b">Timestamp</th>
                            <th class="p-4 border-b">Module</th>
                            <th class="p-4 border-b">Severity</th>
                            <th class="p-4 border-b">Event</th>
                            <th class="p-4 border-b">Details</th>
                        </tr>
                    </thead>
                    <tbody class="text-gray-700 text-sm">
                        <?php foreach($recentLogs as $log): ?>
                        <tr class="hover:bg-gray-50 border-b">
                            <td class="p-4 whitespace-nowrap"><?= htmlspecialchars($log['log_date']) ?></td>
                            <td class="p-4 font-semibold text-blue-600"><?= htmlspecialchars($log['module']) ?></td>
                            <td class="p-4">
                                <span class="px-2 py-1 rounded text-xs font-bold <?= $log['severity'] <= 4 ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700' ?>">
                                    Level <?= htmlspecialchars($log['severity']) ?>
                                </span>
                            </td>
                            <td class="p-4"><?= htmlspecialchars($log['event_type']) ?></td>
                            <td class="p-4 truncate max-w-xs" title="<?= htmlspecialchars($log['message']) ?>">
                                <?= htmlspecialchars($log['message']) ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </main>

    <script>
        const ctx = document.getElementById('moduleChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: <?= json_encode($labels) ?>,
                datasets: [{
                    data: <?= json_encode($data) ?>,
                    backgroundColor: ['#ef4444', '#3b82f6', '#10b981', '#f59e0b', '#6b7280']
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
        });
    </script>
</body>
</html>
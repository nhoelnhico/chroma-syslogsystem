<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) { header("Location: index.php"); exit; }
require 'includes/db.php';

// --- DATE RANGE FILTER LOGIC ---
$dateFilterSql = "";
$params = [];
$startDate = $_GET['start_date'] ?? '';
$endDate = $_GET['end_date'] ?? '';

if (!empty($startDate) && !empty($endDate)) {
    $dateFilterSql = " WHERE created_at BETWEEN ? AND ? ";
    $params[] = $startDate . " 00:00:00";
    $params[] = $endDate . " 23:59:59";
}

// 1. Fetch Severity Distribution
$sevStmt = $pdo->prepare("SELECT severity, COUNT(*) as count FROM syslogs " . $dateFilterSql . " GROUP BY severity ORDER BY severity ASC");
$sevStmt->execute($params);
$severityData = $sevStmt->fetchAll(PDO::FETCH_ASSOC);

$sevLabels = []; $sevCounts = []; $sevColors = [];
foreach ($severityData as $s) {
    $sevLabels[] = 'Level ' . $s['severity'];
    $sevCounts[] = $s['count'];
    // Severity 0-4 = Red (Critical/Error), 5-7 = Green (Notice/Info)
    $sevColors[] = $s['severity'] <= 4 ? 'rgba(239, 68, 68, 0.8)' : 'rgba(16, 185, 129, 0.8)'; 
}

// 2. Fetch Top 10 Modules
$modStmt = $pdo->prepare("SELECT module, COUNT(*) as count FROM syslogs " . $dateFilterSql . " GROUP BY module ORDER BY count DESC LIMIT 10");
$modStmt->execute($params);
$moduleData = $modStmt->fetchAll(PDO::FETCH_ASSOC);

$modLabels = []; $modCounts = [];
foreach ($moduleData as $m) {
    $modLabels[] = $m['module'];
    $modCounts[] = $m['count'];
}

// 3. Threat Categorization Data
$attackStats = ['VPN PEER' => 0, 'SNMP LOGIN' => 0, 'HIGH UTILIZATION' => 0, 'PORT SCAN / FLOOD' => 0, 'OTHER ANOMALIES' => 0];
$threatsStmt = $pdo->prepare("SELECT module, event_type, severity, COUNT(*) as count FROM syslogs " . $dateFilterSql . " GROUP BY module, event_type, severity");
$threatsStmt->execute($params);
$threats = $threatsStmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($threats as $t) {
    $mod = strtoupper($t['module']); $evt = strtoupper($t['event_type']);
    $count = $t['count']; $severity = (int)$t['severity'];

    if (strpos($mod, 'IPSEC') !== false || strpos($mod, 'VPDN') !== false || strpos($mod, 'PPP') !== false) $attackStats['VPN PEER'] += $count;
    elseif (strpos($mod, 'SNMP') !== false) $attackStats['SNMP LOGIN'] += $count;
    elseif (strpos($evt, 'UTILIZATION') !== false || strpos($evt, 'HIGH') !== false || strpos($mod, 'CPU') !== false) $attackStats['HIGH UTILIZATION'] += $count;
    elseif (strpos($mod, 'NETDEFEND') !== false || strpos($evt, 'DUPADDR') !== false || strpos($evt, 'FLOOD') !== false) $attackStats['PORT SCAN / FLOOD'] += $count;
    elseif ($severity <= 4) $attackStats['OTHER ANOMALIES'] += $count;
}
$threatLabels = array_keys($attackStats);
$threatCounts = array_values($attackStats);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analytics - Chroma IT</title>
    <script src="https://cdn.tailwindcss.com"></script>
    
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    animation: { 'fade-in-up': 'fadeInUp 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards' },
                    keyframes: {
                        fadeInUp: {
                            '0%': { opacity: '0', transform: 'translateY(30px)' },
                            '100%': { opacity: '1', transform: 'translateY(0)' },
                        }
                    }
                }
            }
        }
    </script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .glass { background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.1); box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1); }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: rgba(255,255,255,0.05); border-radius: 10px; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.2); border-radius: 10px; }
        
        /* Hidden initially for the slide-up animation */
        .anim-card { opacity: 0; }
    </style>
</head>
<body class="bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 text-slate-200 flex h-screen overflow-hidden font-sans">
    
    <?php include 'includes/sidebar.php'; ?>

    <main class="flex-1 p-4 md:p-8 overflow-y-auto w-full relative">
        <div class="absolute top-[-10%] left-[-10%] w-96 h-96 bg-blue-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none"></div>
        <div class="absolute bottom-[-10%] right-[-10%] w-96 h-96 bg-purple-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none"></div>

        <div class="relative z-10">
            <div class="flex justify-between items-center mb-8 flex-wrap gap-4 anim-card animate-fade-in-up" style="animation-delay: 0.1s;">
                <div class="flex items-center gap-4">
                    <button onclick="toggleSidebar()" class="md:hidden p-2 bg-blue-600/50 hover:bg-blue-600 text-white rounded-lg backdrop-blur-md transition">☰</button>
                    <h1 class="text-3xl font-bold text-white tracking-wide">Graphical Analytics</h1>
                </div>

                <form method="GET" class="glass px-4 py-2 rounded-lg flex items-center gap-3 text-sm">
                    <label class="text-slate-300">From:</label>
                    <input type="date" name="start_date" value="<?= htmlspecialchars($startDate) ?>" class="bg-transparent border-b border-slate-500 focus:outline-none text-white [color-scheme:dark]">
                    <label class="text-slate-300">To:</label>
                    <input type="date" name="end_date" value="<?= htmlspecialchars($endDate) ?>" class="bg-transparent border-b border-slate-500 focus:outline-none text-white [color-scheme:dark]">
                    <button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1 rounded transition">Filter</button>
                    <a href="analytics.php" class="text-slate-400 hover:text-white transition">Clear</a>
                </form>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
                <div class="glass p-6 rounded-xl anim-card animate-fade-in-up" style="animation-delay: 0.2s;">
                    <h2 class="text-lg font-bold text-white mb-4">Threat Intelligence Distribution</h2>
                    <div class="relative h-64">
                        <?php if (array_sum($threatCounts) > 0): ?>
                            <canvas id="threatChart"></canvas>
                        <?php else: ?>
                            <div class="flex h-full items-center justify-center text-slate-500">No threat data found for this date range.</div>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="glass p-6 rounded-xl anim-card animate-fade-in-up" style="animation-delay: 0.3s;">
                    <h2 class="text-lg font-bold text-white mb-4">Log Severity Levels (0 = Highest)</h2>
                    <div class="relative h-64">
                        <?php if (array_sum($sevCounts) > 0): ?>
                            <canvas id="severityChart"></canvas>
                        <?php else: ?>
                            <div class="flex h-full items-center justify-center text-slate-500">No severity data found.</div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="glass p-6 rounded-xl mb-10 anim-card animate-fade-in-up" style="animation-delay: 0.4s;">
                <h2 class="text-lg font-bold text-white mb-4">Top 10 Most Active Network Modules</h2>
                <div class="relative h-80">
                    <?php if (array_sum($modCounts) > 0): ?>
                        <canvas id="moduleChart"></canvas>
                    <?php else: ?>
                        <div class="flex h-full items-center justify-center text-slate-500">No module data found.</div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </main>

    <script>
        Chart.defaults.color = '#cbd5e1'; 
        Chart.defaults.font.family = 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';

        // Advanced Sequential Animation logic for Bar Charts
        const sequentialAnimation = {
            duration: 1200,
            easing: 'easeOutQuart',
            delay: (context) => {
                let delay = 0;
                if (context.type === 'data' && context.mode === 'default' && !context.chart._delayInit) {
                    delay = context.dataIndex * 100 + context.datasetIndex * 100;
                }
                return delay;
            },
        };

        // 1. Threat Doughnut Chart
        <?php if (array_sum($threatCounts) > 0): ?>
        new Chart(document.getElementById('threatChart'), {
            type: 'doughnut',
            data: {
                labels: <?= json_encode($threatLabels) ?>,
                datasets: [{
                    data: <?= json_encode($threatCounts) ?>,
                    backgroundColor: ['#fb923c', '#facc15', '#c084fc', '#f87171', '#94a3b8'],
                    borderWidth: 2,
                    borderColor: '#0f172a',
                    hoverOffset: 10
                }]
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                plugins: { legend: { position: 'right' } },
                animation: {
                    animateScale: true,
                    animateRotate: true,
                    duration: 1500,
                    easing: 'easeOutBounce'
                }
            }
        });
        <?php endif; ?>

        // 2. Severity Bar Chart
        <?php if (array_sum($sevCounts) > 0): ?>
        new Chart(document.getElementById('severityChart'), {
            type: 'bar',
            data: {
                labels: <?= json_encode($sevLabels) ?>,
                datasets: [{
                    label: 'Number of Logs',
                    data: <?= json_encode($sevCounts) ?>,
                    backgroundColor: <?= json_encode($sevColors) ?>,
                    borderRadius: 6,
                    borderSkipped: false
                }]
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                plugins: { legend: { display: false } }, 
                scales: { 
                    y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }, 
                    x: { grid: { display: false } } 
                },
                animation: sequentialAnimation
            }
        });
        <?php endif; ?>

        // 3. Top Modules Bar Chart
        <?php if (array_sum($modCounts) > 0): ?>
        new Chart(document.getElementById('moduleChart'), {
            type: 'bar',
            data: {
                labels: <?= json_encode($modLabels) ?>,
                datasets: [{
                    label: 'Log Frequency',
                    data: <?= json_encode($modCounts) ?>,
                    backgroundColor: 'rgba(59, 130, 246, 0.8)', // Blue
                    hoverBackgroundColor: 'rgba(96, 165, 250, 1)',
                    borderRadius: 6,
                    borderSkipped: false
                }]
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                plugins: { legend: { display: false } }, 
                scales: { 
                    y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }, 
                    x: { grid: { display: false } } 
                },
                animation: sequentialAnimation
            }
        });
        <?php endif; ?>
    </script>
</body>
</html>
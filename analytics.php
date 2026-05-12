<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) { header("Location: index.php"); exit; }
require 'includes/db.php';

// --- CAPTURE FILTERS ---
$startDate = $_GET['start_date'] ?? '';
$endDate = $_GET['end_date'] ?? '';
$selectedBranch = $_GET['branch_id'] ?? '';

// --- BUILD SQL FILTERS ---
$filterConditions = [];
$params = [];

if (!empty($startDate) && !empty($endDate)) {
    $filterConditions[] = "created_at BETWEEN ? AND ?";
    $params[] = $startDate . " 00:00:00";
    $params[] = $endDate . " 23:59:59";
}
if (!empty($selectedBranch)) {
    $filterConditions[] = "branch_id = ?";
    $params[] = $selectedBranch;
}

$baseWhereSql = count($filterConditions) > 0 ? " WHERE " . implode(" AND ", $filterConditions) : "";

// --- 1. SEVERITY DISTRIBUTION ---
$sevStmt = $pdo->prepare("SELECT severity, COUNT(*) as count FROM syslogs " . $baseWhereSql . " GROUP BY severity ORDER BY severity ASC");
$sevStmt->execute($params);
$severityData = $sevStmt->fetchAll(PDO::FETCH_ASSOC);
$sevLabels = []; $sevCounts = []; $sevColors = [];
foreach ($severityData as $s) {
    $sevLabels[] = 'Level ' . $s['severity']; 
    $sevCounts[] = $s['count'];
    $sevColors[] = $s['severity'] <= 4 ? 'rgba(239, 68, 68, 0.8)' : 'rgba(16, 185, 129, 0.8)'; 
}

// --- 2. TOP 10 MODULES ---
$modStmt = $pdo->prepare("SELECT module, COUNT(*) as count FROM syslogs " . $baseWhereSql . " GROUP BY module ORDER BY count DESC LIMIT 10");
$modStmt->execute($params);
$moduleData = $modStmt->fetchAll(PDO::FETCH_ASSOC);
$modLabels = []; $modCounts = [];
foreach ($moduleData as $m) { 
    $modLabels[] = $m['module']; 
    $modCounts[] = $m['count']; 
}

// --- 3. BRANCH COMPARISON ---
$branchStmt = $pdo->prepare("
    SELECT COALESCE(b.name, 'Unassigned') as branch_name, COUNT(s.id) as count 
    FROM syslogs s 
    LEFT JOIN branches b ON s.branch_id = b.id 
    " . $baseWhereSql . " 
    GROUP BY s.branch_id 
    ORDER BY count DESC 
    LIMIT 10
");
$branchStmt->execute($params);
$branchData = $branchStmt->fetchAll(PDO::FETCH_ASSOC);
$branchLabels = []; $branchCounts = [];
foreach ($branchData as $b) { 
    $branchLabels[] = $b['branch_name']; 
    $branchCounts[] = $b['count']; 
}

// --- 4. THREAT CATEGORIZATION (Strict Ruijie Rules synchronized with Dashboard) ---
$attackStats = [
    'VPN PEER' => 0, 
    'SNMP LOGIN' => 0, 
    'HIGH UTILIZATION' => 0, 
    'PORT SCAN / FLOOD' => 0, 
    'ARP CONFLICT' => 0, 
    'OTHER ANOMALIES' => 0
];

$threatsStmt = $pdo->prepare("SELECT module, event_type, severity, COUNT(*) as count FROM syslogs " . $baseWhereSql . " GROUP BY module, event_type, severity");
$threatsStmt->execute($params);
$threats = $threatsStmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($threats as $t) {
    $mod = strtoupper($t['module']); 
    $evt = strtoupper($t['event_type']); 
    $count = $t['count']; 
    $severity = (int)$t['severity'];
    
    if (strpos($mod, 'IPSEC') !== false || strpos($mod, 'VPDN') !== false || strpos($mod, 'PPP') !== false) {
        $attackStats['VPN PEER'] += $count;
    } elseif (strpos($mod, 'SNMP') !== false) {
        $attackStats['SNMP LOGIN'] += $count;
    } elseif (strpos($evt, 'UTILIZATION') !== false || strpos($evt, 'HIGH') !== false || strpos($mod, 'CPU') !== false || $mod === 'DEV_AUDIT') {
        $attackStats['HIGH UTILIZATION'] += $count;
    } elseif (strpos($mod, 'NETDEFEND') !== false || strpos($evt, 'FLOOD') !== false) {
        $attackStats['PORT SCAN / FLOOD'] += $count;
    } elseif ($mod === 'ARP' || strpos($evt, 'DUPADDR') !== false || strpos($evt, 'CONFLICT') !== false) {
        $attackStats['ARP CONFLICT'] += $count; // Accurately catches ARPCHANGEMAC, STATICARPOVR, DUPADDR, PING_CONFLICT
    } elseif ($severity <= 4) {
        $attackStats['OTHER ANOMALIES'] += $count;
    }
}
$threatLabels = array_keys($attackStats); 
$threatCounts = array_values($attackStats);

$branches = $pdo->query("SELECT * FROM branches ORDER BY name ASC")->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analytics - Chroma IT</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config={theme:{extend:{animation:{'fade-in-up':'fadeInUp 0.8s cubic-bezier(0.16,1,0.3,1) forwards'},keyframes:{fadeInUp:{'0%':{opacity:'0',transform:'translateY(30px)'},'100%':{opacity:'1',transform:'translateY(0)'}}}}}}
    </script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .glass{background:rgba(255,255,255,0.05);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.1);box-shadow:0 4px 30px rgba(0,0,0,0.1);}
        .anim-card{opacity:0;}
    </style>
</head>
<body class="bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 text-slate-200 flex h-screen overflow-hidden font-sans">
    
    <?php include 'includes/sidebar.php'; ?>
    
    <main class="flex-1 p-4 md:p-8 overflow-y-auto w-full relative">
        <div class="absolute top-[-10%] left-[-10%] w-96 h-96 bg-blue-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none"></div>
        <div class="absolute bottom-[-10%] right-[-10%] w-96 h-96 bg-purple-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none"></div>

        <div class="relative z-10 max-w-7xl mx-auto">
            <div class="flex justify-between items-center mb-8 flex-wrap gap-4 anim-card animate-fade-in-up">
                <div class="flex items-center gap-4">
                    <button onclick="toggleSidebar()" class="md:hidden p-2 bg-blue-600/50 hover:bg-blue-600 text-white rounded-lg backdrop-blur-md transition">☰</button>
                    <h1 class="text-3xl font-bold text-white tracking-wide">Graphical Analytics</h1>
                </div>

                <form method="GET" class="glass px-4 py-2 rounded-lg flex items-center gap-3 text-sm flex-wrap shadow-lg">
                    <label class="text-slate-300 font-bold">Branch:</label>
                    <select name="branch_id" class="bg-slate-800 text-white border border-slate-600 rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-blue-500">
                        <option value="">All Branches</option>
                        <?php foreach($branches as $b): ?>
                            <option value="<?= $b['id'] ?>" <?= $selectedBranch == $b['id'] ? 'selected' : '' ?>><?= htmlspecialchars($b['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                    
                    <label class="text-slate-300 ml-2">From:</label>
                    <input type="date" name="start_date" value="<?= htmlspecialchars($startDate) ?>" class="bg-transparent border-b border-slate-500 text-white focus:outline-none focus:border-blue-500 [color-scheme:dark]">
                    <label class="text-slate-300">To:</label>
                    <input type="date" name="end_date" value="<?= htmlspecialchars($endDate) ?>" class="bg-transparent border-b border-slate-500 text-white focus:outline-none focus:border-blue-500 [color-scheme:dark]">
                    
                    <button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1 rounded transition">Filter</button>
                    <a href="analytics.php" class="text-slate-400 hover:text-white transition">Clear</a>
                </form>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
                <div class="glass p-6 rounded-xl anim-card animate-fade-in-up shadow-xl flex flex-col h-full" style="animation-delay: 0.2s;">
                    <h2 class="text-lg font-bold text-white mb-4">Threat Intelligence Distribution</h2>
                    <div class="relative h-64 mb-6">
                        <?php if (array_sum($threatCounts) > 0): ?>
                            <canvas id="threatChart"></canvas>
                        <?php else: ?>
                            <div class="flex h-full items-center justify-center text-slate-500 font-medium">No threat data found for current filters.</div>
                        <?php endif; ?>
                    </div>
                    <div class="mt-auto pt-4 border-t border-white/10 text-xs text-slate-400 leading-relaxed">
                        <strong class="text-slate-200">Guide:</strong> 
                        <span class="text-orange-400 font-semibold">VPN PEER</span> (External brute-force on gateways) • 
                        <span class="text-yellow-400 font-semibold">SNMP LOGIN</span> (Network polling/probes) • 
                        <span class="text-purple-400 font-semibold">UTILIZATION</span> (CPU/Memory spikes indicating DDoS or stress) • 
                        <span class="text-red-400 font-semibold">PORT SCAN</span> (External firewall blocks) • 
                        <span class="text-emerald-400 font-semibold">ARP CONFLICT</span> (Internal IP duplications or ARP spoofing).
                    </div>
                </div>
                
                <div class="glass p-6 rounded-xl anim-card animate-fade-in-up shadow-xl flex flex-col h-full" style="animation-delay: 0.3s;">
                    <h2 class="text-lg font-bold text-white mb-4">Log Severity Levels (0 = Highest)</h2>
                    <div class="relative h-64 mb-6">
                        <?php if (array_sum($sevCounts) > 0): ?>
                            <canvas id="severityChart"></canvas>
                        <?php else: ?>
                            <div class="flex h-full items-center justify-center text-slate-500 font-medium">No severity data found for current filters.</div>
                        <?php endif; ?>
                    </div>
                    <div class="mt-auto pt-4 border-t border-white/10 text-xs text-slate-400 leading-relaxed">
                        <strong class="text-slate-200">Guide:</strong> 
                        <span class="text-red-400 font-semibold">Levels 0 to 4 (Red)</span> represent Critical Errors, Warnings, and active Firewall Defense interventions. 
                        <span class="text-emerald-400 font-semibold">Levels 5 to 7 (Green)</span> represent Notifications, Informational messages, and Debugging network traffic.
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-10">
                <div class="glass p-6 rounded-xl anim-card animate-fade-in-up shadow-xl flex flex-col h-full" style="animation-delay: 0.4s;">
                    <h2 class="text-lg font-bold text-white mb-4">Top 10 Most Active Network Modules</h2>
                    <div class="relative h-72 mb-6">
                        <?php if (array_sum($modCounts) > 0): ?>
                            <canvas id="moduleChart"></canvas>
                        <?php else: ?>
                            <div class="flex h-full items-center justify-center text-slate-500 font-medium">No module data found for current filters.</div>
                        <?php endif; ?>
                    </div>
                    <div class="mt-auto pt-4 border-t border-white/10 text-xs text-slate-400 leading-relaxed">
                        <strong class="text-slate-200">Guide:</strong> This chart displays the raw volume of logs generated by specific Ruijie firewall and switch processes. It helps identify the most "chatty" or stressed internal network services.
                    </div>
                </div>

                <div class="glass p-6 rounded-xl anim-card animate-fade-in-up shadow-xl flex flex-col h-full" style="animation-delay: 0.5s;">
                    <h2 class="text-lg font-bold text-white mb-4">Branch Activity Comparison</h2>
                    <div class="relative h-72 mb-6">
                        <?php if (array_sum($branchCounts) > 0): ?>
                            <canvas id="branchChart"></canvas>
                        <?php else: ?>
                            <div class="flex h-full items-center justify-center text-slate-500 font-medium">No branch data found for current filters.</div>
                        <?php endif; ?>
                    </div>
                    <div class="mt-auto pt-4 border-t border-white/10 text-xs text-slate-400 leading-relaxed">
                        <strong class="text-slate-200">Guide:</strong> This chart compares the total volume of network logs generated by each branch location. Use this to instantly identify if a specific branch is experiencing abnormal network activity or being targeted by an attack.
                    </div>
                </div>
            </div>
            
        </div>
    </main>

    <script>
        // Global Chart Defaults
        Chart.defaults.color = '#cbd5e1'; 
        Chart.defaults.font.family = 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';

        const seqAnim = { 
            duration: 1200, 
            easing: 'easeOutQuart', 
            delay: (ctx) => (ctx.type === 'data' && !ctx.chart._delayInit) ? ctx.dataIndex * 100 + ctx.datasetIndex * 100 : 0 
        };

        // 1. Threat Doughnut Chart (6 colors configured)
        <?php if (array_sum($threatCounts) > 0): ?>
        new Chart(document.getElementById('threatChart'), { 
            type: 'doughnut', 
            data: { 
                labels: <?= json_encode($threatLabels) ?>, 
                datasets: [{ 
                    data: <?= json_encode($threatCounts) ?>, 
                    backgroundColor: ['#fb923c', '#facc15', '#c084fc', '#f87171', '#10b981', '#94a3b8'], 
                    borderWidth: 2, 
                    borderColor: '#0f172a',
                    hoverOffset: 10
                }] 
            }, 
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                plugins: { legend: { position: 'right' } },
                animation: { animateScale: true, animateRotate: true, duration: 1500, easing: 'easeOutBounce' }
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
                    label: 'Logs', 
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
                animation: seqAnim 
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
                    label: 'Frequency', 
                    data: <?= json_encode($modCounts) ?>, 
                    backgroundColor: 'rgba(59, 130, 246, 0.8)', 
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
                animation: seqAnim 
            } 
        });
        <?php endif; ?>

        // 4. Branch Comparison Bar Chart
        <?php if (array_sum($branchCounts) > 0): ?>
        new Chart(document.getElementById('branchChart'), { 
            type: 'bar', 
            data: { 
                labels: <?= json_encode($branchLabels) ?>, 
                datasets: [{ 
                    label: 'Total Network Events', 
                    data: <?= json_encode($branchCounts) ?>, 
                    backgroundColor: 'rgba(139, 92, 246, 0.8)', // Violet for branch contrast
                    hoverBackgroundColor: 'rgba(167, 139, 250, 1)', 
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
                animation: seqAnim 
            } 
        });
        <?php endif; ?>
    </script>
</body>
</html>
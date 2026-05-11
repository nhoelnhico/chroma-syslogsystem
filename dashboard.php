<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) { header("Location: index.php"); exit; }
require 'includes/db.php';

// --- 1. CAPTURE URL PARAMETERS ---
$startDate = $_GET['start_date'] ?? '';
$endDate = $_GET['end_date'] ?? '';
$activeCategory = $_GET['category'] ?? 'ALL';

// New Limit Logic
$allowedLimits = ['20', '50', '100', '500', 'ALL'];
$selectedLimit = $_GET['limit'] ?? '100'; // Default to 100
if (!in_array($selectedLimit, $allowedLimits)) $selectedLimit = '100';

// --- 2. BUILD SQL FILTER STRINGS ---
$dateFilterSql = "";
$dateParams = [];

if (!empty($startDate) && !empty($endDate)) {
    $dateFilterSql = " WHERE created_at BETWEEN ? AND ? ";
    $dateParams[] = $startDate . " 00:00:00";
    $dateParams[] = $endDate . " 23:59:59";
}

// Map Category strings to SQL logic
$catSql = "";
if ($activeCategory === 'VPN_PEER') {
    $catSql = " (module LIKE '%IPSEC%' OR module LIKE '%VPDN%' OR module LIKE '%PPP%') ";
} elseif ($activeCategory === 'SNMP_LOGIN') {
    $catSql = " module LIKE '%SNMP%' ";
} elseif ($activeCategory === 'HIGH_UTILIZATION') {
    $catSql = " (event_type LIKE '%UTILIZATION%' OR event_type LIKE '%HIGH%' OR module LIKE '%CPU%') ";
} elseif ($activeCategory === 'PORT_SCAN_FLOOD') {
    $catSql = " (module LIKE '%NETDEFEND%' OR event_type LIKE '%DUPADDR%' OR event_type LIKE '%FLOOD%') ";
} elseif ($activeCategory === 'DEFENDED') {
    $catSql = " (module = 'NETDEFEND' OR event_type = 'DUPADDR') ";
} elseif ($activeCategory === 'OTHER_ANOMALIES') {
    $catSql = " severity <= 4 AND NOT (module LIKE '%IPSEC%' OR module LIKE '%VPDN%' OR module LIKE '%PPP%' OR module LIKE '%SNMP%' OR event_type LIKE '%UTILIZATION%' OR event_type LIKE '%HIGH%' OR module LIKE '%CPU%' OR module LIKE '%NETDEFEND%' OR event_type LIKE '%DUPADDR%' OR event_type LIKE '%FLOOD%') ";
}

// Combine WHERE clauses for the table query
$tableWhereSql = $dateFilterSql;
if (!empty($catSql)) {
    $tableWhereSql .= empty($tableWhereSql) ? " WHERE " : " AND ";
    $tableWhereSql .= $catSql;
}

// --- 3. FETCH GLOBAL ANALYTICS (Cards at the top) ---
$totalLogsStmt = $pdo->prepare("SELECT COUNT(*) FROM syslogs" . $dateFilterSql);
$totalLogsStmt->execute($dateParams);
$totalLogs = $totalLogsStmt->fetchColumn();

$defendedStmt = $pdo->prepare("SELECT COUNT(*) FROM syslogs WHERE (module = 'NETDEFEND' OR event_type = 'DUPADDR')" . str_replace("WHERE", "AND", $dateFilterSql));
if(empty($dateFilterSql)) {
    $defendedStmt = $pdo->prepare("SELECT COUNT(*) FROM syslogs WHERE module = 'NETDEFEND' OR event_type = 'DUPADDR'");
}
$defendedStmt->execute($dateParams);
$threatsDefended = $defendedStmt->fetchColumn();

$defenseRate = $totalLogs > 0 ? round(($threatsDefended / $totalLogs) * 100, 1) : 0;

// Dynamic Threat Categorization (For the numbered cards)
$attackStats = ['VPN_PEER' => 0, 'SNMP_LOGIN' => 0, 'HIGH_UTILIZATION' => 0, 'PORT_SCAN_FLOOD' => 0, 'OTHER_ANOMALIES' => 0];
$threatsStmt = $pdo->prepare("SELECT module, event_type, severity, COUNT(*) as count FROM syslogs " . $dateFilterSql . " GROUP BY module, event_type, severity");
$threatsStmt->execute($dateParams);
$threats = $threatsStmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($threats as $t) {
    $mod = strtoupper($t['module']);
    $evt = strtoupper($t['event_type']);
    $count = $t['count'];
    $severity = (int)$t['severity'];

    if (strpos($mod, 'IPSEC') !== false || strpos($mod, 'VPDN') !== false || strpos($mod, 'PPP') !== false) {
        $attackStats['VPN_PEER'] += $count;
    } elseif (strpos($mod, 'SNMP') !== false) {
        $attackStats['SNMP_LOGIN'] += $count;
    } elseif (strpos($evt, 'UTILIZATION') !== false || strpos($evt, 'HIGH') !== false || strpos($mod, 'CPU') !== false) {
        $attackStats['HIGH_UTILIZATION'] += $count;
    } elseif (strpos($mod, 'NETDEFEND') !== false || strpos($evt, 'DUPADDR') !== false || strpos($evt, 'FLOOD') !== false) {
        $attackStats['PORT_SCAN_FLOOD'] += $count;
    } elseif ($severity <= 4) {
        $attackStats['OTHER_ANOMALIES'] += $count;
    }
}

// --- 4. FETCH TABLE DATA WITH LIMIT ---
$limitSql = ($selectedLimit === 'ALL') ? "" : " LIMIT " . (int)$selectedLimit;
$logsQuery = "SELECT * FROM syslogs " . $tableWhereSql . " ORDER BY id DESC" . $limitSql;
$recentLogsStmt = $pdo->prepare($logsQuery);
$recentLogsStmt->execute($dateParams);
$recentLogs = $recentLogsStmt->fetchAll(PDO::FETCH_ASSOC);

// Helper function to build URLs for links
function buildUrl($updates) {
    $params = array_merge($_GET, $updates);
    return '?' . http_build_query($params);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chroma IT - Security Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .glass {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
        }
        .glass-header { background: rgba(0, 0, 0, 0.2); }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: rgba(255,255,255,0.05); border-radius: 10px; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.2); border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.4); }
        th.sortable:hover { cursor: pointer; color: #60a5fa; }
    </style>
</head>
<body class="bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 text-slate-200 flex h-screen overflow-hidden font-sans">
    
    <?php include 'includes/sidebar.php'; ?>

    <main class="flex-1 p-4 md:p-8 overflow-y-auto w-full relative">
        <div class="absolute top-[-10%] left-[-10%] w-96 h-96 bg-blue-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none"></div>
        <div class="absolute bottom-[-10%] right-[-10%] w-96 h-96 bg-purple-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none"></div>

        <div class="relative z-10">
            <div class="flex justify-between items-center mb-6 flex-wrap gap-4">
                <div class="flex items-center gap-4">
                    <button onclick="toggleSidebar()" class="md:hidden p-2 bg-blue-600/50 hover:bg-blue-600 text-white rounded-lg backdrop-blur-md transition">☰</button>
                    <h1 class="text-3xl font-bold text-white tracking-wide">Security Analytics</h1>
                </div>
                
                <form method="GET" class="glass px-4 py-2 rounded-lg flex items-center gap-3 text-sm">
                    <input type="hidden" name="category" value="<?= htmlspecialchars($activeCategory) ?>">
                    <input type="hidden" name="limit" value="<?= htmlspecialchars($selectedLimit) ?>">
                    <label class="text-slate-300">From:</label>
                    <input type="date" name="start_date" value="<?= htmlspecialchars($startDate) ?>" class="bg-transparent border-b border-slate-500 focus:outline-none text-white [color-scheme:dark]">
                    <label class="text-slate-300">To:</label>
                    <input type="date" name="end_date" value="<?= htmlspecialchars($endDate) ?>" class="bg-transparent border-b border-slate-500 focus:outline-none text-white [color-scheme:dark]">
                    <button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1 rounded transition">Filter</button>
                    <a href="dashboard.php?category=<?= htmlspecialchars($activeCategory) ?>&limit=<?= htmlspecialchars($selectedLimit) ?>" class="text-slate-400 hover:text-white transition">Clear Dates</a>
                </form>
            </div>

            <div class="glass rounded-xl p-6 mb-8 border-l-4 border-l-blue-500">
                <h2 class="text-lg font-semibold text-slate-300 mb-4 uppercase tracking-widest">System Defense Status</h2>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
                    <div>
                        <p class="text-sm text-slate-400">Total System Events</p>
                        <p class="text-4xl font-black text-white"><?= number_format($totalLogs) ?></p>
                    </div>
                    
                    <a href="<?= buildUrl(['category' => 'DEFENDED']) ?>" class="block cursor-pointer hover:bg-white/5 p-3 -m-3 rounded-xl transition-all group <?= $activeCategory === 'DEFENDED' ? 'bg-white/10 ring-1 ring-emerald-500/50' : '' ?>">
                        <p class="text-sm text-slate-400 group-hover:text-emerald-300 transition">Threats Successfully Defended</p>
                        <p class="text-4xl font-black text-emerald-400 group-hover:scale-105 transform origin-left transition duration-300"><?= number_format($threatsDefended) ?></p>
                        <p class="text-xs text-emerald-500/70 mt-1 opacity-0 group-hover:opacity-100 transition">Click to view isolated logs</p>
                    </a>

                    <div class="w-full">
                        <div class="flex justify-between text-sm mb-1">
                            <span class="text-slate-300">Mitigation Rate</span>
                            <span class="text-emerald-400 font-bold"><?= $defenseRate ?>%</span>
                        </div>
                        <div class="w-full bg-slate-700 rounded-full h-3 overflow-hidden">
                            <div class="bg-gradient-to-r from-emerald-600 to-emerald-400 h-3 rounded-full transition-all duration-1000 shadow-[0_0_10px_rgba(52,211,153,0.5)]" style="width: <?= $defenseRate ?>%"></div>
                        </div>
                    </div>
                </div>
            </div>

            <h2 class="text-xl font-semibold text-slate-300 mb-4 uppercase tracking-widest">Threat Intelligence Report <span class="text-xs normal-case text-slate-400 ml-2">(Click to filter table)</span></h2>
            <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
                <?php 
                $cards = [
                    ['id' => 'VPN_PEER', 'color' => 'orange', 'label' => 'VPN PEER'],
                    ['id' => 'SNMP_LOGIN', 'color' => 'yellow', 'label' => 'SNMP LOGIN'],
                    ['id' => 'HIGH_UTILIZATION', 'color' => 'purple', 'label' => 'HIGH UTILIZATION'],
                    ['id' => 'PORT_SCAN_FLOOD', 'color' => 'red', 'label' => 'PORT SCAN / FLOOD'],
                    ['id' => 'OTHER_ANOMALIES', 'color' => 'slate', 'label' => 'OTHER ANOMALIES']
                ];

                foreach ($cards as $card): 
                    $count = $attackStats[$card['id']];
                    $isActive = ($activeCategory === $card['id']);
                    $colorClass = $count > 0 ? "text-{$card['color']}-400 drop-shadow-[0_0_8px_currentColor]" : "text-slate-500";
                    $borderClass = $count > 0 ? "border-{$card['color']}-500/50" : "border-white/10";
                    $activeBg = $isActive ? "bg-white/10 ring-1 ring-{$card['color']}-500/50" : "";
                ?>
                <a href="<?= buildUrl(['category' => $card['id']]) ?>" class="block glass p-4 rounded-xl <?= $borderClass ?> <?= $activeBg ?> hover:bg-white/10 hover:-translate-y-1 transition-all duration-300 cursor-pointer group">
                    <h4 class="text-xs text-slate-400 uppercase font-bold tracking-wider mb-1 group-hover:text-white transition"><?= $card['label'] ?></h4>
                    <p class="text-3xl font-black <?= $colorClass ?>">
                        <?= number_format($count) ?>
                    </p>
                </a>
                <?php endforeach; ?>
            </div>

            <div class="glass rounded-xl overflow-hidden flex flex-col mb-10">
                <div class="p-4 glass-header flex flex-wrap justify-between items-center gap-4 shrink-0 border-b border-white/10">
                    <div>
                        <h2 class="text-lg font-bold text-white">Network Events Overview</h2>
                        <p class="text-xs text-slate-400">
                            <?php 
                                $displayCat = str_replace('_', ' ', $activeCategory);
                                echo $activeCategory === 'ALL' 
                                ? "Showing recent network events." 
                                : "Filtered by: <strong class='text-white'>{$displayCat}</strong>.";
                            ?>
                        </p>
                    </div>

                    <div class="flex items-center gap-3">
                        <form method="GET" id="limitForm" class="flex items-center gap-2">
                            <input type="hidden" name="category" value="<?= htmlspecialchars($activeCategory) ?>">
                            <input type="hidden" name="start_date" value="<?= htmlspecialchars($startDate) ?>">
                            <input type="hidden" name="end_date" value="<?= htmlspecialchars($endDate) ?>">
                            
                            <label class="text-sm text-slate-400">Show:</label>
                            <select name="limit" onchange="document.getElementById('limitForm').submit()" class="bg-slate-800 text-white text-sm border border-slate-600 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500">
                                <option value="20" <?= $selectedLimit == '20' ? 'selected' : '' ?>>20</option>
                                <option value="50" <?= $selectedLimit == '50' ? 'selected' : '' ?>>50</option>
                                <option value="100" <?= $selectedLimit == '100' ? 'selected' : '' ?>>100</option>
                                <option value="500" <?= $selectedLimit == '500' ? 'selected' : '' ?>>500</option>
                                <option value="ALL" <?= $selectedLimit == 'ALL' ? 'selected' : '' ?>>View All</option>
                            </select>
                            <span class="text-sm text-slate-400 hidden sm:inline">entries</span>
                        </form>

                        <?php if($activeCategory !== 'ALL'): ?>
                            <a href="<?= buildUrl(['category' => 'ALL']) ?>" class="text-sm bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded-lg transition text-white font-medium shadow-lg whitespace-nowrap">Clear Filter</a>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="overflow-x-auto overflow-y-auto max-h-[600px] w-full">
                    <table class="w-full text-left border-collapse relative" id="eventsTable">
                        <thead class="glass-header sticky top-0 z-20 shadow-md backdrop-blur-md">
                            <tr class="text-slate-300 text-xs uppercase tracking-wider">
                                <th class="p-4 border-b border-white/10 sortable bg-slate-900/50 hover:bg-slate-800/50 transition" onclick="sortTable(0)">Timestamp ⇅</th>
                                <th class="p-4 border-b border-white/10 sortable bg-slate-900/50 hover:bg-slate-800/50 transition" onclick="sortTable(1)">Module ⇅</th>
                                <th class="p-4 border-b border-white/10 sortable bg-slate-900/50 hover:bg-slate-800/50 transition" onclick="sortTable(2)">Severity ⇅</th>
                                <th class="p-4 border-b border-white/10 sortable bg-slate-900/50 hover:bg-slate-800/50 transition" onclick="sortTable(3)">Event ⇅</th>
                                <th class="p-4 border-b border-white/10 bg-slate-900/50">Details</th>
                            </tr>
                        </thead>
                        <tbody class="text-sm divide-y divide-white/5" id="eventsBody">
                            <?php foreach($recentLogs as $log): ?>
                            <tr class="hover:bg-white/5 transition log-row">
                                <td class="p-4 whitespace-nowrap text-slate-300"><?= htmlspecialchars($log['log_date']) ?></td>
                                <td class="p-4 font-semibold text-blue-400"><?= htmlspecialchars($log['module']) ?></td>
                                <td class="p-4 whitespace-nowrap">
                                    <span class="px-2 py-1 rounded-md text-xs font-bold border <?= $log['severity'] <= 4 ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' ?>">
                                        Lvl <?= htmlspecialchars($log['severity']) ?>
                                    </span>
                                </td>
                                <td class="p-4 font-medium text-slate-200"><?= htmlspecialchars($log['event_type']) ?></td>
                                <td class="p-4 text-slate-400 truncate max-w-lg hover:whitespace-normal transition-all cursor-default" title="<?= htmlspecialchars($log['message']) ?>">
                                    <?= htmlspecialchars($log['message']) ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                            
                            <?php if(empty($recentLogs)): ?>
                            <tr>
                                <td colspan="5" class="p-8 text-center text-slate-500 font-medium">No logs found matching current filters.</td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </main>

    <script>
        // --- JS Logic for Column Sorting (Sorts the currently loaded rows in the browser) ---
        let sortDirections = [true, true, true, true]; 

        function sortTable(columnIndex) {
            const tbody = document.getElementById("eventsBody");
            const rows = Array.from(tbody.querySelectorAll("tr.log-row"));
            const isAsc = sortDirections[columnIndex];

            rows.sort((a, b) => {
                let cellA = a.cells[columnIndex].innerText.trim();
                let cellB = b.cells[columnIndex].innerText.trim();

                if (columnIndex === 2) {
                    cellA = parseInt(cellA.replace(/\D/g, '')) || 0;
                    cellB = parseInt(cellB.replace(/\D/g, '')) || 0;
                    return isAsc ? cellA - cellB : cellB - cellA;
                }

                return isAsc ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
            });

            rows.forEach(row => tbody.appendChild(row));
            sortDirections[columnIndex] = !isAsc;
        }
    </script>
</body>
</html>
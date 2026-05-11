<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) { header("Location: index.php"); exit; }
require 'includes/db.php';

// --- CAPTURE FILTERS ---
$startDate = $_GET['start_date'] ?? '';
$endDate = $_GET['end_date'] ?? '';
$activeCategory = $_GET['category'] ?? 'ALL';
$selectedBranch = $_GET['branch_id'] ?? '';
$selectedLimit = $_GET['limit'] ?? '100'; 
if (!in_array($selectedLimit, ['20', '50', '100', '500', 'ALL'])) $selectedLimit = '100';

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

// Category Map
$catSql = "";
if ($activeCategory === 'VPN_PEER') $catSql = " (module LIKE '%IPSEC%' OR module LIKE '%VPDN%' OR module LIKE '%PPP%') ";
elseif ($activeCategory === 'SNMP_LOGIN') $catSql = " module LIKE '%SNMP%' ";
elseif ($activeCategory === 'HIGH_UTILIZATION') $catSql = " (event_type LIKE '%UTILIZATION%' OR event_type LIKE '%HIGH%' OR module LIKE '%CPU%') ";
elseif ($activeCategory === 'PORT_SCAN_FLOOD') $catSql = " (module LIKE '%NETDEFEND%' OR event_type LIKE '%DUPADDR%' OR event_type LIKE '%FLOOD%') ";
elseif ($activeCategory === 'DEFENDED') $catSql = " (module = 'NETDEFEND' OR event_type = 'DUPADDR') ";
elseif ($activeCategory === 'OTHER_ANOMALIES') $catSql = " severity <= 4 AND NOT (module LIKE '%IPSEC%' OR module LIKE '%VPDN%' OR module LIKE '%PPP%' OR module LIKE '%SNMP%' OR event_type LIKE '%UTILIZATION%' OR event_type LIKE '%HIGH%' OR module LIKE '%CPU%' OR module LIKE '%NETDEFEND%' OR event_type LIKE '%DUPADDR%' OR event_type LIKE '%FLOOD%') ";

$tableWhereSql = $baseWhereSql;
if (!empty($catSql)) {
    $tableWhereSql .= empty($tableWhereSql) ? " WHERE " : " AND ";
    $tableWhereSql .= $catSql;
}

// Analytics Queries
$totalLogsStmt = $pdo->prepare("SELECT COUNT(*) FROM syslogs" . $baseWhereSql);
$totalLogsStmt->execute($params);
$totalLogs = $totalLogsStmt->fetchColumn();

$defendedQuery = "SELECT COUNT(*) FROM syslogs " . (empty($baseWhereSql) ? "WHERE" : $baseWhereSql . " AND ") . " (module = 'NETDEFEND' OR event_type = 'DUPADDR')";
$defendedStmt = $pdo->prepare($defendedQuery);
$defendedStmt->execute($params);
$threatsDefended = $defendedStmt->fetchColumn();
$defenseRate = $totalLogs > 0 ? round(($threatsDefended / $totalLogs) * 100, 1) : 0;

$attackStats = ['VPN_PEER' => 0, 'SNMP_LOGIN' => 0, 'HIGH_UTILIZATION' => 0, 'PORT_SCAN_FLOOD' => 0, 'OTHER_ANOMALIES' => 0];
$threatsStmt = $pdo->prepare("SELECT module, event_type, severity, COUNT(*) as count FROM syslogs " . $baseWhereSql . " GROUP BY module, event_type, severity");
$threatsStmt->execute($params);
$threats = $threatsStmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($threats as $t) {
    $mod = strtoupper($t['module']); $evt = strtoupper($t['event_type']); $count = $t['count']; $severity = (int)$t['severity'];
    if (strpos($mod, 'IPSEC') !== false || strpos($mod, 'VPDN') !== false || strpos($mod, 'PPP') !== false) $attackStats['VPN_PEER'] += $count;
    elseif (strpos($mod, 'SNMP') !== false) $attackStats['SNMP_LOGIN'] += $count;
    elseif (strpos($evt, 'UTILIZATION') !== false || strpos($evt, 'HIGH') !== false || strpos($mod, 'CPU') !== false) $attackStats['HIGH_UTILIZATION'] += $count;
    elseif (strpos($mod, 'NETDEFEND') !== false || strpos($evt, 'DUPADDR') !== false || strpos($evt, 'FLOOD') !== false) $attackStats['PORT_SCAN_FLOOD'] += $count;
    elseif ($severity <= 4) $attackStats['OTHER_ANOMALIES'] += $count;
}

$limitSql = ($selectedLimit === 'ALL') ? "" : " LIMIT " . (int)$selectedLimit;
$logsQuery = "SELECT * FROM syslogs " . $tableWhereSql . " ORDER BY id DESC" . $limitSql;
$recentLogsStmt = $pdo->prepare($logsQuery);
$recentLogsStmt->execute($params);
$recentLogs = $recentLogsStmt->fetchAll(PDO::FETCH_ASSOC);

$branches = $pdo->query("SELECT * FROM branches ORDER BY name ASC")->fetchAll(PDO::FETCH_ASSOC);
function buildUrl($updates) { return '?' . http_build_query(array_merge($_GET, $updates)); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - Chroma IT</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>.glass { background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.1); } .glass-header { background: rgba(0, 0, 0, 0.2); } ::-webkit-scrollbar { width: 8px; height: 8px; } ::-webkit-scrollbar-track { background: rgba(255,255,255,0.05); border-radius: 10px; } ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.2); border-radius: 10px; } th.sortable:hover { cursor: pointer; color: #60a5fa; }</style>
</head>
<body class="bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 text-slate-200 flex h-screen overflow-hidden font-sans">
    <?php include 'includes/sidebar.php'; ?>
    <main class="flex-1 p-4 md:p-8 overflow-y-auto w-full relative">
        <div class="relative z-10">
            <div class="flex justify-between items-center mb-6 flex-wrap gap-4">
                <div class="flex items-center gap-4">
                    <button onclick="toggleSidebar()" class="md:hidden p-2 bg-blue-600/50 hover:bg-blue-600 text-white rounded-lg">☰</button>
                    <h1 class="text-3xl font-bold text-white tracking-wide">Security Analytics</h1>
                </div>
                
                <form method="GET" class="glass px-4 py-2 rounded-lg flex items-center gap-3 text-sm flex-wrap">
                    <input type="hidden" name="category" value="<?= htmlspecialchars($activeCategory) ?>">
                    <input type="hidden" name="limit" value="<?= htmlspecialchars($selectedLimit) ?>">
                    
                    <label class="text-slate-300 font-bold">Branch:</label>
                    <select name="branch_id" class="bg-slate-800 text-white border border-slate-600 rounded px-2 py-1">
                        <option value="">All Branches</option>
                        <?php foreach($branches as $b): ?>
                            <option value="<?= $b['id'] ?>" <?= $selectedBranch == $b['id'] ? 'selected' : '' ?>><?= htmlspecialchars($b['name']) ?></option>
                        <?php endforeach; ?>
                    </select>

                    <label class="text-slate-300 ml-2">From:</label>
                    <input type="date" name="start_date" value="<?= htmlspecialchars($startDate) ?>" class="bg-transparent border-b border-slate-500 text-white [color-scheme:dark]">
                    <label class="text-slate-300">To:</label>
                    <input type="date" name="end_date" value="<?= htmlspecialchars($endDate) ?>" class="bg-transparent border-b border-slate-500 text-white [color-scheme:dark]">
                    
                    <button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1 rounded">Filter</button>
                    <a href="dashboard.php" class="text-slate-400 hover:text-white">Clear</a>
                </form>
            </div>

            <div class="glass rounded-xl p-6 mb-8 border-l-4 border-l-blue-500">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
                    <div>
                        <p class="text-sm text-slate-400">Total System Events</p>
                        <p class="text-4xl font-black text-white"><?= number_format($totalLogs) ?></p>
                    </div>
                    <a href="<?= buildUrl(['category' => 'DEFENDED']) ?>" class="block cursor-pointer hover:bg-white/5 p-3 rounded-xl transition-all group">
                        <p class="text-sm text-slate-400 group-hover:text-emerald-300">Threats Successfully Defended</p>
                        <p class="text-4xl font-black text-emerald-400"><?= number_format($threatsDefended) ?></p>
                    </a>
                    <div class="w-full">
                        <div class="flex justify-between text-sm mb-1">
                            <span class="text-slate-300">Mitigation Rate</span>
                            <span class="text-emerald-400 font-bold"><?= $defenseRate ?>%</span>
                        </div>
                        <div class="w-full bg-slate-700 rounded-full h-3 overflow-hidden">
                            <div class="bg-emerald-500 h-3 rounded-full" style="width: <?= $defenseRate ?>%"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
                <?php $cards = [['id' => 'VPN_PEER', 'color' => 'orange', 'label' => 'VPN PEER'], ['id' => 'SNMP_LOGIN', 'color' => 'yellow', 'label' => 'SNMP LOGIN'], ['id' => 'HIGH_UTILIZATION', 'color' => 'purple', 'label' => 'HIGH UTILIZATION'], ['id' => 'PORT_SCAN_FLOOD', 'color' => 'red', 'label' => 'PORT SCAN / FLOOD'], ['id' => 'OTHER_ANOMALIES', 'color' => 'slate', 'label' => 'OTHER ANOMALIES']];
                foreach ($cards as $card): 
                    $count = $attackStats[$card['id']];
                    $colorClass = $count > 0 ? "text-{$card['color']}-400" : "text-slate-500";
                    $borderClass = $count > 0 ? "border-{$card['color']}-500/50" : "border-white/10";
                    $activeBg = ($activeCategory === $card['id']) ? "bg-white/10 ring-1 ring-{$card['color']}-500/50" : "";
                ?>
                <a href="<?= buildUrl(['category' => $card['id']]) ?>" class="block glass p-4 rounded-xl <?= $borderClass ?> <?= $activeBg ?> hover:bg-white/10 hover:-translate-y-1 transition-all group">
                    <h4 class="text-xs text-slate-400 uppercase font-bold mb-1 group-hover:text-white"><?= $card['label'] ?></h4>
                    <p class="text-3xl font-black <?= $colorClass ?>"><?= number_format($count) ?></p>
                </a>
                <?php endforeach; ?>
            </div>

            <div class="glass rounded-xl overflow-hidden flex flex-col mb-10">
                <div class="p-4 glass-header flex flex-wrap justify-between items-center gap-4 border-b border-white/10">
                    <div>
                        <h2 class="text-lg font-bold text-white">Network Events Overview</h2>
                    </div>
                    <form method="GET" id="limitForm" class="flex items-center gap-2">
                        <input type="hidden" name="category" value="<?= htmlspecialchars($activeCategory) ?>">
                        <input type="hidden" name="branch_id" value="<?= htmlspecialchars($selectedBranch) ?>">
                        <input type="hidden" name="start_date" value="<?= htmlspecialchars($startDate) ?>">
                        <input type="hidden" name="end_date" value="<?= htmlspecialchars($endDate) ?>">
                        <label class="text-sm text-slate-400">Show:</label>
                        <select name="limit" onchange="document.getElementById('limitForm').submit()" class="bg-slate-800 text-white text-sm border border-slate-600 rounded px-2 py-1">
                            <?php foreach(['20','50','100','500','ALL'] as $v): ?>
                                <option value="<?= $v ?>" <?= $selectedLimit == $v ? 'selected' : '' ?>><?= $v ?></option>
                            <?php endforeach; ?>
                        </select>
                        <?php if($activeCategory !== 'ALL'): ?><a href="<?= buildUrl(['category' => 'ALL']) ?>" class="ml-2 bg-slate-700 px-3 py-1 rounded text-sm text-white">Clear Filter</a><?php endif; ?>
                    </form>
                </div>
                
                <div class="overflow-x-auto overflow-y-auto max-h-[600px] w-full">
                    <table class="w-full text-left border-collapse" id="eventsTable">
                        <thead class="glass-header sticky top-0 z-20 shadow-md backdrop-blur-md">
                            <tr class="text-slate-300 text-xs uppercase tracking-wider">
                                <th class="p-4 border-b border-white/10 sortable bg-slate-900/50" onclick="sortTable(0)">Timestamp ⇅</th>
                                <th class="p-4 border-b border-white/10 sortable bg-slate-900/50" onclick="sortTable(1)">Module ⇅</th>
                                <th class="p-4 border-b border-white/10 sortable bg-slate-900/50" onclick="sortTable(2)">Severity ⇅</th>
                                <th class="p-4 border-b border-white/10 sortable bg-slate-900/50" onclick="sortTable(3)">Event ⇅</th>
                                <th class="p-4 border-b border-white/10 bg-slate-900/50">Details</th>
                            </tr>
                        </thead>
                        <tbody class="text-sm divide-y divide-white/5" id="eventsBody">
                            <?php foreach($recentLogs as $log): ?>
                            <tr class="hover:bg-white/5 transition log-row">
                                <td class="p-4 text-slate-300 whitespace-nowrap"><?= htmlspecialchars($log['log_date']) ?></td>
                                <td class="p-4 font-semibold text-blue-400"><?= htmlspecialchars($log['module']) ?></td>
                                <td class="p-4"><span class="px-2 py-1 rounded-md text-xs font-bold border <?= $log['severity'] <= 4 ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' ?>">Lvl <?= htmlspecialchars($log['severity']) ?></span></td>
                                <td class="p-4 font-medium text-slate-200"><?= htmlspecialchars($log['event_type']) ?></td>
                                <td class="p-4 text-slate-400 truncate max-w-lg hover:whitespace-normal"><?= htmlspecialchars($log['message']) ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </main>
    <script>
        let sortDirections = [true, true, true, true]; 
        function sortTable(col) {
            const tbody = document.getElementById("eventsBody"), rows = Array.from(tbody.querySelectorAll("tr.log-row")), isAsc = sortDirections[col];
            rows.sort((a, b) => {
                let cellA = a.cells[col].innerText.trim(), cellB = b.cells[col].innerText.trim();
                if (col === 2) { cellA = parseInt(cellA.replace(/\D/g, ''))||0; cellB = parseInt(cellB.replace(/\D/g, ''))||0; return isAsc ? cellA - cellB : cellB - cellA; }
                return isAsc ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
            });
            rows.forEach(row => tbody.appendChild(row));
            sortDirections[col] = !isAsc;
        }
    </script>
</body>
</html>
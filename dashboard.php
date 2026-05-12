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

// --- STRICT CATEGORY SQL MAP ---
$catSql = "";
if ($activeCategory === 'VPN_PEER') {
    $catSql = " (module LIKE '%IPSEC%' OR module LIKE '%VPDN%' OR module LIKE '%PPP%') ";
} elseif ($activeCategory === 'SNMP_LOGIN') {
    $catSql = " module LIKE '%SNMP%' ";
} elseif ($activeCategory === 'HIGH_UTILIZATION') {
    $catSql = " (event_type LIKE '%UTILIZATION%' OR event_type LIKE '%HIGH%' OR module LIKE '%CPU%' OR module = 'DEV_AUDIT') ";
} elseif ($activeCategory === 'PORT_SCAN_FLOOD') {
    $catSql = " (module LIKE '%NETDEFEND%' OR event_type LIKE '%FLOOD%') "; 
} elseif ($activeCategory === 'ARP_SPOOF_CONFLICT') {
    $catSql = " (module = 'ARP' OR event_type LIKE '%DUPADDR%' OR event_type LIKE '%CONFLICT%') "; 
} elseif ($activeCategory === 'DEFENDED') {
    $catSql = " (module = 'NETDEFEND' OR module = 'ARP' OR event_type LIKE '%DUPADDR%' OR event_type LIKE '%CONFLICT%' OR ((module LIKE '%IPSEC%' OR module LIKE '%VPDN%' OR module LIKE '%PPP%') AND (event_type LIKE '%FAIL%' OR event_type LIKE '%DROP%' OR event_type LIKE '%ERROR%' OR LOWER(message) LIKE '%fail%'))) ";
} elseif ($activeCategory === 'OTHER_ANOMALIES') {
    $catSql = " severity <= 4 AND NOT (module LIKE '%IPSEC%' OR module LIKE '%VPDN%' OR module LIKE '%PPP%' OR module LIKE '%SNMP%' OR event_type LIKE '%UTILIZATION%' OR event_type LIKE '%HIGH%' OR module LIKE '%CPU%' OR module = 'DEV_AUDIT' OR module LIKE '%NETDEFEND%' OR event_type LIKE '%FLOOD%' OR module = 'ARP' OR event_type LIKE '%DUPADDR%' OR event_type LIKE '%CONFLICT%') ";
}

$tableWhereSql = $baseWhereSql;
if (!empty($catSql)) {
    $tableWhereSql .= empty($tableWhereSql) ? " WHERE " : " AND ";
    $tableWhereSql .= $catSql;
}

// --- GLOBAL SYSTEM ANALYTICS ---
$totalLogsStmt = $pdo->prepare("SELECT COUNT(*) FROM syslogs" . $baseWhereSql);
$totalLogsStmt->execute($params);
$totalLogs = $totalLogsStmt->fetchColumn();

$defendedQuery = "SELECT COUNT(*) FROM syslogs " . (empty($baseWhereSql) ? "WHERE" : $baseWhereSql . " AND ") . " (module = 'NETDEFEND' OR module = 'ARP' OR event_type LIKE '%DUPADDR%' OR event_type LIKE '%CONFLICT%' OR ((module LIKE '%IPSEC%' OR module LIKE '%VPDN%' OR module LIKE '%PPP%') AND (event_type LIKE '%FAIL%' OR event_type LIKE '%DROP%' OR event_type LIKE '%ERROR%' OR LOWER(message) LIKE '%fail%')))";
$defendedStmt = $pdo->prepare($defendedQuery);
$defendedStmt->execute($params);
$threatsDefended = $defendedStmt->fetchColumn();
$defenseRate = $totalLogs > 0 ? round(($threatsDefended / $totalLogs) * 100, 1) : 0;

// --- DYNAMIC THREAT CATEGORIZATION ENGINE ---
$attackStats = [
    'VPN_PEER' => 0, 
    'SNMP_LOGIN' => 0, 
    'HIGH_UTILIZATION' => 0, 
    'PORT_SCAN_FLOOD' => 0, 
    'ARP_SPOOF_CONFLICT' => 0, 
    'OTHER_ANOMALIES' => 0
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
        $attackStats['VPN_PEER'] += $count;
    } elseif (strpos($mod, 'SNMP') !== false) {
        $attackStats['SNMP_LOGIN'] += $count;
    } elseif (strpos($evt, 'UTILIZATION') !== false || strpos($evt, 'HIGH') !== false || strpos($mod, 'CPU') !== false || $mod === 'DEV_AUDIT') {
        $attackStats['HIGH_UTILIZATION'] += $count;
    } elseif (strpos($mod, 'NETDEFEND') !== false || strpos($evt, 'FLOOD') !== false) {
        $attackStats['PORT_SCAN_FLOOD'] += $count;
    } elseif ($mod === 'ARP' || strpos($evt, 'DUPADDR') !== false || strpos($evt, 'CONFLICT') !== false) {
        $attackStats['ARP_SPOOF_CONFLICT'] += $count; 
    } elseif ($severity <= 4) {
        $attackStats['OTHER_ANOMALIES'] += $count;
    }
}

// --- FETCH TABLE DATA ---
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Chroma IT</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .glass { background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.1); box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1); } 
        .glass-header { background: rgba(0, 0, 0, 0.2); } 
        ::-webkit-scrollbar { width: 8px; height: 8px; } 
        ::-webkit-scrollbar-track { background: rgba(255,255,255,0.05); border-radius: 10px; } 
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.2); border-radius: 10px; } 
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
                    <button onclick="toggleSidebar()" class="md:hidden p-2 bg-blue-600/50 hover:bg-blue-600 text-white rounded-lg transition backdrop-blur-md">☰</button>
                    <h1 class="text-3xl font-bold text-white tracking-wide">Security Analytics</h1>
                </div>
                
                <form method="GET" class="glass px-4 py-2 rounded-lg flex items-center gap-3 text-sm flex-wrap shadow-lg">
                    <input type="hidden" name="category" value="<?= htmlspecialchars($activeCategory) ?>">
                    <input type="hidden" name="limit" value="<?= htmlspecialchars($selectedLimit) ?>">
                    
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
                    <a href="dashboard.php" class="text-slate-400 hover:text-white transition">Clear</a>
                </form>
            </div>

            <div class="glass rounded-xl p-6 mb-8 border-l-4 border-l-blue-500 shadow-xl">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
                    <div>
                        <p class="text-sm text-slate-400 uppercase tracking-wider font-bold mb-1">Total System Events</p>
                        <p class="text-4xl font-black text-white"><?= number_format($totalLogs) ?></p>
                    </div>
                    
                    <a href="<?= buildUrl(['category' => 'DEFENDED']) ?>" class="block cursor-pointer hover:bg-white/5 p-3 -m-3 rounded-xl transition-all group <?= $activeCategory === 'DEFENDED' ? 'bg-white/10 ring-1 ring-emerald-500/50' : '' ?>">
                        <p class="text-sm text-slate-400 uppercase tracking-wider font-bold mb-1 group-hover:text-emerald-300 transition">Threats Defended</p>
                        <p class="text-4xl font-black text-emerald-400 group-hover:scale-105 transform origin-left transition duration-300"><?= number_format($threatsDefended) ?></p>
                    </a>

                    <div class="w-full">
                        <div class="flex justify-between text-sm mb-1">
                            <span class="text-slate-300 uppercase tracking-wider font-bold text-xs">Mitigation Rate</span>
                            <span class="text-emerald-400 font-bold"><?= $defenseRate ?>%</span>
                        </div>
                        <div class="w-full bg-slate-700 rounded-full h-3 overflow-hidden shadow-inner">
                            <div class="bg-gradient-to-r from-emerald-600 to-emerald-400 h-3 rounded-full transition-all duration-1000 shadow-[0_0_10px_rgba(52,211,153,0.5)]" style="width: <?= $defenseRate ?>%"></div>
                        </div>
                    </div>
                </div>
            </div>

            <h2 class="text-xl font-semibold text-slate-300 mb-4 uppercase tracking-widest text-sm">Threat Intelligence Report <span class="text-slate-500 lowercase normal-case text-xs ml-2">(Click to isolate)</span></h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 mb-8">
                <?php 
                $cards = [
                    ['id' => 'VPN_PEER', 'color' => 'orange', 'label' => 'VPN PEER', 'desc' => 'External attempts on VPN gateways. Failed logins count as defended.'], 
                    ['id' => 'SNMP_LOGIN', 'color' => 'yellow', 'label' => 'SNMP LOGIN', 'desc' => 'Unauthorized network polling and SNMP discovery probes.'], 
                    ['id' => 'HIGH_UTILIZATION', 'color' => 'purple', 'label' => 'HIGH UTILIZATION', 'desc' => 'CPU or memory spikes indicating stress or potential DDoS.'], 
                    ['id' => 'PORT_SCAN_FLOOD', 'color' => 'red', 'label' => 'PORT SCAN / FLOOD', 'desc' => 'External firewall (NETDEFEND) blocks against port scanning.'], 
                    ['id' => 'ARP_SPOOF_CONFLICT', 'color' => 'emerald', 'label' => 'ARP CONFLICT', 'desc' => 'Internal IP address duplications or ARP spoofing attacks.'],
                    ['id' => 'OTHER_ANOMALIES', 'color' => 'slate', 'label' => 'OTHER ANOMALIES', 'desc' => 'Catch-all for high-severity unclassified system errors.']
                ];
                
                foreach ($cards as $card): 
                    $count = $attackStats[$card['id']];
                    $colorClass = $count > 0 ? "text-{$card['color']}-400 drop-shadow-[0_0_8px_currentColor]" : "text-slate-500";
                    $borderClass = $count > 0 ? "border-{$card['color']}-500/50" : "border-white/10";
                    $activeBg = ($activeCategory === $card['id']) ? "bg-white/10 ring-1 ring-{$card['color']}-500/50" : "";
                ?>
                <a href="<?= buildUrl(['category' => $card['id']]) ?>" class="block glass p-4 rounded-xl <?= $borderClass ?> <?= $activeBg ?> hover:bg-white/10 hover:-translate-y-1 transition-all group shadow-md flex flex-col justify-between h-full">
                    <div>
                        <h4 class="text-[11px] text-slate-400 uppercase font-bold mb-1 group-hover:text-white transition truncate" title="<?= $card['label'] ?>"><?= $card['label'] ?></h4>
                        <p class="text-3xl font-black <?= $colorClass ?> mb-3"><?= number_format($count) ?></p>
                    </div>
                    <div class="mt-auto pt-3 border-t border-white/5">
                        <p class="text-[10px] leading-snug text-slate-500 group-hover:text-slate-300 transition-colors">
                            <?= $card['desc'] ?>
                        </p>
                    </div>
                </a>
                <?php endforeach; ?>
            </div>

            <div class="glass rounded-xl overflow-hidden flex flex-col mb-10 shadow-xl">
                <div class="p-4 glass-header flex flex-wrap justify-between items-center gap-4 border-b border-white/10">
                    <div>
                        <h2 class="text-lg font-bold text-white">Network Events Log</h2>
                        <p class="text-xs text-slate-400 mt-1">Click on any row to view full raw log details.</p>
                    </div>
                    
                    <form method="GET" id="limitForm" class="flex items-center gap-2">
                        <input type="hidden" name="category" value="<?= htmlspecialchars($activeCategory) ?>">
                        <input type="hidden" name="branch_id" value="<?= htmlspecialchars($selectedBranch) ?>">
                        <input type="hidden" name="start_date" value="<?= htmlspecialchars($startDate) ?>">
                        <input type="hidden" name="end_date" value="<?= htmlspecialchars($endDate) ?>">
                        
                        <label class="text-sm text-slate-400">Show:</label>
                        <select name="limit" onchange="document.getElementById('limitForm').submit()" class="bg-slate-800 text-white text-sm border border-slate-600 rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-blue-500">
                            <?php foreach(['20','50','100','500','ALL'] as $v): ?>
                                <option value="<?= $v ?>" <?= $selectedLimit == $v ? 'selected' : '' ?>><?= $v ?></option>
                            <?php endforeach; ?>
                        </select>
                        <span class="text-sm text-slate-400 hidden sm:inline">entries</span>
                        
                        <?php if($activeCategory !== 'ALL'): ?>
                            <a href="<?= buildUrl(['category' => 'ALL']) ?>" class="ml-2 bg-slate-700 hover:bg-slate-600 px-3 py-1 rounded text-sm text-white transition shadow-md">Clear Filter</a>
                        <?php endif; ?>
                    </form>
                </div>
                
                <div class="overflow-x-auto overflow-y-auto max-h-[600px] w-full">
                    <table class="w-full text-left border-collapse" id="eventsTable">
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
                            <?php foreach($recentLogs as $log): 
                                
                                // Determine if this specific log is classified as Defended
                                $m = strtoupper($log['module']);
                                $e = strtoupper($log['event_type']);
                                $msg = strtolower($log['message']);
                                $isDefended = false;
                                
                                if ($m === 'NETDEFEND' || $m === 'ARP' || strpos($e, 'DUPADDR') !== false || strpos($e, 'CONFLICT') !== false) {
                                    $isDefended = true;
                                } elseif (in_array($m, ['IPSEC', 'VPDN', 'PPP']) && (strpos($e, 'FAIL') !== false || strpos($e, 'DROP') !== false || strpos($e, 'ERROR') !== false || strpos($msg, 'fail') !== false)) {
                                    $isDefended = true;
                                }
                            ?>
                            
                            <tr class="hover:bg-white/10 transition log-row cursor-pointer group"
                                data-date="<?= htmlspecialchars($log['log_date']) ?>"
                                data-module="<?= htmlspecialchars($log['module']) ?>"
                                data-severity="<?= htmlspecialchars($log['severity']) ?>"
                                data-event="<?= htmlspecialchars($log['event_type']) ?>"
                                data-message="<?= htmlspecialchars($log['message']) ?>"
                                data-raw="<?= htmlspecialchars($log['raw_log']) ?>"
                                data-defended="<?= $isDefended ? 'true' : 'false' ?>"
                                onclick="openLogModal(this)">
                                
                                <td class="p-4 text-slate-300 whitespace-nowrap group-hover:text-white"><?= htmlspecialchars($log['log_date']) ?></td>
                                <td class="p-4 font-semibold text-blue-400"><?= htmlspecialchars($log['module']) ?></td>
                                <td class="p-4 whitespace-nowrap">
                                    <span class="px-2 py-1 rounded-md text-xs font-bold border <?= $log['severity'] <= 4 ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' ?>">
                                        Lvl <?= htmlspecialchars($log['severity']) ?>
                                    </span>
                                </td>
                                <td class="p-4 font-medium text-slate-200 group-hover:text-white flex items-center gap-2">
                                    <span class="truncate max-w-[150px] sm:max-w-none" title="<?= htmlspecialchars($log['event_type']) ?>"><?= htmlspecialchars($log['event_type']) ?></span>
                                    <?php if($isDefended): ?>
                                        <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 whitespace-nowrap" title="Successfully Defended or Mitigated">
                                            🛡️ DEFENDED
                                        </span>
                                    <?php endif; ?>
                                </td>
                                <td class="p-4 text-slate-400 truncate max-w-xs md:max-w-md transition-all group-hover:text-blue-300">
                                    <?= htmlspecialchars($log['message']) ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                            
                            <?php if(empty($recentLogs)): ?>
                            <tr>
                                <td colspan="5" class="p-8 text-center text-slate-500 font-medium">No log entries found.</td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </main>

    <div id="logModal" class="fixed inset-0 z-[100] hidden items-center justify-center bg-black/70 backdrop-blur-sm p-4 opacity-0 transition-opacity duration-300">
        <div class="glass w-full max-w-3xl rounded-2xl shadow-2xl border-t-4 border-t-blue-500 relative transform scale-95 transition-transform duration-300 flex flex-col max-h-[90vh]" id="logModalContent">
            
            <button onclick="closeLogModal()" class="absolute top-4 right-4 text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 p-2 rounded-full transition z-10">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>

            <div class="p-6 md:p-8 overflow-y-auto">
                <div class="flex items-center gap-3 mb-6">
                    <span class="bg-blue-500/20 p-2 rounded-lg border border-blue-500/30">
                        <svg class="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                    </span>
                    <h2 class="text-2xl font-bold text-white flex-1">Detailed Log Inspector</h2>
                    
                    <div id="modalDefendedBadge" class="hidden items-center px-3 py-1 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-bold text-sm shadow-[0_0_10px_rgba(52,211,153,0.3)]">
                        🛡️ SYSTEM DEFENDED
                    </div>
                </div>
                
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                    <div class="bg-black/20 p-4 rounded-xl border border-white/5 flex flex-col justify-center">
                        <span class="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Timestamp</span>
                        <span id="modalDate" class="text-slate-200 font-medium text-sm"></span>
                    </div>
                    <div class="bg-black/20 p-4 rounded-xl border border-white/5 flex flex-col justify-center">
                        <span class="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Severity</span>
                        <span id="modalSeverity" class="font-bold text-sm"></span>
                    </div>
                    <div class="bg-black/20 p-4 rounded-xl border border-white/5 flex flex-col justify-center overflow-hidden">
                        <span class="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Module</span>
                        <span id="modalModule" class="text-blue-400 font-bold text-sm truncate"></span>
                    </div>
                    <div class="bg-black/20 p-4 rounded-xl border border-white/5 flex flex-col justify-center">
                        <span class="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Event Action</span>
                        <span id="modalEvent" class="text-slate-200 font-medium text-sm break-all md:break-words line-clamp-2" title=""></span>
                    </div>
                </div>

                <div class="mb-6">
                    <span class="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2">Parsed Event Description</span>
                    <div id="modalMessage" class="bg-blue-900/20 p-5 rounded-xl border border-blue-500/20 text-slate-200 text-sm break-words leading-relaxed"></div>
                </div>

                <div>
                    <span class="block text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-2 flex items-center gap-2">
                        Raw Syslog Output 
                        <span class="bg-slate-700 text-slate-300 text-[9px] px-2 py-0.5 rounded">TERMINAL</span>
                    </span>
                    <div id="modalRaw" class="bg-[#0f172a] p-4 rounded-xl border border-slate-700 text-emerald-400 font-mono text-xs overflow-x-auto whitespace-pre-wrap shadow-inner leading-relaxed max-h-48 overflow-y-auto"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Modal Logic
        function openLogModal(row) {
            document.getElementById('modalDate').innerText = row.getAttribute('data-date');
            document.getElementById('modalModule').innerText = row.getAttribute('data-module');
            
            const eventText = row.getAttribute('data-event');
            const eventEl = document.getElementById('modalEvent');
            eventEl.innerText = eventText;
            eventEl.title = eventText; // For hover on long text
            
            document.getElementById('modalMessage').innerText = row.getAttribute('data-message');
            document.getElementById('modalRaw').innerText = row.getAttribute('data-raw');

            // Severity Coloring
            const sev = parseInt(row.getAttribute('data-severity'));
            const sevEl = document.getElementById('modalSeverity');
            sevEl.innerText = 'Level ' + sev;
            sevEl.className = sev <= 4 ? 'text-red-400 font-bold text-sm' : 'text-emerald-400 font-bold text-sm';

            // Defended Badge logic
            const isDefended = row.getAttribute('data-defended') === 'true';
            const badgeEl = document.getElementById('modalDefendedBadge');
            if (isDefended) {
                badgeEl.classList.remove('hidden');
                badgeEl.classList.add('flex');
            } else {
                badgeEl.classList.add('hidden');
                badgeEl.classList.remove('flex');
            }

            const modal = document.getElementById('logModal');
            const content = document.getElementById('logModalContent');
            
            modal.classList.remove('hidden');
            modal.classList.add('flex');
            
            // Trigger animation
            setTimeout(() => {
                modal.classList.remove('opacity-0');
                content.classList.remove('scale-95');
                content.classList.add('scale-100');
            }, 10);
        }

        function closeLogModal() {
            const modal = document.getElementById('logModal');
            const content = document.getElementById('logModalContent');
            
            modal.classList.add('opacity-0');
            content.classList.remove('scale-100');
            content.classList.add('scale-95');
            
            setTimeout(() => {
                modal.classList.add('hidden');
                modal.classList.remove('flex');
            }, 300);
        }

        // Close modal on escape key or clicking outside
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeLogModal();
        });
        document.getElementById('logModal').addEventListener('click', (e) => {
            if (e.target === document.getElementById('logModal')) closeLogModal();
        });

        // Front-end Table Sorting Logic
        let sortDirections = [true, true, true, true]; 
        
        function sortTable(col) {
            const tbody = document.getElementById("eventsBody");
            const rows = Array.from(tbody.querySelectorAll("tr.log-row"));
            const isAsc = sortDirections[col];
            
            rows.sort((a, b) => {
                let cellA = a.cells[col].innerText.trim();
                let cellB = b.cells[col].innerText.trim();
                
                // If sorting severity, strip the text to compare the integer values
                if (col === 2) { 
                    cellA = parseInt(cellA.replace(/\D/g, '')) || 0; 
                    cellB = parseInt(cellB.replace(/\D/g, '')) || 0; 
                    return isAsc ? cellA - cellB : cellB - cellA; 
                }
                
                return isAsc ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
            });
            
            rows.forEach(row => tbody.appendChild(row));
            sortDirections[col] = !isAsc;
        }
    </script>
</body>
</html>
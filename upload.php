<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) { header("Location: index.php"); exit; }
require 'includes/db.php';

$message = '';
$uploadDir = 'uploads/';
if (!is_dir($uploadDir)) { mkdir($uploadDir, 0777, true); }

// --- HANDLE DELETE ---
if (isset($_GET['delete'])) {
    $fileId = (int)$_GET['delete'];
    $stmt = $pdo->prepare("SELECT filename FROM uploaded_files WHERE id = ?");
    $stmt->execute([$fileId]);
    $fileRecord = $stmt->fetch();
    
    if ($fileRecord) {
        $filePath = $uploadDir . $fileRecord['filename'];
        if (file_exists($filePath)) { unlink($filePath); }
        $pdo->prepare("DELETE FROM syslogs WHERE file_id = ?")->execute([$fileId]);
        $pdo->prepare("DELETE FROM uploaded_files WHERE id = ?")->execute([$fileId]);
        $message = "<div class='bg-emerald-500/20 border border-emerald-500/50 text-emerald-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>File and associated logs deleted.</div>";
    }
}

// --- HANDLE UPLOAD WITH BRANCH LOGIC ---
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['syslog_file'])) {
    $file = $_FILES['syslog_file'];
    $branchSelection = $_POST['branch_id'] ?? '';
    $finalBranchId = null;

    // Determine Branch
    if ($branchSelection === 'new') {
        $newBranchName = trim($_POST['new_branch_name']);
        if (!empty($newBranchName)) {
            $stmt = $pdo->prepare("INSERT IGNORE INTO branches (name) VALUES (?)");
            $stmt->execute([$newBranchName]);
            
            $stmt = $pdo->prepare("SELECT id FROM branches WHERE name = ?");
            $stmt->execute([$newBranchName]);
            $finalBranchId = $stmt->fetchColumn();
        }
    } else {
        $finalBranchId = (int)$branchSelection;
    }

    if ($file['type'] == 'text/plain' && $file['error'] == 0 && $finalBranchId) {
        $originalName = basename($file['name']);
        $uniqueFilename = time() . '_' . preg_replace("/[^a-zA-Z0-9.]/", "_", $originalName);
        $destination = $uploadDir . $uniqueFilename;
        
        if (move_uploaded_file($file['tmp_name'], $destination)) {
            $content = file($destination);
            $inserted = 0;
            
            // Insert File Record
            $stmtFile = $pdo->prepare("INSERT INTO uploaded_files (filename, original_name, branch_id) VALUES (?, ?, ?)");
            $stmtFile->execute([$uniqueFilename, $originalName, $finalBranchId]);
            $newFileId = $pdo->lastInsertId();
            
            // Insert Logs
            $pdo->beginTransaction();
            $stmtLog = $pdo->prepare("INSERT INTO syslogs (file_id, branch_id, log_date, module, severity, event_type, message, raw_log) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");

            foreach ($content as $line) {
                $line = trim($line);
                if (empty($line)) continue;
                $cleanLine = preg_replace('/^\\s*/', '', $line);
                $pattern = '/^\*?([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}):\s+%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+):\s+(.*)/';
                
                if (preg_match($pattern, $cleanLine, $matches)) {
                    $stmtLog->execute([$newFileId, $finalBranchId, $matches[1], $matches[2], $matches[3], $matches[4], $matches[5], $line]);
                    $inserted++;
                }
            }
            $pdo->commit();
            
            $pdo->prepare("UPDATE uploaded_files SET total_logs = ? WHERE id = ?")->execute([$inserted, $newFileId]);
            $message = "<div class='bg-blue-500/20 border border-blue-500/50 text-blue-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>Imported <strong>$inserted</strong> log entries.</div>";
        }
    } else {
        $message = "<div class='bg-orange-500/20 border border-orange-500/50 text-orange-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>Invalid file or missing branch selection.</div>";
    }
}

$branches = $pdo->query("SELECT * FROM branches ORDER BY name ASC")->fetchAll(PDO::FETCH_ASSOC);
$uploadedFiles = $pdo->query("SELECT u.*, b.name as branch_name FROM uploaded_files u LEFT JOIN branches b ON u.branch_id = b.id ORDER BY u.uploaded_at DESC")->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload - Chroma IT</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>.glass { background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.1); box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1); } .glass-header { background: rgba(0, 0, 0, 0.2); } ::-webkit-scrollbar { width: 8px; height: 8px; } ::-webkit-scrollbar-track { background: rgba(255,255,255,0.05); border-radius: 10px; } ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.2); border-radius: 10px; }</style>
</head>
<body class="bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 text-slate-200 flex h-screen overflow-hidden font-sans">
    <?php include 'includes/sidebar.php'; ?>
    <main class="flex-1 p-4 md:p-8 overflow-y-auto w-full relative">
        <div class="absolute top-[-10%] left-[-10%] w-96 h-96 bg-blue-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none"></div>
        <div class="absolute bottom-[-10%] right-[-10%] w-96 h-96 bg-purple-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none"></div>

        <div class="relative z-10 max-w-6xl mx-auto">
            <div class="flex items-center gap-4 mb-6">
                <button onclick="toggleSidebar()" class="md:hidden p-2 bg-blue-600/50 hover:bg-blue-600 text-white rounded-lg backdrop-blur-md transition">☰</button>
                <h1 class="text-3xl font-bold text-white tracking-wide">Upload Data</h1>
            </div>
            
            <?= $message ?>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div class="glass p-8 rounded-xl shadow-lg border-t-4 border-t-blue-500 h-fit">
                    <h2 class="text-xl font-semibold text-white mb-6">Import Syslog</h2>
                    
                    <form method="POST" enctype="multipart/form-data" class="w-full flex flex-col items-center">
                        <div class="w-full mb-6 text-left">
                            <label class="block text-slate-400 text-xs font-bold uppercase mb-2">Target Branch</label>
                            <select name="branch_id" id="branchSelect" required class="w-full p-3 bg-black/30 border border-white/20 text-white rounded-lg focus:outline-none focus:border-blue-500">
                                <option value="">-- Select Branch --</option>
                                <?php foreach($branches as $b): ?>
                                    <option value="<?= $b['id'] ?>"><?= htmlspecialchars($b['name']) ?></option>
                                <?php endforeach; ?>
                                <option value="new" class="font-bold text-blue-400">+ Add New Branch</option>
                            </select>
                            <input type="text" name="new_branch_name" id="newBranchInput" class="w-full mt-3 p-3 bg-black/30 border border-blue-500/50 text-white rounded-lg hidden placeholder-slate-500" placeholder="Type new branch name...">
                        </div>

                        <div class="w-full border-2 border-dashed border-white/20 rounded-xl p-6 bg-black/10 hover:bg-white/5 transition flex flex-col items-center mb-6">
                            <svg class="w-10 h-10 text-blue-400 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                            <input type="file" name="syslog_file" accept=".txt" required class="block w-full text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:font-bold file:bg-blue-500/20 file:text-blue-400 hover:file:bg-blue-500/40 transition cursor-pointer">
                        </div>
                        
                        <button type="submit" class="w-full bg-blue-600 hover:bg-blue-500 text-white py-3 rounded-lg shadow-lg transition font-bold tracking-wide">
                            Process & Import Logs
                        </button>
                    </form>
                </div>

                <div class="lg:col-span-2 glass rounded-xl flex flex-col h-full max-h-[700px]">
                    <div class="p-6 glass-header border-b border-white/10 shrink-0">
                        <h2 class="text-lg font-bold text-white">File Manager</h2>
                    </div>
                    
                    <div class="overflow-y-auto flex-1 w-full p-4">
                        <table class="w-full text-left border-collapse">
                            <thead>
                                <tr class="text-slate-400 text-xs uppercase tracking-wider border-b border-white/10">
                                    <th class="pb-3 px-2">Filename</th>
                                    <th class="pb-3 px-2">Branch</th>
                                    <th class="pb-3 px-2">Upload Date</th>
                                    <th class="pb-3 px-2">Logs Parsed</th>
                                    <th class="pb-3 px-2 text-right">Action</th>
                                </tr>
                            </thead>
                            <tbody class="text-sm divide-y divide-white/5">
                                <?php foreach($uploadedFiles as $file): ?>
                                <tr class="hover:bg-white/5 transition">
                                    <td class="py-4 px-2 font-medium text-slate-200"><?= htmlspecialchars($file['original_name']) ?></td>
                                    <td class="py-4 px-2 font-bold text-blue-400"><?= htmlspecialchars($file['branch_name'] ?? 'Unknown') ?></td>
                                    <td class="py-4 px-2 text-slate-400"><?= date('M d, Y h:i A', strtotime($file['uploaded_at'])) ?></td>
                                    <td class="py-4 px-2 text-emerald-400 font-semibold"><?= number_format($file['total_logs']) ?></td>
                                    <td class="py-4 px-2 text-right">
                                        <a href="?delete=<?= $file['id'] ?>" onclick="return confirm('Delete this file and all its logs?')" class="px-3 py-1 bg-red-500/10 text-red-400 rounded text-xs font-bold border border-red-500/30 hover:bg-red-500 hover:text-white transition">Delete</a>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </main>
    <script>
        document.getElementById('branchSelect').addEventListener('change', function() {
            const input = document.getElementById('newBranchInput');
            if (this.value === 'new') {
                input.classList.remove('hidden');
                input.required = true;
            } else {
                input.classList.add('hidden');
                input.required = false;
            }
        });
    </script>
</body>
</html>
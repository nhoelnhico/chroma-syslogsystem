<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) { header("Location: index.php"); exit; }
require 'includes/db.php';

$message = '';

// Ensure upload directory exists
$uploadDir = 'uploads/';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

// --- HANDLE DELETE ---
if (isset($_GET['delete'])) {
    $fileId = (int)$_GET['delete'];
    
    // Fetch file details
    $stmt = $pdo->prepare("SELECT filename FROM uploaded_files WHERE id = ?");
    $stmt->execute([$fileId]);
    $fileRecord = $stmt->fetch();
    
    if ($fileRecord) {
        // Delete physical file
        $filePath = $uploadDir . $fileRecord['filename'];
        if (file_exists($filePath)) {
            unlink($filePath);
        }
        
        // Delete associated logs from syslogs table
        $pdo->prepare("DELETE FROM syslogs WHERE file_id = ?")->execute([$fileId]);
        
        // Delete the file record itself
        $pdo->prepare("DELETE FROM uploaded_files WHERE id = ?")->execute([$fileId]);
        
        $message = "<div class='bg-emerald-500/20 border border-emerald-500/50 text-emerald-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>File and all associated network logs were successfully deleted.</div>";
    }
}

// --- HANDLE UPLOAD ---
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['syslog_file'])) {
    $file = $_FILES['syslog_file'];
    
    // Check if it's a text file
    if ($file['type'] == 'text/plain' && $file['error'] == 0) {
        
        $originalName = basename($file['name']);
        $uniqueFilename = time() . '_' . preg_replace("/[^a-zA-Z0-9.]/", "_", $originalName);
        $destination = $uploadDir . $uniqueFilename;
        
        if (move_uploaded_file($file['tmp_name'], $destination)) {
            $content = file($destination);
            $inserted = 0;
            
            // 1. Create the File Record first to get the ID
            $stmtFile = $pdo->prepare("INSERT INTO uploaded_files (filename, original_name) VALUES (?, ?)");
            $stmtFile->execute([$uniqueFilename, $originalName]);
            $newFileId = $pdo->lastInsertId();
            
            // 2. Parse and Insert Logs (Using Transaction for extreme speed)
            $pdo->beginTransaction();
            $stmtLog = $pdo->prepare("INSERT INTO syslogs (file_id, log_date, module, severity, event_type, message, raw_log) VALUES (?, ?, ?, ?, ?, ?, ?)");

            foreach ($content as $line) {
                $line = trim($line);
                if (empty($line)) continue;

                $cleanLine = preg_replace('/^\\s*/', '', $line);
                $pattern = '/^\*?([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}):\s+%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+):\s+(.*)/';
                
                if (preg_match($pattern, $cleanLine, $matches)) {
                    $stmtLog->execute([
                        $newFileId,
                        $matches[1], // Date
                        $matches[2], // Module
                        $matches[3], // Severity
                        $matches[4], // Event
                        $matches[5], // Message
                        $line        // Raw
                    ]);
                    $inserted++;
                }
            }
            $pdo->commit();
            
            // 3. Update the file record with the total count
            $pdo->prepare("UPDATE uploaded_files SET total_logs = ? WHERE id = ?")->execute([$inserted, $newFileId]);
            
            $message = "<div class='bg-blue-500/20 border border-blue-500/50 text-blue-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>Successfully processed and imported <strong>$inserted</strong> log entries from $originalName.</div>";
        } else {
            $message = "<div class='bg-red-500/20 border border-red-500/50 text-red-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>Error moving uploaded file. Check folder permissions.</div>";
        }
    } else {
        $message = "<div class='bg-orange-500/20 border border-orange-500/50 text-orange-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>Invalid file. Please upload a valid .txt Syslog file.</div>";
    }
}

// Fetch recently uploaded files
$uploadedFiles = $pdo->query("SELECT * FROM uploaded_files ORDER BY uploaded_at DESC")->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Syslog - Chroma IT</title>
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
    </style>
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
                
                <div class="glass p-8 rounded-xl shadow-lg border-t-4 border-t-blue-500 flex flex-col items-center justify-center h-fit">
                    <h2 class="text-xl font-semibold text-white mb-6 w-full text-left">Import Ruijie Syslog</h2>
                    
                    <form method="POST" enctype="multipart/form-data" class="w-full flex flex-col items-center border-2 border-dashed border-white/20 rounded-xl p-10 bg-black/10 hover:bg-white/5 hover:border-blue-500/50 transition duration-300">
                        <svg class="w-16 h-16 text-blue-400 mb-4 drop-shadow-[0_0_8px_rgba(96,165,250,0.5)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                        
                        <label class="block text-slate-300 text-sm font-medium mb-4 text-center">Drag and drop or browse to upload your .txt log file.</label>
                        
                        <input type="file" name="syslog_file" accept=".txt" required class="block w-full text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-bold file:bg-blue-500/20 file:text-blue-400 file:border file:border-blue-500/50 hover:file:bg-blue-500/40 hover:file:text-white transition-all mb-8 cursor-pointer">
                        
                        <button type="submit" class="w-full bg-blue-600 hover:bg-blue-500 text-white py-3 rounded-lg shadow-[0_0_15px_rgba(37,99,235,0.4)] transition font-bold tracking-wide">
                            Process & Import Logs
                        </button>
                    </form>
                </div>

                <div class="lg:col-span-2 glass rounded-xl overflow-hidden flex flex-col h-full max-h-[700px]">
                    <div class="p-6 glass-header border-b border-white/10 shrink-0">
                        <h2 class="text-lg font-bold text-white">File Manager</h2>
                        <p class="text-xs text-slate-400">View and manage uploaded log files.</p>
                    </div>
                    
                    <div class="overflow-y-auto flex-1 w-full p-4">
                        <table class="w-full text-left border-collapse">
                            <thead>
                                <tr class="text-slate-400 text-xs uppercase tracking-wider border-b border-white/10">
                                    <th class="pb-3 px-2">Filename</th>
                                    <th class="pb-3 px-2">Upload Date</th>
                                    <th class="pb-3 px-2">Logs Parsed</th>
                                    <th class="pb-3 px-2 text-right">Action</th>
                                </tr>
                            </thead>
                            <tbody class="text-sm divide-y divide-white/5">
                                <?php foreach($uploadedFiles as $file): ?>
                                <tr class="hover:bg-white/5 transition group">
                                    <td class="py-4 px-2 font-medium text-slate-200 break-all">
                                        <div class="flex items-center gap-2">
                                            <svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                                            <?= htmlspecialchars($file['original_name']) ?>
                                        </div>
                                    </td>
                                    <td class="py-4 px-2 text-slate-400"><?= date('M d, Y h:i A', strtotime($file['uploaded_at'])) ?></td>
                                    <td class="py-4 px-2 text-emerald-400 font-semibold"><?= number_format($file['total_logs']) ?></td>
                                    <td class="py-4 px-2 text-right">
                                        <a href="?delete=<?= $file['id'] ?>" onclick="return confirm('WARNING: Are you sure? This will delete the file AND permanently remove its <?= $file['total_logs'] ?> logs from the dashboard.')" class="inline-block px-3 py-1 bg-red-500/10 text-red-400 hover:bg-red-500 hover:text-white border border-red-500/30 hover:border-red-500 rounded text-xs font-bold transition-all shadow-sm">
                                            Delete
                                        </a>
                                    </td>
                                </tr>
                                <?php endforeach; ?>

                                <?php if(empty($uploadedFiles)): ?>
                                <tr>
                                    <td colspan="4" class="py-8 text-center text-slate-500">No files uploaded yet.</td>
                                </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>
        </div>
    </main>
</body>
</html>
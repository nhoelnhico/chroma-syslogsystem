<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) { header("Location: index.php"); exit; }
require 'includes/db.php';

$message = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['syslog_file'])) {
    $file = $_FILES['syslog_file'];
    
    if ($file['type'] == 'text/plain' && $file['error'] == 0) {
        $content = file($file['tmp_name']);
        $inserted = 0;
        
        $stmt = $pdo->prepare("INSERT INTO syslogs (log_date, module, severity, event_type, message, raw_log) VALUES (?, ?, ?, ?, ?, ?)");

        foreach ($content as $line) {
            $line = trim($line);
            if (empty($line)) continue;

            // Remove "" artifact if present
            $cleanLine = preg_replace('/^\\s*/', '', $line);
            
            // Regex to match: *Apr 24 23:25:28: %ROUTE_DB-5-UPDATE: System updates...
            $pattern = '/^\*?([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}):\s+%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+):\s+(.*)/';
            
            if (preg_match($pattern, $cleanLine, $matches)) {
                $stmt->execute([
                    $matches[1], // Date/Time
                    $matches[2], // Module (e.g. ARP)
                    $matches[3], // Severity
                    $matches[4], // Event Type (e.g. DUPADDR)
                    $matches[5], // Description
                    $line        // Raw
                ]);
                $inserted++;
            }
        }
        $message = "<div class='bg-green-100 text-green-700 p-4 rounded-lg mb-4'>Successfully processed and saved $inserted log entries.</div>";
    } else {
        $message = "<div class='bg-red-100 text-red-700 p-4 rounded-lg mb-4'>Please upload a valid .txt file.</div>";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Syslog</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 flex h-screen overflow-hidden">
    <?php include 'includes/sidebar.php'; ?>

    <main class="flex-1 p-8 overflow-y-auto w-full">
        <button onclick="toggleSidebar()" class="md:hidden mb-4 p-2 bg-blue-600 text-white rounded">☰ Menu</button>
        <h1 class="text-3xl font-bold text-gray-800 mb-6">Upload Syslog Data</h1>
        
        <?= $message ?>

        <div class="bg-white p-8 rounded-xl shadow-sm border">
            <form method="POST" enctype="multipart/form-data" class="flex flex-col items-center border-2 border-dashed border-gray-300 rounded-lg p-10">
                <svg class="w-16 h-16 text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                <label class="block text-gray-700 text-lg font-medium mb-4 text-center">Select Ruijie .txt log file to analyze</label>
                <input type="file" name="syslog_file" accept=".txt" required class="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 mb-6">
                <button type="submit" class="bg-blue-600 text-white px-8 py-3 rounded-lg shadow hover:bg-blue-700 transition font-bold">Upload & Parse</button>
            </form>
        </div>
    </main>
</body>
</html>
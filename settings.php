<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) { header("Location: index.php"); exit; }
require 'includes/db.php';

$message = '';

// --- 1. HANDLE SYSTEM DATA RESET ---
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'reset_data') {
    try {
        // Truncate tables to reset IDs to 1
        $pdo->exec("SET FOREIGN_KEY_CHECKS = 0;");
        $pdo->exec("TRUNCATE TABLE syslogs;");
        $pdo->exec("TRUNCATE TABLE uploaded_files;");
        $pdo->exec("SET FOREIGN_KEY_CHECKS = 1;");

        // Delete all physical files in the uploads folder
        $uploadDir = 'uploads/';
        if (is_dir($uploadDir)) {
            $files = glob($uploadDir . '*'); 
            foreach ($files as $file) {
                if (is_file($file)) {
                    unlink($file); 
                }
            }
        }
        $message = "<div class='bg-emerald-500/20 border border-emerald-500/50 text-emerald-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'><strong>Success!</strong> All network logs and uploaded files have been permanently wiped. System is restored to original state.</div>";
    } catch (Exception $e) {
        $message = "<div class='bg-red-500/20 border border-red-500/50 text-red-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>Error resetting data: " . $e->getMessage() . "</div>";
    }
}

// --- 2. HANDLE USER ADD ---
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'add_user') {
    $user = trim($_POST['username']);
    $pass = $_POST['password'];
    
    $check = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
    $check->execute([$user]);
    if ($check->fetchColumn() > 0) {
        $message = "<div class='bg-red-500/20 border border-red-500/50 text-red-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>Username already exists!</div>";
    } else {
        $hash = password_hash($pass, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->execute([$user, $hash]);
        $message = "<div class='bg-blue-500/20 border border-blue-500/50 text-blue-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>New administrator successfully created.</div>";
    }
}

// --- 3. HANDLE USER EDIT/UPDATE ---
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'edit_user') {
    $id = (int)$_POST['user_id'];
    $newUser = trim($_POST['username']);
    $newPass = $_POST['password'];

    if (!empty($newPass)) {
        // Update username AND password
        $hash = password_hash($newPass, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("UPDATE users SET username = ?, password = ? WHERE id = ?");
        $stmt->execute([$newUser, $hash, $id]);
    } else {
        // Update ONLY username (keep old password)
        $stmt = $pdo->prepare("UPDATE users SET username = ? WHERE id = ?");
        $stmt->execute([$newUser, $id]);
    }
    
    // If they updated their own username, update the session
    if ($_SESSION['username'] == $_POST['old_username']) {
        $_SESSION['username'] = $newUser;
    }
    
    $message = "<div class='bg-blue-500/20 border border-blue-500/50 text-blue-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>Administrator profile successfully updated.</div>";
}

// --- 4. HANDLE USER DELETE ---
if (isset($_GET['delete'])) {
    $id = (int)$_GET['delete'];
    
    // Prevent deleting the currently logged-in user
    $stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
    $stmt->execute([$id]);
    $targetUser = $stmt->fetchColumn();

    if ($targetUser === $_SESSION['username']) {
        $message = "<div class='bg-orange-500/20 border border-orange-500/50 text-orange-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>You cannot delete your own active session account.</div>";
    } elseif ($targetUser === 'admin') {
        $message = "<div class='bg-orange-500/20 border border-orange-500/50 text-orange-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>The primary 'admin' account cannot be deleted.</div>";
    } else {
        $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$id]);
        $message = "<div class='bg-blue-500/20 border border-blue-500/50 text-blue-400 p-4 rounded-xl mb-6 shadow-lg backdrop-blur-md'>User successfully deleted.</div>";
    }
}

// Fetch all users
$users = $pdo->query("SELECT id, username, created_at FROM users ORDER BY created_at ASC")->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - Chroma IT</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .glass { background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.1); box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1); }
        .glass-header { background: rgba(0, 0, 0, 0.2); }
    </style>
</head>
<body class="bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 text-slate-200 flex h-screen overflow-hidden font-sans">
    
    <?php include 'includes/sidebar.php'; ?>

    <main class="flex-1 p-4 md:p-8 overflow-y-auto w-full relative">
        <div class="absolute top-[-10%] left-[-10%] w-96 h-96 bg-blue-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none"></div>
        <div class="absolute bottom-[-10%] right-[-10%] w-96 h-96 bg-purple-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none"></div>

        <div class="relative z-10 max-w-7xl mx-auto">
            <div class="flex items-center gap-4 mb-8">
                <button onclick="toggleSidebar()" class="md:hidden p-2 bg-blue-600/50 hover:bg-blue-600 text-white rounded-lg backdrop-blur-md transition">☰</button>
                <h1 class="text-3xl font-bold text-white tracking-wide">System Settings</h1>
            </div>

            <?= $message ?>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                
                <div class="lg:col-span-2 space-y-8">
                    
                    <div class="glass rounded-xl overflow-hidden shadow-lg">
                        <div class="p-6 glass-header border-b border-white/10 flex justify-between items-center">
                            <div>
                                <h2 class="text-lg font-bold text-white">Administrator Accounts</h2>
                                <p class="text-xs text-slate-400">Manage who has access to the Syslog Dashboard.</p>
                            </div>
                        </div>
                        
                        <div class="overflow-x-auto p-4">
                            <table class="w-full text-left border-collapse">
                                <thead>
                                    <tr class="text-slate-400 text-xs uppercase tracking-wider border-b border-white/10">
                                        <th class="pb-3 px-4">Username</th>
                                        <th class="pb-3 px-4">Date Created</th>
                                        <th class="pb-3 px-4 text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody class="text-sm divide-y divide-white/5">
                                    <?php foreach($users as $u): ?>
                                    <tr class="hover:bg-white/5 transition group">
                                        <td class="py-4 px-4 font-bold text-blue-400">
                                            <?= htmlspecialchars($u['username']) ?>
                                            <?php if($u['username'] == $_SESSION['username']): ?>
                                                <span class="ml-2 text-[10px] bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded-full border border-blue-500/30">YOU</span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="py-4 px-4 text-slate-400"><?= date('M d, Y', strtotime($u['created_at'])) ?></td>
                                        <td class="py-4 px-4 text-right space-x-2">
                                            
                                            <button onclick="openEditModal(<?= $u['id'] ?>, '<?= htmlspecialchars($u['username']) ?>')" class="inline-block px-3 py-1 bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500 hover:text-white border border-yellow-500/30 hover:border-yellow-500 rounded text-xs font-bold transition-all">
                                                Edit
                                            </button>

                                            <?php if($u['username'] !== 'admin' && $u['username'] !== $_SESSION['username']): ?>
                                                <a href="?delete=<?= $u['id'] ?>" onclick="return confirm('Are you sure you want to delete this administrator?')" class="inline-block px-3 py-1 bg-red-500/10 text-red-400 hover:bg-red-500 hover:text-white border border-red-500/30 hover:border-red-500 rounded text-xs font-bold transition-all">
                                                    Delete
                                                </a>
                                            <?php else: ?>
                                                <span class="inline-block px-3 py-1 bg-slate-700/50 text-slate-500 rounded text-xs font-bold cursor-not-allowed border border-white/5">Delete</span>
                                            <?php endif; ?>

                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div class="space-y-8">
                    
                    <div class="glass p-6 rounded-xl shadow-lg border-t-4 border-t-blue-500">
                        <h2 class="text-lg font-bold text-white mb-4">Add Administrator</h2>
                        <form method="POST" class="space-y-4">
                            <input type="hidden" name="action" value="add_user">
                            <div>
                                <label class="block text-slate-400 text-xs font-bold uppercase mb-1">Username</label>
                                <input type="text" name="username" required class="w-full p-3 bg-black/20 border border-white/10 text-white rounded-lg focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 placeholder-slate-600 transition" placeholder="New username">
                            </div>
                            <div>
                                <label class="block text-slate-400 text-xs font-bold uppercase mb-1">Password</label>
                                <input type="password" name="password" required class="w-full p-3 bg-black/20 border border-white/10 text-white rounded-lg focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 placeholder-slate-600 transition" placeholder="••••••••">
                            </div>
                            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-500 text-white py-3 rounded-lg shadow-[0_0_15px_rgba(37,99,235,0.3)] transition font-bold tracking-wide">
                                Create Account
                            </button>
                        </form>
                    </div>

                    <div class="glass p-6 rounded-xl shadow-lg border border-red-500/30 relative overflow-hidden">
                        <div class="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-red-600 to-red-400"></div>
                        <h2 class="text-lg font-bold text-red-400 mb-2 flex items-center gap-2">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                            Danger Zone
                        </h2>
                        <p class="text-sm text-slate-400 mb-6">This action will permanently delete all uploaded Syslog files and wipe the database logs. Administrator accounts will remain active.</p>
                        
                        <form method="POST" onsubmit="return confirm('CRITICAL WARNING: Are you absolutely sure? This will delete all network analytics data and cannot be undone.')">
                            <input type="hidden" name="action" value="reset_data">
                            <button type="submit" class="w-full bg-red-500/20 text-red-400 hover:bg-red-500 hover:text-white border border-red-500/50 py-3 rounded-lg shadow-[0_0_15px_rgba(239,68,68,0.2)] hover:shadow-[0_0_20px_rgba(239,68,68,0.5)] transition font-bold tracking-wide">
                                Factory Reset Data
                            </button>
                        </form>
                    </div>

                </div>
            </div>
        </div>
    </main>

    <div id="editModal" class="fixed inset-0 z-[100] hidden items-center justify-center bg-black/60 backdrop-blur-sm p-4">
        <div class="glass w-full max-w-md rounded-2xl shadow-2xl border-t-4 border-t-yellow-500 relative transform transition-all">
            
            <button onclick="closeEditModal()" class="absolute top-4 right-4 text-slate-400 hover:text-white transition">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>

            <div class="p-8">
                <h2 class="text-2xl font-bold text-white mb-6">Edit Administrator</h2>
                
                <form method="POST" class="space-y-5">
                    <input type="hidden" name="action" value="edit_user">
                    <input type="hidden" name="user_id" id="edit_user_id">
                    <input type="hidden" name="old_username" id="edit_old_username">
                    
                    <div>
                        <label class="block text-slate-400 text-xs font-bold uppercase mb-1">Update Username</label>
                        <input type="text" name="username" id="edit_username" required class="w-full p-3 bg-black/40 border border-white/10 text-white rounded-lg focus:outline-none focus:border-yellow-500 focus:ring-1 focus:ring-yellow-500 transition">
                    </div>
                    
                    <div>
                        <label class="block text-slate-400 text-xs font-bold uppercase mb-1">Update Password</label>
                        <input type="password" name="password" class="w-full p-3 bg-black/40 border border-white/10 text-white rounded-lg focus:outline-none focus:border-yellow-500 focus:ring-1 focus:ring-yellow-500 placeholder-slate-500 transition" placeholder="Leave blank to keep current password">
                        <p class="text-[10px] text-slate-500 mt-1">* Only fill this out if you want to change their password.</p>
                    </div>
                    
                    <button type="submit" class="w-full bg-yellow-600 hover:bg-yellow-500 text-white py-3 rounded-lg shadow-[0_0_15px_rgba(202,138,4,0.3)] transition font-bold tracking-wide mt-4">
                        Save Changes
                    </button>
                </form>
            </div>
        </div>
    </div>

    <script>
        function openEditModal(id, currentUsername) {
            document.getElementById('edit_user_id').value = id;
            document.getElementById('edit_username').value = currentUsername;
            document.getElementById('edit_old_username').value = currentUsername;
            
            const modal = document.getElementById('editModal');
            modal.classList.remove('hidden');
            modal.classList.add('flex');
        }

        function closeEditModal() {
            const modal = document.getElementById('editModal');
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
    </script>
</body>
</html>
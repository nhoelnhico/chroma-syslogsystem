<?php
session_start();
if (!isset($_SESSION['admin_logged_in'])) { header("Location: index.php"); exit; }
require 'includes/db.php';

// Handle Add
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'add') {
    $hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->execute([$_POST['username'], $hash]);
}

// Handle Delete
if (isset($_GET['delete'])) {
    $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
    $stmt->execute([$_GET['delete']]);
    header("Location: settings.php");
    exit;
}

$users = $pdo->query("SELECT id, username, created_at FROM users")->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 flex h-screen overflow-hidden">
    <?php include 'includes/sidebar.php'; ?>

    <main class="flex-1 p-8 overflow-y-auto w-full">
        <button onclick="toggleSidebar()" class="md:hidden mb-4 p-2 bg-blue-600 text-white rounded">☰ Menu</button>
        <h1 class="text-3xl font-bold text-gray-800 mb-6">User Management</h1>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div class="bg-white p-6 rounded-xl shadow-sm border">
                <h2 class="text-xl font-bold mb-4">Add New Admin</h2>
                <form method="POST" class="space-y-4">
                    <input type="hidden" name="action" value="add">
                    <div>
                        <label class="block text-gray-700">Username</label>
                        <input type="text" name="username" required class="w-full mt-1 p-2 border rounded">
                    </div>
                    <div>
                        <label class="block text-gray-700">Password</label>
                        <input type="password" name="password" required class="w-full mt-1 p-2 border rounded">
                    </div>
                    <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">Create User</button>
                </form>
            </div>

            <div class="bg-white p-6 rounded-xl shadow-sm border">
                <h2 class="text-xl font-bold mb-4">Current Administrators</h2>
                <ul class="divide-y divide-gray-200">
                    <?php foreach($users as $u): ?>
                    <li class="py-3 flex justify-between items-center">
                        <span class="font-medium text-gray-800"><?= htmlspecialchars($u['username']) ?></span>
                        <?php if($u['username'] !== 'admin'): ?>
                            <a href="?delete=<?= $u['id'] ?>" class="text-red-500 hover:text-red-700 text-sm font-bold bg-red-50 px-3 py-1 rounded">Delete</a>
                        <?php else: ?>
                            <span class="text-gray-400 text-xs uppercase">Primary</span>
                        <?php endif; ?>
                    </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
    </main>
</body>
</html>
<?php
session_start();
require 'includes/db.php';

// If already logged in, redirect to dashboard
if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
    header("Location: dashboard.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $user = trim($_POST['username']);
    $pass = trim($_POST['password']);

    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$user]);
    $account = $stmt->fetch();

    if ($account && password_verify($pass, $account['password'])) {
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['username'] = $account['username'];
        header("Location: dashboard.php");
        exit;
    } else {
        $error = "Invalid username or password.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Chroma IT Security</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .glass {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
        }
    </style>
</head>
<body class="bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 flex items-center justify-center min-h-screen relative overflow-hidden font-sans">
    
    <div class="absolute top-[-10%] left-[-10%] w-96 h-96 bg-blue-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none animate-pulse" style="animation-duration: 8s;"></div>
    <div class="absolute bottom-[-10%] right-[-10%] w-96 h-96 bg-purple-600 rounded-full mix-blend-multiply filter blur-[128px] opacity-40 pointer-events-none animate-pulse" style="animation-duration: 10s;"></div>

    <div class="w-full max-w-md relative z-10 px-4">
        
        <div class="glass p-10 rounded-2xl border-t-4 border-t-blue-500 transform transition-all">
            
            <div class="text-center mb-10">
                <p class="text-xs text-blue-400 font-bold tracking-[0.2em] uppercase mb-2">Chromaesthetics Inc</p>
                <h2 class="text-3xl font-black text-white tracking-wide drop-shadow-md">IT DEPARTMENT</h2>
                <p class="text-slate-400 mt-2 text-sm font-medium">Network Security & Syslog Monitor</p>
            </div>

            <?php if(isset($error)): ?>
                <div class="bg-red-500/20 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-center text-sm font-medium backdrop-blur-md">
                    <svg class="w-5 h-5 inline-block mr-1 mb-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <?= $error ?>
                </div>
            <?php endif; ?>

            <form method="POST" class="space-y-6">
                <div class="group">
                    <label class="block text-slate-400 text-xs font-bold uppercase tracking-wider mb-2 group-focus-within:text-blue-400 transition-colors">Username</label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <svg class="w-5 h-5 text-slate-500 group-focus-within:text-blue-400 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
                        </div>
                        <input type="text" name="username" required autocomplete="username" class="w-full pl-10 pr-4 py-3 bg-black/20 border border-white/10 text-white rounded-xl focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all placeholder-slate-600" placeholder="Enter admin username">
                    </div>
                </div>

                <div class="group">
                    <label class="block text-slate-400 text-xs font-bold uppercase tracking-wider mb-2 group-focus-within:text-blue-400 transition-colors">Password</label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <svg class="w-5 h-5 text-slate-500 group-focus-within:text-blue-400 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                        </div>
                        <input type="password" name="password" required autocomplete="current-password" class="w-full pl-10 pr-4 py-3 bg-black/20 border border-white/10 text-white rounded-xl focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all placeholder-slate-600" placeholder="••••••••">
                    </div>
                </div>

                <button type="submit" class="w-full bg-blue-600 text-white font-bold tracking-wide py-3 px-4 rounded-xl shadow-[0_0_15px_rgba(37,99,235,0.4)] hover:bg-blue-500 hover:shadow-[0_0_25px_rgba(37,99,235,0.6)] hover:-translate-y-0.5 transition-all duration-300 mt-4">
                    Authenticate
                </button>
            </form>
            
        </div>
        
        <div class="text-center mt-8 text-slate-500 text-xs">
            &copy; <?= date('Y') ?> Chromaesthetics Inc. All rights reserved.
        </div>
    </div>
</body>
</html>
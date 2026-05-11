<?php
require 'includes/db.php';

$username = 'admin';
$password = 'admin123';

// Generate a fresh hash using your server's PHP environment
$hash = password_hash($password, PASSWORD_DEFAULT);

// Try to update the existing admin account
$stmt = $pdo->prepare("UPDATE users SET password = ? WHERE username = ?");
$stmt->execute([$hash, $username]);

// If the account doesn't exist at all, insert it
if ($stmt->rowCount() == 0) {
    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->execute([$username, $hash]);
    echo "<h3 style='color:green; font-family:sans-serif;'>Admin account created! Username: admin | Password: admin123</h3>";
} else {
    echo "<h3 style='color:green; font-family:sans-serif;'>Password successfully reset to: admin123</h3>";
}

echo "<p style='font-family:sans-serif;'><strong>SECURITY WARNING:</strong> Please delete this <code>reset_admin.php</code> file immediately, then go to the <a href='index.php'>Login Page</a>.</p>";
?>
<?php
$host = 'localhost';
$dbname = 'chroma_syslog';
$username = 'root';
$password = ''; // default password for XAMPP, change if necessary

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}
?>
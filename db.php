<?php
// Database connection details
$servername = "sql105.infinityfree.com";
$username = "if0_36918650";
$password = "Rishabhs9959";
$dbname = "if0_36918650_Test";

try {
    // Create a PDO instance
    $db = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    // Set PDO error mode to exception
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}
?>

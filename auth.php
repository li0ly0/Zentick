<?php
header('Content-Type: application/json');
require 'db.php';

$data = json_decode(file_get_contents('php://input'), true);
$email = trim($data['email'] ?? ''); 
$password = trim($data['password'] ?? '');

// 1. Fetch the user by email ONLY, and make sure to select the stored password hash
$stmt = $pdo->prepare("SELECT email, role, name, password FROM users WHERE email = ?");
$stmt->execute([$email]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

// 2. Use password_verify to check if the typed password matches the hash
if ($user && password_verify($password, $user['password'])) {
    
    // 3. Security Check: Never send the password hash back to the frontend
    unset($user['password']);

    echo json_encode([
        "success" => true, 
        "user" => $user
    ]);
} else {
    http_response_code(401);
    echo json_encode(["error" => "Invalid email or password"]);
}
?>

<?php
session_start();

require 'db.php';
require 'roles.php';
require 'authz.php';
require 'csrf.php';
require 'logger.php';

/* ADMIN ONLY */
requireRole([ROLE_ADMIN]);

csrf_verify($_POST['csrf_token'] ?? '');

$actorUserId = (int)$_SESSION['user_id'];
$actorRole   = $_SESSION['role'];

$userId  = (int)($_POST['user_id'] ?? 0);
$newRole = $_POST['new_role'] ?? '';

/* Validate input */
if ($userId <= 0 || !in_array($newRole, [ROLE_USER, ROLE_MODERATOR], true)) {
    http_response_code(400);
    exit('Invalid request');
}

/* Prevent self role change */
if ($userId === $actorUserId) {
    http_response_code(403);
    exit('Cannot modify yourself');
}

/* Fetch target user */
$stmt = $pdo->prepare(
    "SELECT username, role FROM users WHERE id = ?"
);
$stmt->execute([$userId]);
$target = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$target) {
    http_response_code(404);
    exit('User not found');
}

/* Enforce role hierarchy */
if (!canManage($actorRole, $target['role'])) {
    http_response_code(403);
    exit('Forbidden');
}

/* Update role */
$stmt = $pdo->prepare(
    "UPDATE users SET role = ? WHERE id = ?"
);
$stmt->execute([$newRole, $userId]);

/* Audit log */
log_event(
    'ROLE_UPDATED',
    "actor={$actorUserId}, target={$userId}, {$target['role']}→{$newRole}",
    'info',
    'admin'
);

/* Redirect back */
header('Location: admin.php');
exit;

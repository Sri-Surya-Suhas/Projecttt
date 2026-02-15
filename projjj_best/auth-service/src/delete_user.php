<?php
session_start();

require 'db.php';
require 'roles.php';
require 'authz.php';
require 'csrf.php';
require 'logger.php';

/* ADMIN OR MODERATOR */
requireRole([ROLE_ADMIN, ROLE_MODERATOR]);

csrf_verify($_POST['csrf_token'] ?? '');

$actorRole = $_SESSION['role'];
$actorId   = (int)$_SESSION['user_id'];
$targetId  = (int)($_POST['user_id'] ?? 0);

/* Basic validation */
if ($targetId <= 0) {
    http_response_code(400);
    exit('Invalid request');
}

/* Prevent self delete */
if ($targetId === $actorId) {
    http_response_code(403);
    exit('Cannot delete yourself');
}

/* Fetch target user */
$stmt = $pdo->prepare(
    "SELECT username, role FROM users WHERE id = ?"
);
$stmt->execute([$targetId]);
$target = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$target) {
    http_response_code(404);
    exit('User not found');
}

/* Enforce delete permissions */
if (!canDelete($actorRole, $target['role'])) {
    http_response_code(403);
    exit('Unauthorized delete');
}

/* Delete user */
$stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
$stmt->execute([$targetId]);

/* Audit log */
log_event(
    'USER_DELETED',
    "actor={$actorId}, target={$targetId}, username={$target['username']}",
    'warning',
    'admin'
);

/* ✅ ROLE-AWARE REDIRECT */
if ($actorRole === ROLE_ADMIN) {
    header('Location: /admin');
} else {
    header('Location: /moderator');
}
exit;

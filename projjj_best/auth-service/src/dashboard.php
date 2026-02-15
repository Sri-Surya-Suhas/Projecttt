<?php
session_start();

require 'roles.php';
require 'authz.php';

if (!isset($_SESSION['username'])) {
    header('Location: /login');
    exit;
}

$username = $_SESSION['username'];
$role     = $_SESSION['role'];

$roleStyles = [
    ROLE_ADMIN     => 'bg-red-500/20 text-red-300 border-red-400/30',
    ROLE_MODERATOR => 'bg-yellow-500/20 text-yellow-300 border-yellow-400/30',
    ROLE_USER      => 'bg-blue-500/20 text-blue-300 border-blue-400/30',
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-gray-950 text-white">

<!-- TOP BAR -->
<header class="flex justify-between items-center px-8 py-5 border-b border-white/10">
    <h1 class="text-xl font-bold tracking-wide">
        Secure Dashboard
    </h1>

    <div class="flex items-center gap-4">
        <span class="text-sm text-gray-300">
            <?= htmlspecialchars($username) ?>
        </span>

        <span class="text-xs px-3 py-1 rounded-full border <?= $roleStyles[$role] ?>">
            <?= htmlspecialchars(strtoupper($role)) ?>
        </span>

        <a href="/logout.php"
           class="text-sm text-red-300 hover:text-red-400 transition">
            Logout
        </a>
    </div>
</header>

<!-- MAIN CONTENT -->
<main class="max-w-5xl mx-auto px-6 py-10">

    <!-- WELCOME CARD -->
    <div class="bg-white/5 border border-white/10 rounded-2xl p-8 mb-8 shadow-lg">
        <h2 class="text-2xl font-bold mb-2">
            Welcome back, <?= htmlspecialchars($username) ?> 👋
        </h2>
        <p class="text-gray-300 text-sm">
            You are logged in securely. Your session is active.
        </p>
    </div>

    <!-- ACTIONS GRID -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">

        <!-- ACCOUNT INFO -->
        <div class="bg-white/5 border border-white/10 rounded-xl p-6 hover:bg-white/10 transition">
            <h3 class="text-lg font-semibold mb-2">
                Your Account
            </h3>
            <p class="text-sm text-gray-300 mb-4">
                Basic account information.
            </p>
            <ul class="text-sm space-y-1 text-gray-200">
                <li><strong>Username:</strong> <?= htmlspecialchars($username) ?></li>
                <li><strong>Role:</strong> <?= htmlspecialchars($role) ?></li>
            </ul>
        </div>

        <!-- ROLE-SPECIFIC MANAGEMENT -->
        <?php if ($role === ROLE_ADMIN): ?>
            <div class="bg-white/5 border border-white/10 rounded-xl p-6 hover:bg-white/10 transition">
                <h3 class="text-lg font-semibold mb-2">
                    Administration
                </h3>
                <p class="text-sm text-gray-300 mb-4">
                    Full system management access.
                </p>
                <a href="/admin"
                   class="inline-block text-red-300 hover:underline font-semibold">
                    Go to Admin Panel →
                </a>
            </div>

        <?php elseif ($role === ROLE_MODERATOR): ?>
            <div class="bg-white/5 border border-white/10 rounded-xl p-6 hover:bg-white/10 transition">
                <h3 class="text-lg font-semibold mb-2">
                    Moderation
                </h3>
                <p class="text-sm text-gray-300 mb-4">
                    Manage user activity.
                </p>
                <a href="/moderator"
                   class="inline-block text-yellow-300 hover:underline font-semibold">
                    Go to Moderator Panel →
                </a>
            </div>
        <?php endif; ?>

    </div>

    <!-- FOOTER NOTE -->
    <div class="mt-12 text-center text-xs text-gray-400">
        Unauthorized access is prohibited
    </div>

</main>

</body>
</html>

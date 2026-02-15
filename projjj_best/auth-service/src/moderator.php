<?php
session_start();

require 'db.php';
require 'roles.php';
require 'authz.php';
require 'csrf.php';

/* MODERATOR ONLY */
requireRole([ROLE_MODERATOR]);

$currentUserId = $_SESSION['user_id'];

$stmt = $pdo->prepare(
    "SELECT id, username
     FROM users
     WHERE role = ?
     ORDER BY username"
);
$stmt->execute([ROLE_USER]);

$users = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Moderator Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-gradient-to-br from-gray-900 via-slate-900 to-black min-h-screen text-white">

<div class="max-w-5xl mx-auto p-8">

    <!-- Header -->
    <div class="flex items-center justify-between mb-8">
        <h1 class="text-3xl font-extrabold">
            Moderator Panel
        </h1>

        <a href="/dashboard"
           class="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded-lg text-sm">
            ← Back to Dashboard
        </a>
    </div>

    <p class="text-gray-400 mb-6 text-sm">
        You can manage regular users only.
    </p>

    <!-- Users Table -->
    <div class="bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl overflow-hidden">

        <table class="w-full text-sm">
            <thead class="bg-white/10 text-gray-300 uppercase text-xs">
                <tr>
                    <th class="p-4 text-left">Username</th>
                    <th class="p-4 text-left">Actions</th>
                </tr>
            </thead>

            <tbody>
            <?php foreach ($users as $u): ?>
                <tr class="border-t border-white/10 hover:bg-white/5">

                    <td class="p-4 font-semibold">
                        <?= htmlspecialchars($u['username']) ?>
                    </td>

                    <td class="p-4">
                        <form method="POST" action="/delete_user.php"
                              onsubmit="return confirm('Delete this user?');">
                            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                            <input type="hidden" name="user_id" value="<?= $u['id'] ?>">

                            <button
                                class="bg-red-600 hover:bg-red-500 px-4 py-1 rounded text-sm font-semibold">
                                Delete User
                            </button>
                        </form>
                    </td>

                </tr>
            <?php endforeach; ?>

            <?php if (count($users) === 0): ?>
                <tr>
                    <td colspan="2" class="p-6 text-center text-gray-400">
                        No users available.
                    </td>
                </tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

</body>
</html>

<?php
session_start();

require 'db.php';
require 'roles.php';
require 'authz.php';
require 'csrf.php';

requireRole([ROLE_ADMIN, ROLE_MODERATOR]);

$currentRole   = $_SESSION['role'];
$currentUserId = $_SESSION['user_id'];

$stmt = $pdo->query(
    "SELECT id, username, role FROM users
     ORDER BY
        CASE role
            WHEN 'admin' THEN 1
            WHEN 'moderator' THEN 2
            ELSE 3
        END, username"
);
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Management</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-gradient-to-br from-gray-900 via-slate-900 to-black min-h-screen text-white">

<div class="max-w-6xl mx-auto p-8">

    <!-- Header -->
    <div class="flex items-center justify-between mb-8">
        <h1 class="text-3xl font-extrabold tracking-wide">
            User Management
        </h1>

        <a href="/dashboard"
           class="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded-lg text-sm transition">
            ← Back to Dashboard
        </a>
    </div>

    <!-- Table Card -->
    <div class="bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl overflow-hidden shadow-xl">

        <table class="w-full text-sm">
            <thead class="bg-white/10 text-gray-300 uppercase text-xs">
                <tr>
                    <th class="p-4 text-left">Username</th>
                    <th class="p-4 text-left">Role</th>
                    <th class="p-4 text-left">Actions</th>
                </tr>
            </thead>

            <tbody>
            <?php foreach ($users as $u): ?>
                <tr class="border-t border-white/10 hover:bg-white/5 transition">

                    <!-- Username -->
                    <td class="p-4 font-semibold">
                        <?= htmlspecialchars($u['username']) ?>
                        <?php if ($u['id'] === $currentUserId): ?>
                            <span class="ml-2 text-xs text-yellow-400">(you)</span>
                        <?php endif; ?>
                    </td>

                    <!-- Role Badge -->
                    <td class="p-4">
                        <?php
                        $roleBadge = match ($u['role']) {
                            ROLE_ADMIN => 'bg-purple-600/30 text-purple-300',
                            ROLE_MODERATOR => 'bg-blue-600/30 text-blue-300',
                            default => 'bg-gray-600/30 text-gray-300',
                        };
                        ?>
                        <span class="px-3 py-1 rounded-full text-xs font-bold <?= $roleBadge ?>">
                            <?= htmlspecialchars($u['role']) ?>
                        </span>
                    </td>

                    <!-- Actions -->
                    <td class="p-4">
                        <?php if ($u['id'] === $currentUserId): ?>

                            <span class="text-gray-400 italic">
                                Cannot modify yourself
                            </span>

                        <?php else: ?>
                            <div class="flex flex-wrap items-center gap-3">

                                <!-- ROLE CHANGE (ADMIN ONLY) -->
                                <?php if ($currentRole === ROLE_ADMIN && canManage($currentRole, $u['role'])): ?>
                                    <form method="post" action="/update_role.php" class="flex gap-2">
                                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">

                                        <select name="new_role"
                                                class="bg-gray-800 border border-white/20 rounded px-2 py-1 text-sm">
                                            <?php if ($u['role'] === ROLE_USER): ?>
                                                <option value="<?= ROLE_MODERATOR ?>">Moderator</option>
                                            <?php elseif ($u['role'] === ROLE_MODERATOR): ?>
                                                <option value="<?= ROLE_USER ?>">User</option>
                                            <?php endif; ?>
                                        </select>

                                        <button
                                            class="bg-emerald-600 hover:bg-emerald-500 px-3 py-1 rounded text-sm font-semibold transition">
                                            Update
                                        </button>
                                    </form>
                                <?php endif; ?>

                                <!-- DELETE -->
                                <?php if (canDelete($currentRole, $u['role'])): ?>
                                    <form method="post" action="/delete_user.php"
                                          onsubmit="return confirm('Delete this user permanently?');">
                                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">

                                        <button
                                            class="bg-red-600 hover:bg-red-500 px-3 py-1 rounded text-sm font-semibold transition">
                                            Delete
                                        </button>
                                    </form>
                                <?php endif; ?>

                                <?php if (
                                    !canManage($currentRole, $u['role']) &&
                                    !canDelete($currentRole, $u['role'])
                                ): ?>
                                    <span class="text-gray-400 italic">
                                        No permitted actions
                                    </span>
                                <?php endif; ?>

                            </div>
                        <?php endif; ?>
                    </td>

                </tr>
            <?php endforeach; ?>
            </tbody>

        </table>
    </div>
</div>

</body>
</html>

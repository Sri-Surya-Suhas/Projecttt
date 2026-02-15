<?php
require 'bootstrap.php';
require 'db.php';
require 'roles.php';
require 'authz.php';

requireRole([ROLE_ADMIN]);

$stmt = $pdo->query(
    "SELECT event_type, message, ip_address, user_agent, created_at
     FROM audit_logs
     ORDER BY created_at DESC
     LIMIT 200"
);
$logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html>
<head>
    <title>Audit Logs</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-gray-900 text-white min-h-screen">

<div class="max-w-7xl mx-auto p-8">
    <h1 class="text-3xl font-bold mb-6">Audit Logs</h1>

    <div class="overflow-x-auto bg-gray-800 rounded-xl">
        <table class="w-full text-sm">
            <thead class="bg-gray-700">
                <tr>
                    <th class="p-3">Time</th>
                    <th class="p-3">Event</th>
                    <th class="p-3">Message</th>
                    <th class="p-3">IP</th>
                    <th class="p-3">User Agent</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $l): ?>
                <tr class="border-t border-gray-700">
                    <td class="p-3"><?= htmlspecialchars($l['created_at']) ?></td>
                    <td class="p-3 font-semibold"><?= htmlspecialchars($l['event_type']) ?></td>
                    <td class="p-3"><?= htmlspecialchars($l['message']) ?></td>
                    <td class="p-3"><?= htmlspecialchars($l['ip_address']) ?></td>
                    <td class="p-3 truncate max-w-md"><?= htmlspecialchars($l['user_agent']) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <a href="dashboard.php"
       class="inline-block mt-6 bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded">
        ← Back
    </a>
</div>

</body>
</html>

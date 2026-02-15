<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require 'bootstrap.php';
require 'db.php';
require 'password.php';
require 'csrf.php';
require 'recaptcha.php';

$siteKey = getenv('RECAPTCHA_SITE_KEY');
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    csrf_verify($_POST['csrf_token'] ?? '');

    if (
        !$siteKey ||
        !verify_recaptcha($_POST['recaptcha_token'] ?? '', 'register')
    ) {
        $error = 'Suspicious activity detected.';
    } else {

        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($username === '' || $password === '') {
            $error = 'All fields are required.';
        } elseif (strlen($username) < 3 || strlen($username) > 20) {
            $error = 'Username must be 3–20 characters long.';
        } else {

            $stmt = $pdo->prepare("SELECT 1 FROM users WHERE username = ?");
            $stmt->execute([$username]);

            if ($stmt->fetchColumn()) {
                $error = 'Username already taken.';
            } else {

                $passwordHash = hash_password($password);

                try {
                    $stmt = $pdo->prepare(
                        "INSERT INTO users (username, password, role)
                         VALUES (?, ?, 'user')"
                    );
                    $stmt->execute([$username, $passwordHash]);

                    header('Location: /');
                    exit;

                } catch (Throwable $e) {
                    error_log('REGISTER_FAILED: ' . $e->getMessage());
                    $error = 'Registration failed. Try again later.';
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Create Account</title>
    <script src="https://cdn.tailwindcss.com"></script>

    <style>
        body {
            background: linear-gradient(135deg, #020617, #1e1b4b, #020617);
        }
        .glass {
            background: rgba(15, 23, 42, 0.65);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(99,102,241,0.35);
        }
        .eye-btn svg {
            width: 20px;
            height: 20px;
        }
    </style>
</head>

<body class="min-h-screen flex items-center justify-center text-white">

<div class="glass p-8 rounded-2xl w-full max-w-md">

    <h1 class="text-3xl font-extrabold text-center mb-1">
        Create Account
    </h1>
    <p class="text-center text-blue-200 mb-6 text-sm">
        Join us and get started 🚀
    </p>

    <?php if ($error): ?>
        <div class="flex items-center gap-2 bg-red-500/10
                    border border-red-400/40 text-red-200
                    p-3 rounded-lg mb-4 text-sm">
            <span>⚠️</span>
            <span><?= htmlspecialchars($error) ?></span>
        </div>
    <?php endif; ?>

    <form method="post" class="space-y-4">
        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
        <input type="hidden" name="recaptcha_token" id="recaptcha_token">

        <input type="text" name="username" placeholder="Username" required autofocus
               class="w-full p-3 rounded bg-white/10">

        <!-- Password -->
        <div class="relative">
            <input type="password" name="password" id="password"
                   placeholder="Password" required
                   class="w-full p-3 rounded bg-white/10 pr-12">
            <button type="button"
                    class="eye-btn absolute right-3 top-3 text-blue-200/70 hover:text-blue-200"
                    onclick="togglePassword('password', this)">
                <!-- Eye -->
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                     stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/>
                    <circle cx="12" cy="12" r="3"/>
                </svg>
            </button>
        </div>

        <!-- Confirm Password -->
        <div class="relative">
            <input type="password" id="confirm_password"
                   placeholder="Confirm Password" required
                   class="w-full p-3 rounded bg-white/10 pr-12">
            <button type="button"
                    class="eye-btn absolute right-3 top-3 text-blue-200/70 hover:text-blue-200"
                    onclick="togglePassword('confirm_password', this)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                     stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/>
                    <circle cx="12" cy="12" r="3"/>
                </svg>
            </button>
        </div>

        <button type="submit" id="registerBtn"
                class="w-full bg-gradient-to-r from-cyan-400 via-blue-500 to-indigo-600
                       p-3 rounded-xl font-bold">
            Create Account
        </button>
    </form>
</div>

<?php if ($siteKey): ?>
<script src="https://www.google.com/recaptcha/api.js?render=<?= htmlspecialchars($siteKey) ?>"></script>
<script>
grecaptcha.ready(() => {
    grecaptcha.execute('<?= htmlspecialchars($siteKey) ?>', { action: 'register' })
        .then(token => document.getElementById('recaptcha_token').value = token);
});
</script>
<?php endif; ?>

<script>
function togglePassword(id, btn) {
    const input = document.getElementById(id);
    const svg = btn.querySelector('svg');

    if (input.type === 'password') {
        input.type = 'text';
        svg.innerHTML = `
            <path d="M17.94 17.94A10.94 10.94 0 0 1 12 20
                     C6 20 2 12 2 12a21.81 21.81 0 0 1 5.06-6.94"/>
            <path d="M1 1l22 22"/>
        `;
    } else {
        input.type = 'password';
        svg.innerHTML = `
            <path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/>
            <circle cx="12" cy="12" r="3"/>
        `;
    }
}
</script>

</body>
</html>

<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once 'bootstrap.php';
require_once 'db.php';
require_once 'csrf.php';
require_once 'password.php';
require_once 'logger.php';
require_once 'risk.php';
require_once 'recaptcha.php';
require_once 'device.php';
require_once 'ip_reputation.php';

$siteKey  = getenv('RECAPTCHA_SITE_KEY');
$error    = '';
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '';

/* ================= CONTROL 16: IP BLOCK CHECK (FAIL-SAFE) ================= */
try {
    if (ip_is_blocked($clientIp)) {
        log_event('IP_BLOCKED', "ip=$clientIp");
        http_response_code(403);
        exit('Too many attempts. Try again later.');
    }
} catch (Throwable $e) {
    log_event('IP_CHECK_FAILED', $e->getMessage(), 'warning');
}

/* ================= LOGIN ================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    csrf_verify($_POST['csrf_token'] ?? '');

    if (
        !$siteKey ||
        !verify_recaptcha($_POST['recaptcha_token'] ?? '', 'login')
    ) {
        log_event('RECAPTCHA_FAILED', "ip=$clientIp");
        ip_record_event($clientIp, 15);
        $error = 'Suspicious activity detected.';
    } else {

        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {

            if (!empty($user['lock_until']) && strtotime($user['lock_until']) > time()) {
                log_event('ACCOUNT_LOCKED', "username=$username");
                ip_record_event($clientIp, 10);
                $error = 'Account locked. Try again later.';
            } elseif (verify_password($password, $user['password'])) {

                session_regenerate_id(true);

                $pdo->prepare(
                    "UPDATE users
                     SET failed_attempts = 0, lock_until = NULL
                     WHERE id = ?"
                )->execute([$user['id']]);

                /* -------- CONTROL 15: DEVICE -------- */
                $deviceContext = handle_device(
                    $user['id'],
                    $_POST['device_fingerprint'] ?? '',
                    $clientIp,
                    $_SERVER['HTTP_USER_AGENT'] ?? ''
                );

                if ($deviceContext['known'] === false) {
                    log_event('NEW_DEVICE_LOGIN', "username=$username ip=$clientIp");
                    ip_record_event($clientIp, 5);
                }

                /* -------- CONTROL 17: RISK -------- */
                [$riskScore, $riskReasons] = calculate_risk(
                    $user,
                    $clientIp,
                    $deviceContext
                );

                if ($riskScore >= 70) {
                    log_event(
                        'HIGH_RISK_LOGIN_BLOCKED',
                        implode(',', $riskReasons)
                    );
                    ip_record_event($clientIp, 25);
                    $error = 'Login blocked due to suspicious activity.';
                } else {

                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['role'] = $user['role'];
                    $_SESSION['created_at'] = time();
                    $_SESSION['last_activity'] = time();

                    ip_record_event($clientIp, -15);
                    log_event('LOGIN_SUCCESS', "username=$username");

                    header('Location: dashboard.php');
                    exit;
                }

            } else {
                $attempts = (int)$user['failed_attempts'] + 1;
                $lockUntil = $attempts >= 5
                    ? date('Y-m-d H:i:s', time() + 900)
                    : null;

                $pdo->prepare(
                    "UPDATE users
                     SET failed_attempts = ?, lock_until = ?
                     WHERE id = ?"
                )->execute([$attempts, $lockUntil, $user['id']]);

                ip_record_event($clientIp, 10);
                log_event('LOGIN_FAILED', "username=$username");
                $error = 'Invalid credentials';
            }
        } else {
            ip_record_event($clientIp, 10);
            log_event('LOGIN_FAILED', "username=$username");
            $error = 'Invalid credentials';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
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
        Welcome Back
    </h1>
    <p class="text-center text-blue-200 mb-6 text-sm">
        Login to continue
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
        <input type="hidden" name="device_fingerprint" id="device_fingerprint">

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
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                     stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/>
                    <circle cx="12" cy="12" r="3"/>
                </svg>
            </button>
        </div>

        <button type="submit"
                class="w-full bg-gradient-to-r from-cyan-400 via-blue-500 to-indigo-600
                       p-3 rounded-xl font-bold">
            Login
        </button>
    </form>

    <p class="text-center text-sm text-blue-200 mt-4">
        Don’t have an account?
        <a href="/register" class="text-cyan-300 hover:underline font-semibold">
            Register
        </a>
    </p>
</div>

<script src="/js/device_fingerprint.js"></script>

<?php if ($siteKey): ?>
<script src="https://www.google.com/recaptcha/api.js?render=<?= htmlspecialchars($siteKey) ?>"></script>
<script>
grecaptcha.ready(() => {
    grecaptcha.execute('<?= htmlspecialchars($siteKey) ?>', { action: 'login' })
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
            <path d="M1 1l22 22"/>
            <path d="M17.94 17.94A10.94 10.94 0 0 1 12 20
                     C6 20 2 12 2 12a21.81 21.81 0 0 1 5.06-6.94"/>
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

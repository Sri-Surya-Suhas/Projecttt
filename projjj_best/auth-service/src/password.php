<?php
/* Password hashing & verification helper */

function hash_password(string $password): string {
    $pepper = $_ENV['PASSWORD_PEPPER'];
    $peppered = hash_hmac('sha256', $password, $pepper);
    return password_hash($peppered, PASSWORD_ARGON2ID);
}

function verify_password(string $password, string $hash): bool {
    $pepper = $_ENV['PASSWORD_PEPPER'];
    $peppered = hash_hmac('sha256', $password, $pepper);
    return password_verify($peppered, $hash);
}

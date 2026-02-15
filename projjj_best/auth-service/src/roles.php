<?php

define('ROLE_ADMIN', 'admin');
define('ROLE_MODERATOR', 'moderator');
define('ROLE_USER', 'user');

function roleLevel(string $role): int
{
    return match ($role) {
        ROLE_ADMIN     => 3,
        ROLE_MODERATOR => 2,
        ROLE_USER      => 1,
        default        => 0,
    };
}

function canManage(string $actor, string $target): bool
{
    return roleLevel($actor) > roleLevel($target);
}

function canDelete(string $actor, string $target): bool
{
    if ($actor === ROLE_ADMIN) {
        return $target !== ROLE_ADMIN;
    }

    if ($actor === ROLE_MODERATOR) {
        return $target === ROLE_USER;
    }

    return false;
}

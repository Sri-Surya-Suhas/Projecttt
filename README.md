# Secure Authentication System
[![Ask DeepWiki](https://devin.ai/assets/askdeepwiki.png)](https://deepwiki.com/Sri-Surya-Suhas/Projecttt)

This repository contains a secure, containerized user authentication and management system built with PHP. It demonstrates a range of modern security practices within a microservice-oriented architecture, featuring separate services for user registration and authentication, all managed via Docker Compose.

The system is fronted by an Nginx reverse proxy that handles TLS termination, rate limiting, and request routing to the appropriate backend services.

## Key Security Features

This project implements a multi-layered security approach to protect against common web vulnerabilities.

### Authentication & Access Control
*   **Password Security**: Utilizes the `Argon2ID` hashing algorithm combined with a server-side secret pepper for robust password storage.
*   **Role-Based Access Control (RBAC)**: Implements `admin`, `moderator`, and `user` roles with a clear permission hierarchy. Admins can manage moderators and users, while moderators can only manage users.
*   **Account Lockout**: Automatically locks user accounts temporarily after five consecutive failed login attempts to thwart brute-force attacks.
*   **Secure Authorization**: Enforces strict access control checks on every privileged endpoint, ensuring users can only access resources permitted by their role.

### Threat Detection & Prevention
*   **CSRF Protection**: Employs per-session tokens on all state-changing forms to prevent Cross-Site Request Forgery attacks.
*   **IP Reputation & Blocking**: A dynamic reputation system scores IP addresses based on suspicious activities (e.g., login failures). IPs with high scores are temporarily blocked from accessing the system.
*   **Behavioral Risk Scoring**: Before finalizing a login, the system calculates a risk score based on contextual factors like recent failed attempts for the account, if the login is from a new device, and the IP's reputation score. High-risk logins are blocked.
*   **Device Fingerprinting**: A lightweight JavaScript-based fingerprinting mechanism helps detect and flag logins from new or unrecognized devices.
*   **Bot Detection**: Integrates Google reCAPTCHA v3 on both login and registration forms to distinguish between human users and automated bots.
*   **Rate Limiting**: Nginx is configured to limit the rate of requests to the login and registration endpoints, further mitigating brute-force and denial-of-service attempts.

### Session Management & Auditing
*   **Secure Session Handling**: Enforces secure session cookie attributes (`Secure`, `HttpOnly`, `SameSite=Strict`), session ID regeneration on login, and strict mode to prevent session fixation.
*   **Session Timeouts**: Configured with both idle and absolute session timeouts to automatically log out inactive users.
*   **Comprehensive Audit Trail**: Logs critical security events such as successful/failed logins, user deletions, role changes, and high-risk activities to a dedicated database table for monitoring and forensic analysis.

## System Architecture

The application is composed of four main services orchestrated by Docker Compose:

*   **`nginx`**: A web server acting as a reverse proxy. It handles incoming HTTPS traffic, terminates SSL, applies rate limits, and routes requests to the appropriate backend service.
*   **`auth-service`**: A PHP service responsible for user login, session management, user account management (by admins/moderators), and rendering all authenticated pages (dashboard, admin panel, etc.).
*   **`register-service`**: A dedicated PHP service that handles new user registration.
*   **`db`**: A PostgreSQL database instance that stores user data, audit logs, and IP reputation information.

## Getting Started

### Prerequisites

*   Docker
*   Docker Compose

### Installation

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/sri-surya-suhas/projecttt.git
    cd projecttt/projjj_best
    ```

2.  **Configure the Password Pepper:**
    Before starting, you must set a unique secret for password hashing. Open the `docker-compose.yml` file and replace `CHANGE_THIS_TO_A_REAL_SECRET` with a long, random string.
    ```yaml
    # in docker-compose.yml
    services:
      auth:
        # ...
        environment:
          PASSWORD_PEPPER: "your-super-secret-random-string-here"
      register:
        # ...
        environment:
          PASSWORD_PEPPER: "your-super-secret-random-string-here"
    ```

3.  **Build and run the containers:**
    ```sh
    docker-compose up --build -d
    ```

The application will now be running. You can access it at `https://localhost`. Your browser may show a warning for the self-signed SSL certificate; you can safely proceed.

### Creating an Admin User

By default, all new users are registered with the `user` role. To create an administrator, first register a user through the web interface, then follow these steps to manually update their role in the database.

1.  **Access the database container:**
    ```sh
    docker-compose exec db psql -U myuser -d mydb
    ```

2.  **Update the user's role:**
    Run the following SQL command, replacing `'your-username'` with the username you just registered.
    ```sql
    UPDATE users SET role = 'admin' WHERE username = 'your-username';
    ```

3.  **Exit the `psql` shell:**
    ```sql
    \q
    ```
The specified user will now have administrator privileges.

## Usage

*   **Registration**: Navigate to `https://localhost/register` to create a new account.
*   **Login**: Navigate to `https://localhost/login` to sign in.
*   **Dashboard**: After logging in, you will be redirected to your user dashboard at `https://localhost/dashboard`.
*   **User Management (Admin)**: Administrators can manage all users by visiting `https://localhost/admin`.
*   **User Management (Moderator)**: Moderators can manage standard users by visiting `https://localhost/moderator`.
*   **Audit Logs (Admin)**: Administrators can view the security audit trail at `https://localhost/audit_logs.php`.
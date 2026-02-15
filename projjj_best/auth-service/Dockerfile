FROM php:8.2-apache

# Install PostgreSQL PDO extension
RUN apt-get update \
    && apt-get install -y libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql

# Enable Apache rewrite
RUN a2enmod rewrite

# Set working directory
WORKDIR /var/www/html

# Copy application source
COPY src/ /var/www/html/

# Secure permissions
RUN chown -R www-data:www-data /var/www/html

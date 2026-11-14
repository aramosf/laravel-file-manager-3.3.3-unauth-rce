FROM composer:2 AS composer

FROM php:8.3-apache

RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip libzip-dev libpng-dev libjpeg62-turbo-dev libfreetype6-dev \
        libonig-dev libsqlite3-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" pdo_sqlite gd zip \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer /usr/bin/composer /usr/bin/composer

WORKDIR /app

RUN composer create-project laravel/laravel:^12.0 . --no-interaction --prefer-dist \
    && composer require alexusmai/laravel-file-manager:3.3.3 --no-interaction --prefer-dist

RUN php artisan vendor:publish --tag=fm-config --force \
    && cp .env.example .env \
    && sed -i 's/^SESSION_DRIVER=.*/SESSION_DRIVER=file/' .env \
    && sed -i 's/^CACHE_STORE=.*/CACHE_STORE=file/' .env \
    && sed -i 's/^APP_DEBUG=.*/APP_DEBUG=false/' .env \
    && php artisan key:generate --force \
    && php artisan storage:link \
    && mkdir -p storage/app/public \
    && chown -R www-data:www-data storage bootstrap/cache \
    && chmod -R ug+rwX storage bootstrap/cache

RUN printf '%s\n' \
    '<VirtualHost *:80>' \
    '    DocumentRoot /app/public' \
    '    <Directory /app/public>' \
    '        Options Indexes FollowSymLinks' \
    '        AllowOverride All' \
    '        Require all granted' \
    '    </Directory>' \
    '    ErrorLog /var/log/apache2/error.log' \
    '    CustomLog /var/log/apache2/access.log combined' \
    '</VirtualHost>' > /etc/apache2/sites-available/000-default.conf

EXPOSE 80

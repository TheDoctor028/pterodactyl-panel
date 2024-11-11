FROM nginx:stable-alpine

RUN addgroup -g 1000 laravel && adduser -G laravel -g laravel -s /bin/sh -D laravel

ADD ./nginx.conf /etc/nginx/
ADD ./default.conf /etc/nginx/conf.d/

RUN mkdir -p /var/www/html

RUN chown laravel:laravel /var/www/html

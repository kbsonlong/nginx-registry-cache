FROM debian:bookworm-slim AS build

ARG OPENRESTY_VERSION=1.27.1.2
ARG NGINX_VERSION=1.27.1
ARG PROXY_CONNECT_REF=v0.0.7

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates gcc git libc6-dev libpcre3-dev libssl-dev make \
       patch perl wget zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN wget -q https://openresty.org/download/openresty-${OPENRESTY_VERSION}.tar.gz \
    && tar -xzf openresty-${OPENRESTY_VERSION}.tar.gz \
    && git clone --depth 1 --branch ${PROXY_CONNECT_REF} \
       https://github.com/chobits/ngx_http_proxy_connect_module.git proxy-connect

WORKDIR /src/openresty-${OPENRESTY_VERSION}

RUN ./configure \
       --prefix=/usr/local/openresty \
       --with-http_ssl_module \
       --with-http_stub_status_module \
       --with-http_auth_request_module \
       --with-pcre-jit \
       --add-module=/src/proxy-connect \
    && patch -d build/nginx-${NGINX_VERSION} -p1 \
       < /src/proxy-connect/patch/proxy_connect_rewrite_102101.patch \
    && make -j2 \
    && make install

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpcre3 libssl3 openssl zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/openresty/certs /etc/openresty/logs /data/registry-aliyun-blobs /data/registry-temp \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
       -subj '/CN=registry-cache.local' \
       -addext 'subjectAltName=DNS:registry-cache.local,DNS:localhost,IP:127.0.0.1' \
       -keyout /etc/openresty/certs/tls-origin.key \
       -out /etc/openresty/certs/tls-origin.crt \
    && chown -R www-data:www-data /etc/openresty /data

COPY --from=build /usr/local/openresty /usr/local/openresty
COPY nginx.conf /etc/openresty/nginx.conf

EXPOSE 8080 443 9145

CMD ["/usr/local/openresty/nginx/sbin/nginx", "-p", "/etc/openresty", "-c", "/etc/openresty/nginx.conf", "-g", "daemon off;"]

# Собирается с контекстом = корень репозитория (см. install/docker/docker-compose.yml):
# docker build -f install/docker/radius/Dockerfile .
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
# third_party нужен уже на этапе go mod download - на layeh.com/radius есть
# local replace на ./third_party/layeh-radius (см. README-FORK.md в этой директории)
COPY third_party ./third_party
RUN go mod download
COPY . .
# VERSION/BUILD_DATE - те же -X main.VERSION/main.BUILD_DATE, что и в бинарной
# сборке (.github/workflows/build.yml), пробрасываются через --build-arg оттуда же.
# Без этого rad_sys_version в /metrics всегда показывал бы зашитый в исходниках
# дефолт независимо от того, какой тег реально собран
ARG VERSION=dev
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -ldflags "-X main.VERSION=${VERSION} -X main.BUILD_DATE=${BUILD_DATE}" -o /out/dhcp-radius-server ./server

FROM alpine:3.20
LABEL maintainer="Max Boyar <max.boyar.a@gmail.com>"
# ca-certificates - для HTTPS-запросов к script.database (clientdb) и api.addresses
RUN apk add --no-cache ca-certificates
COPY --from=build /out/dhcp-radius-server /opt/dhcp-radius-server
COPY --from=build /src/script/examples /opt/scripts
COPY server/radius.server.conf.yml /opt/radius.conf.yml
# Пути к lua-скриптам в конфиге по умолчанию относительны (для локального запуска из
# корня репозитория) - переопределяем на путь внутри образа, куда скрипты скопированы выше
ENV SCRIPT_AUTH_PATH=/opt/scripts/auth.lua
ENV SCRIPT_ACCT_PATH=/opt/scripts/acct.lua
ENV SCRIPT_POSTAUTH_PATH=/opt/scripts/post_auth.lua
ENTRYPOINT ["/opt/dhcp-radius-server", "-c", "/opt/radius.conf.yml"]

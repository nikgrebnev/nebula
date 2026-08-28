#!/bin/sh
# Воспроизводимая сборка нашего форка.
#
# Go на узле не установлен — собираем в образе. Версия берётся из метки git,
# поэтому собранное всегда можно сопоставить с историей: раньше бинарник на
# семнадцати боевых узлах был собран из рабочей копии, которую нельзя повторить.
#
# CGO_ENABLED=0 ОБЯЗАТЕЛЕН: в образе nebulaoss нет ld-linux, и динамический
# бинарник там не стартует вовсе — вечный перезапуск без внятной ошибки.
set -eu
cd "$(dirname "$0")"
VER=${1:-$(git describe --exact-match --tags 2>/dev/null | sed "s/^v//" || git describe --tags --dirty | sed "s/^v//")}
echo "версия сборки: $VER"
docker run --rm \
  -v "$PWD":/src -w /src \
  -v nebula-gocache:/root/.cache/go-build \
  -v nebula-gomod:/go/pkg/mod \
  -e CGO_ENABLED=0 \
  golang:1.26 \
  go build -trimpath -ldflags "-X main.Build=$VER" -o ./nebula ./cmd/nebula
file -b ./nebula | grep -q "statically linked" || { echo "БИНАРНИК НЕ СТАТИЧЕСКИЙ — в образе не запустится"; exit 1; }
./nebula -version
sha256sum ./nebula

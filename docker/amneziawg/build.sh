#!/bin/sh
set -eu
output=${1:?Specify the output directory}
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
curl -fsSL --retry 3 https://codeload.github.com/amnezia-vpn/amneziawg-go/tar.gz/08fe3d33bbb116be09a6183d02609311b8b0c9e8 -o "$work/go.tar.gz"
printf '%s  %s\n' e33d8a62928222592df23b75356d79e0ea6b590943cbe3a4cfcdf9c357bb416e "$work/go.tar.gz" | sha256sum -c -
mkdir "$work/go"
tar -xzf "$work/go.tar.gz" --strip-components=1 -C "$work/go"
patch -d "$work/go" -p1 < "$script_dir/bind-address.patch"
(cd "$work/go" && CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -ldflags='-s -w' -o "$output/amneziawg-go" .)
curl -fsSL --retry 3 https://codeload.github.com/amnezia-vpn/amneziawg-tools/tar.gz/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843 -o "$work/tools.tar.gz"
printf '%s  %s\n' 22438f231d39ea27e4bdc69707ec3103357f3cecc9ad3eecba18a61e5b39c9b9 "$work/tools.tar.gz" | sha256sum -c -
mkdir "$work/tools"
tar -xzf "$work/tools.tar.gz" --strip-components=1 -C "$work/tools"
make -C "$work/tools/src" -j2 WITH_WGQUICK=no WITH_SYSTEMDUNITS=no
install -m 755 "$work/tools/src/wg" "$output/awg"
printf '{"version":"3.1.20261116","sourceCommit":"08fe3d33bbb116be09a6183d02609311b8b0c9e8"}\n' > "$output/build-info.json"

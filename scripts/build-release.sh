#!/bin/sh
# build-release.sh builds doh for every supported platform into dist/, as
# archives with a SHA256SUMS file. Builds are static (CGO_ENABLED=0) and
# reproducible: the same commit builds the same bytes anywhere, so anyone
# can check a release against its source.
#
# Usage: scripts/build-release.sh [version]
#   version defaults to the git tag at HEAD, or "dev".
set -eu

version=${1:-$(git describe --tags --exact-match 2>/dev/null || echo dev)}
out=dist
rm -rf "$out"
mkdir -p "$out"

# Reproducible archives: fixed times, owners, and order.
epoch=$(git log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH="$epoch"

for target in \
	linux/amd64 linux/arm64 linux/arm/7 linux/riscv64 \
	darwin/amd64 darwin/arm64 \
	windows/amd64 windows/arm64 \
	freebsd/amd64; do
	goos=${target%%/*}
	rest=${target#*/}
	goarch=${rest%%/*}
	goarm=""
	[ "$goarch" = arm ] && goarm=${rest#*/}

	name="doh_${version#v}_${goos}_${goarch}${goarm:+v$goarm}"
	dir="$out/$name"
	mkdir -p "$dir"
	bin=doh
	[ "$goos" = windows ] && bin=doh.exe

	echo "building $name" >&2
	CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch GOARM=$goarm \
		go build -trimpath -buildvcs=true -ldflags="-s -w -buildid=" -o "$dir/$bin" .
	cp LICENSE README.md "$dir/"

	if [ "$goos" = windows ]; then
		(cd "$out" && find "$name" -exec touch -h -d "@$epoch" {} + && zip -qrX "$name.zip" "$name")
	else
		tar -C "$out" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -czf "$out/$name.tar.gz" "$name"
	fi
	rm -rf "$dir"
done

(cd "$out" && sha256sum -- *.tar.gz *.zip > SHA256SUMS)
echo "built $(ls "$out" | wc -l) files in $out" >&2

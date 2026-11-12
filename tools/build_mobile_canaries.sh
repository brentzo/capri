#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "$sdk_root" ]]; then
    echo "Set ANDROID_SDK_ROOT to an Android SDK installation." >&2
    exit 1
fi

build_tools="$sdk_root/build-tools/30.0.3"
android_jar="$sdk_root/platforms/android-30/android.jar"
for tool in aapt d8 zipalign apksigner; do
    if [[ ! -x "$build_tools/$tool" ]]; then
        echo "Missing $build_tools/$tool. Install platforms;android-30 and build-tools;30.0.3 with sdkmanager." >&2
        exit 1
    fi
done
if [[ ! -f "$android_jar" ]]; then
    echo "Missing $android_jar. Install platforms;android-30 with sdkmanager." >&2
    exit 1
fi
for tool in javac jar keytool; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing $tool. Install a JDK and add it to PATH." >&2
        exit 1
    fi
done
if [[ "$(javac -version 2>&1)" != javac\ 17.* ]]; then
    echo "The canary builder requires JDK 17." >&2
    exit 1
fi

source_dir="$repo_root/tests/fixtures/mobile/canary"
output_dir="$repo_root/build/mobile-canary"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$output_dir" "$work_dir/classes" "$work_dir/dex"

javac -source 8 -target 8 -bootclasspath "$android_jar" \
    -d "$work_dir/classes" "$source_dir/MainActivity.java"
jar cf "$work_dir/canary.jar" -C "$work_dir/classes" .
d8 --lib "$android_jar" --output "$work_dir/dex" "$work_dir/canary.jar"
keytool -genkeypair -noprompt -keystore "$work_dir/canary.keystore" \
    -storepass android -keypass android -alias capri-canary \
    -dname "CN=Capri Mobile Canary,O=Capri,C=US" -keyalg RSA -keysize 2048 -validity 10000

for flavor in vulnerable patched; do
    variant_dir="$work_dir/$flavor"
    mkdir -p "$variant_dir"
    manifest="$variant_dir/AndroidManifest.xml"
    if [[ "$flavor" == "vulnerable" ]]; then
        vulnerable=true
    else
        vulnerable=false
    fi
    sed "s/@VULNERABLE@/$vulnerable/g" "$source_dir/AndroidManifest.xml.in" > "$manifest"
    unsigned="$work_dir/$flavor-unsigned.apk"
    aligned="$work_dir/$flavor-aligned.apk"
    "$build_tools/aapt" package -f -M "$manifest" -I "$android_jar" -F "$unsigned"
    jar uf "$unsigned" -C "$work_dir/dex" classes.dex
    "$build_tools/zipalign" -f -p 4 "$unsigned" "$aligned"
    "$build_tools/apksigner" sign --ks "$work_dir/canary.keystore" \
        --ks-key-alias capri-canary --ks-pass pass:android --key-pass pass:android \
        --out "$output_dir/$flavor.apk" "$aligned"
    "$build_tools/apksigner" verify "$output_dir/$flavor.apk"
done

printf 'Built %s and %s\n' \
    "$output_dir/vulnerable.apk" "$output_dir/patched.apk"

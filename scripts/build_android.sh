#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT/android"

echo "=== Building LinkBridge Android APK (API 28+) ==="
if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ]; then
    echo "ERROR: ANDROID_HOME or ANDROID_SDK_ROOT is not set. Please install Android SDK (Platform 34, Build-Tools 34.0.0) and JDK 17." >&2
    exit 1
fi

if command -v gradle >/dev/null 2>&1; then
    gradle assembleDebug
elif [ -x "./gradlew" ]; then
    ./gradlew assembleDebug
else
    echo "ERROR: Neither gradle nor ./gradlew found." >&2
    exit 1
fi

echo "APK built successfully at: android/app/build/outputs/apk/debug/app-debug.apk"

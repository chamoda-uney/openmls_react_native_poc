#!/bin/bash

#dependancies
#cargo-ndk
#aarch64-linux-android
#armv7-linux-androideabi
#i686-linux-android
#x86_64-linux-android

#clear the old build
rm -rf android
rm -rf target

# Build the dylib
cargo build

# adding the android build tools
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

# Build the android library
cargo ndk -o android/jniLibs --manifest-path ./Cargo.toml -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 build --release

#generate kotlin bindings
cargo run --bin uniffi-bindgen generate --library ./target/debug/libopenmls_react_native_poc.dylib --language kotlin --out-dir android/

# Cleanup
rm -rf target
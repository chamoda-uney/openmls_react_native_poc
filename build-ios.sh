#!/bin/bash

#clear the old build
rm -rf bindings
rm -rf ios
rm -rf target

# Build the dylib
cargo build

# Generate bindings
cargo run --bin uniffi-bindgen generate --library ./target/debug/libopenmls_react_native_poc.dylib --language swift --out-dir ./bindings

# Add the iOS targets and build
for TARGET in \
        aarch64-apple-ios \
        aarch64-apple-ios-sim
do
    rustup target add $TARGET
    cargo build --release --target=$TARGET
done

# Rename *.modulemap to module.modulemap
mv ./bindings/openmls_react_native_pocFFI.modulemap ./bindings/module.modulemap

mkdir ios

# Move the Swift file to the project
mv ./bindings/openmls_react_native_poc.swift ./ios/OpenMLSReactNativePOC.swift

# Recreate XCFramework
rm -rf "ios/OpenMLSReactNativePOC.xcframework"
xcodebuild -create-xcframework \
        -library ./target/aarch64-apple-ios-sim/release/libopenmls_react_native_poc.a -headers ./bindings \
        -library ./target/aarch64-apple-ios/release/libopenmls_react_native_poc.a -headers ./bindings \
        -output "ios/OpenMLSReactNativePOC.xcframework"

# Cleanup
rm -rf bindings
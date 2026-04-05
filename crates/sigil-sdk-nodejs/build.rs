//! Build script for sigil-sdk-nodejs
//!
//! This script configures the napi-rs build system to generate
//! the Node.js native bindings.

extern crate napi_build;

fn main() {
    napi_build::setup();
}

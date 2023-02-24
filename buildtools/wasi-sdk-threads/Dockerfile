# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y curl gnupg make

RUN curl -sS https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor > /etc/apt/trusted.gpg.d/llvm.gpg && \
    echo "deb [signed-by=/etc/apt/trusted.gpg.d/llvm.gpg] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-16 main" >> /etc/apt/sources.list.d/llvm.list && \
    echo "deb-src [signed-by=/etc/apt/trusted.gpg.d/llvm.gpg] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-16 main" >> /etc/apt/sources.list.d/llvm.list

RUN apt-get update && apt-get install -y clang-16 lld-16

ADD https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-20%2Bthreads/wasi-sysroot-20.0.threads.tar.gz /
RUN tar -xf wasi-sysroot-20.0.threads.tar.gz

ADD https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-20%2Bthreads/libclang_rt.builtins-wasm32-wasi-20.0.threads.tar.gz /
# APT repository and package only include major version but the directory includes a patch version.
# We use a wildcard to make this compatible for any patch version.
RUN tar -xf libclang_rt.builtins-wasm32-wasi-20.0.threads.tar.gz -C /usr/lib/llvm-16/lib/clang/16/

ENV CC clang-16
ENV CXX clang++-16
ENV LD wasm-ld-16
ENV AR llvm-ar-16
ENV RANLIB llvm-ranlib-16
ENV CFLAGS -O3 --target=wasm32-wasi-threads --sysroot=/wasi-sysroot
ENV CXXFLAGS -O3 -fno-exceptions --target=wasm32-wasi-threads --sysroot=/wasi-sysroot
ENV LDFLAGS ${CXXFLAGS} --rtlib=compiler-rt -Wl,--demangle,--allow-undefined

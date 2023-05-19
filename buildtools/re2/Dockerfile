# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/webassembly/wasi-sdk:wasi-sdk-20

ENV CFLAGS --target=wasm32-wasi-threads --sysroot=/wasi-sysroot -pthread
ENV CXXFLAGS $CFLAGS
ENV LDFLAGS $CFLAGS -mexec-model=reactor

RUN apt-get update && apt-get install -y binaryen curl

# Use post-release commit for now as it includes support for no-threads
RUN mkdir -p /re2 && curl -L https://github.com/google/re2/archive/refs/tags/2023-03-01.tar.gz | tar -xz --strip-components 1 -C /re2
WORKDIR /re2
ENV CXXFLAGS -fno-exceptions -O3 ${CXXFLAGS}
RUN make obj/libre2.a

WORKDIR /cre2
ADD internal/cre2/cre2.cpp /cre2
ADD internal/cre2/thread.c /cre2
ADD internal/cre2/thread_init.s /cre2
ADD internal/cre2/cre2.h /cre2
# Just one source file so not worth running make
RUN $CXX -c cre2.cpp -o cre2.o -I. -I/re2 $CXXFLAGS && \
    $CC -c thread.c -o thread.o $CFLAGS && \
    $CC -c thread_init.s -o thread_init.o $CFLAGS && \
    $AR cru libcre2.a  cre2.o && \
    $AR cru libcre2.a  thread.o && \
    $AR cru libcre2.a  thread_init.o && \
    $RANLIB libcre2.a

# Separate step so exports can be updated without recompiling.
# Number of layers isn't really a concern for this image.
# global-base=1024 same as emcc and allows further wasm-opt optimizations
RUN $CXX -o libcre2-noopt.so -Wl,--global-base=1024 $LDFLAGS \
    /re2/obj/libre2.a \
    /cre2/libcre2.a \
    -Wl,--import-memory -Wl,--export-memory -Wl,--max-memory=1073741824 \
    -Wl,--export=malloc \
    -Wl,--export=free \
    -Wl,--export=cre2_new \
    -Wl,--export=cre2_delete \
    -Wl,--export=cre2_opt_new \
    -Wl,--export=cre2_opt_delete \
    -Wl,--export=cre2_opt_set_max_mem \
    -Wl,--export=cre2_opt_set_log_errors \
    -Wl,--export=cre2_opt_set_longest_match \
    -Wl,--export=cre2_opt_set_posix_syntax \
    -Wl,--export=cre2_opt_set_case_sensitive \
    -Wl,--export=cre2_opt_set_latin1_encoding \
    -Wl,--export=cre2_error_code \
    -Wl,--export=cre2_error_arg \
    -Wl,--export=cre2_num_capturing_groups \
    -Wl,--export=cre2_match \
    -Wl,--export=cre2_named_groups_iter_new \
    -Wl,--export=cre2_named_groups_iter_next \
    -Wl,--export=cre2_named_groups_iter_delete \
    -Wl,--export=cre2_global_replace_re \
    -Wl,--export=wasi_new_thread \
    -Wl,--export=wasi_thread_init

#RUN wasm-opt -o libcre2.so --low-memory-unused --flatten --rereloop --converge -O3 libcre2-noopt.so
RUN cp libcre2-noopt.so libcre2.so

CMD ["bash", "-c", "cp /re2/obj/libre2.a /cre2/libcre2.so /cre2/libcre2.a /out/"]

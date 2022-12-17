FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libz-dev clang

COPY . /repo
WORKDIR /repo/src
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_bam_swap_endian_8.cpp -fsanitize=fuzzer,address -I /repo/src/ -lz -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /repo/src/split_fa /
COPY --from=builder /fuzz /fuzz_bam_swap_endian_8

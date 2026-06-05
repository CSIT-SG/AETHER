FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
        gcc \
        mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY src/assets/ .

RUN mkdir -p /out/linux /out/windows

RUN for cfile in *.c; do \
        name="$(basename "$cfile" .c)"; \
        gcc -O0 "$cfile" -o "/out/linux/$name" && \
        x86_64-w64-mingw32-gcc -O0 "$cfile" -o "/out/windows/$name.exe"; \
    done

FROM ubuntu:22.04
COPY --from=builder /out /out
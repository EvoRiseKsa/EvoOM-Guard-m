FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:bfd6d19416d9f7a791857d3f5746bc9050138a1843aa7e98b617469d8d631bab

COPY . /src/evoom-guard
WORKDIR /src/evoom-guard
COPY .clusterfuzzlite/build.sh /src/build.sh

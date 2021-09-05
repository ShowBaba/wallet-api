FROM ubuntu:18.04

# Install some basics
RUN apt-get update \
    && apt-get install -y \
        wget \
        curl \
        git \
        vim \
        unzip \
        xz-utils \
        software-properties-common \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Add latest cmake/boost
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc | apt-key add - \
    && apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main' \
    && apt-add-repository -y ppa:mhier/libboost-latest

# Install required packages for dev
RUN apt-get update \
    && apt-get install -y \
        build-essential \
        libtool autoconf pkg-config \
        ninja-build \
        ruby-full \
        clang-10 \
        llvm-10 \
        libc++-dev libc++abi-dev \
        cmake \        
        libboost1.74-dev \
        ccache \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV CC=/usr/bin/clang-10
ENV CXX=/usr/bin/clang++-10

# ↑ Setup build environment
# ↓ Build and compile wallet core

RUN mkdir wallet-core
RUN git clone https://github.com/trustwallet/wallet-core.git wallet-core
WORKDIR /wallet-core

## RUN git clone https://github.com/ShowBaba/wallet-api.git
COPY . /wallet-core/wallet-api
RUN mv /wallet-core/wallet-api/go-config.sh /wallet-core
RUN ls
RUN chmod +x ./go-config.sh
RUN ./go-config.sh
RUN ls

ENV PATH=$PATH:/wallet-core/go/bin

# RUN echo $PATH

# Install dependencies
RUN tools/install-dependencies

# Build: generate, cmake, and make
RUN tools/generate-files \
    && cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=Debug \
    && make -Cbuild -j12

RUN cd wallet-api && go mod download && go build main.go

EXPOSE 8080

# ENV PORT=8080

# RUN ls

# RUN go env

ENTRYPOINT ["/wallet-core/wallet-api/main"]

#CMD ["/bin/bash"]
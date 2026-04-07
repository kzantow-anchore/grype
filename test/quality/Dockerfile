FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    make \
    bash \
    curl \
    golang \
    oras \
    ncurses-bin \
    && rm -rf /var/lib/apt/lists/*

CMD ["bash"]

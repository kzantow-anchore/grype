ARG PYTHON_VERSION="3.13"

FROM python:${PYTHON_VERSION}-slim

ARG GO_VERSION="1.25.9"

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    zsh \
    git \
    make \
    curl \
    oras \
    ncurses-bin \
    && rm -rf /var/lib/apt/lists/*

RUN adduser dev

COPY --from=1password/op:2 /usr/local/bin/op /usr/local/bin/op

USER dev

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

RUN curl -fsSL https://claude.ai/install.sh | bash

RUN curl -LsSf https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -xzC /home/dev

RUN <<EOF
mkdir -p /home/dev/tools
for name in gh gosimports golangci-lint oras; do
    echo "/home/dev/.tool/binny run $name \$@" > /home/dev/tools/$name
    chmod +x /home/dev/tools/$name
done
EOF

ENV PATH="$PATH:/home/dev/tools:/home/dev/go/bin"
ENV BINNY_ROOT="/home/dev/.tool"

RUN echo "\n alias dir='ls -alFh --color'" >> /home/dev/.bashrc
RUN echo "\n source .bashrc \n PROMPT='%n@%m %~ %# '" >> /home/dev/.zshrc

CMD ["bash"]

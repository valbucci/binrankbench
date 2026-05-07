FROM python:3.14-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
        build-essential \
        python3-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY dist/ dist/
COPY requirements.txt pyproject.toml ./
COPY binrankbench/ binrankbench/

RUN pip install --no-cache-dir \
    dist/functionsimsearch-*.whl \
    dist/marcellisimsearch-*.whl \
    -r requirements.txt \
    .

EXPOSE 8888

CMD ["jupyter", "lab", "--ip=0.0.0.0", "--no-browser", "--allow-root", "--notebook-dir=/workspace/evaluation/notebooks"]

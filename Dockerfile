FROM rust:1.77.2-slim

# install python
RUN apt-get update; \
    apt-get install -y --no-install-recommends \
        git \
        python-is-python3 \
        python3.11 \
        python3-pip \
        texlive \
        texlive-latex-extra \
        cm-super \
        dvipng \
        ; \
    rm -rf /var/lib/apt/lists/*;

# create working directory to put the files
WORKDIR /usr/src/vldp

# install python requirements
COPY ./requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel; \
    pip install --no-cache-dir -r requirements.txt --break-system-packages; \
    apt-get remove -y --auto-remove \
        git \
        ;

# copy all relevant code and files (excludes are in .dockerignore)
COPY . .

# in case the original files did not have run permissions
RUN chmod +x -R .

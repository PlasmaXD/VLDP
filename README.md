# VLDP in local and shuffle model

This repository contains the code for the paper *Efficient Verifiable Differential
Privacy with Input Authenticity in the Local and Shuffle Model* by *Tariq Bontekoe*, *Hassan Jameel Asghar*, and *Fatih
Turkmen*. Links: [arXiv](https://arxiv.org/abs/2406.18940); [IACR ePrint](https://eprint.iacr.org/2024/1042)

We make our code available open-source under the MIT license. To enable anyone to re-use our code and/or reproduce the
results from our paper.

## Contents

1. [Description](#description)
2. [Repository lay-out](#repository-lay-out)
3. [Running in docker](#running-in-docker)
4. [Running locally](#running-locally)

## Description

This repository implements the client and server functionality for the three different VLDP schemes presented in the
paper (*Base*, *Expand*, and *Shuffle*). Moreover, we implement benchmarks on random data and example scripts on real
datasets to evaluate our schemes. The benchmarks give an insight into the client/server performance and the examples
show the behaviour on real data. Next to this, we also include Jupyter notebooks which were used for dataset parsing and
determining the DP parameters used in the examples and the paper. Finally, we include script for running all benchmarks
and examples at once, parsing the results and transforming these into the plots that are presented in the paper.

The simplest way to run the code is by using [Docker](#running-in-docker). To reproduce the experiments from the paper (
on your own hardware, so the runtimes may be different, but the trend should be similar) you can run the `run_all`
container (or `run_all_fast` for faster, but less precise results). To view and reproduce the datasets we used for the
experiments on our paper, one can run the `notebook` container.

*Note:
In our benchmark and example scripts, the trusted environment, communication, and (if present) shuffler are emulated, as
these were not needed to measure the client/server performance and communication costs. The code has been written in
such a way that messages are easily serialized, and one can use any existing or new library to implement these parts.*

## Repository Lay-Out

This repository contains the following relevant directories and files:

- `benches`: Rust code implementing the benchmarks on random data (either for histogram or real-valued data)
- `examples`: Rust code implementing the use cases on real data (geodata/histogram or smart meter/real-valued)
- `resources\shuffle-model-parameters`: datasets for both use cases and Jupyter notebook for creating these datasets
  from the original raw data + determining the DP parameters
- `scripts`: Convenient scripts for automated running of benchmarks, parsing the raw results, and making plots. The
  `linux` subfolder contains the scripts for running on Linux-based systems, and `windows` for Windows-based systems.
  The Python scripts parse the raw results or make plots.
    - `run_all`: Runs all benchmarks+examples, parses data, and makes plots. This gives all the results used in the
      paper. (3 warmup runs, 100 measurement runs)
    - `run_all_fast`: Same as above, but only 1 warmup run and 10 measurement runs
    - `run_benches`: Runs performance benchmarks on the client/server to obtain accurate runtime estimates. (3 warmup
      runs, 100 measurement runs)
    - `run_benches_fast`: Same as above, but only 1 warmup run and 10 measurement runs
    - `run_additional_benches`: Runs more benchmarks to obtain accurate runtime estimates for different Merkle tree
      sizes and amounts of randomness. (3 warmup runs, 100 measurement runs)
    - `run_additional_benches_fast`: Same as above, but only 1 warmup run and 10 measurement runs
    - `run_geo_data_examples`: Runs benchmarks on the Geodata use case.
    - `run_smart_meter_examples`: Runs benchmarks on the Smart Meter use case.
- `src`: Actual implementation of the client and server code for our VLDP schemes.
- `PAPER_RESULTS.ZIP`: Raw results as generated for the paper, accompanied by its parsed version and plots made from it.

## Running in Docker

The simplest way to run the code, scripts and notebook is by means of docker. We have defined a single container which
can be used to run all code. For ease of use we set up the most convenient use cases (including an interactive shell to
the container) using docker compose.

First make sure you install Docker (in case you do not yet have it):

- Either install [Docker Desktop](https://docs.docker.com/desktop/), which provides at least Docker Engine and Docker
  Compose (make sure to launch it before running).
- Or (on Linux and a bit more work) install Docker Engine and Docker Compose independently:
    - [Docker Engine](https://docs.docker.com/engine/install/)
    - [Docker Compose](https://docs.docker.com/compose/install/)

First, we have to build the docker containers, this is done using `docker-compose build`.

Then one can run any of the following containers using `docker-compose up -d <container_name> --build`, where
`<container_name>` is replaced by any of the following:

- `notebook`: This runs the jupyter notebook and enables port forwarding of port 8888 to port 8888 on you local machine.
  The notebook can be accessed by using a browser to go to `localhost:8888`. The notebook can be found in
  `resources/shuffle-model-parameters`. Its progress and outputs are mounted to the local folder with the same path in
  your repository, so any changes there are also made locally (PLEASE BE AWARE OF THIS!).
- `run_all`: This runs all benchmarks (i.e., the `run_all` script). Results are made available locally through a mount
  at `docker_mounts/run_all`.
- `run_all_fast`: This runs all benchmarks in the fast setting (i.e., the `run_all_fast` script). Results are made
  available locally through a mount at `docker_mounts/run_all_fast`.

To run any container in interactive mode (i.e., it will not run any command at launch) run
`docker-compose run <container_name>`. This can be convenient when you want to run your own commands in one of the
provided containers.

Note: In case you wish to change the port forwarding on your local machine, you can open the `compose.yaml` file and
change any occurrence of `8888:8888` to `<your port>:8888`.

## Running Locally

Depending on what exactly you wish to run, you can follow either (or both) of the following:

- [Running the Rust code](#rust-code)
- [Running the Jupyter Notebook and/or parse/plot scripts](#jupyter-notebook-and-scripts)

### Rust Code

First do the following:

- [Install Rust](https://www.rust-lang.org/tools/install)
- Clone this repository/Download this code

- Open a terminal inside the git repo.
- All commands below can be appended with `--features print-trace` to show timing information.
- To run an example: `cargo run --example <name>` or `cargo run --release --example <name>` (release model, this is the
  most efficient, and what should be used in practice).
    - To see the available examples: `cargo run --example`
- To run the benchmarks see [below](#jupyter-notebook-and-scripts)

### Jupyter Notebook and Scripts

First do the following:

- [Install Python](https://www.python.org/downloads/)
- Clone this repository/Download this code

- Open a terminal inside the git repo.
- (Optional:) Make and activate a [virtual environment](https://docs.python.org/3/library/venv.html)
- Install the requirements: `python -m pip install -r requirements.txt`

#### Jupyter Notebook

- Type the following in your terminal: `jupyter notebook`.
- A browser should open automatically, if not please do so yourself and go to http://localhost:8888
- Go to the folder `resources/shuffle-model-parameters` and open `LDP-Shuffle-Parameters.ipynb` and run it.

#### Scripts: Benchmarks, Parsing, and Plots

To run everything, parse the raw results, and make plots: (on Linux) `./scripts/linux/run_all.cmd` (on Windows)
`.\scripts\windows\run_all.cmd`. This will create a `results` folder containing three folders:

- `raw`: The raw logs from the benchmarks.
- `parsed`: CSV files containing the relevant information from the raw logs.
- `plots`: Plots made from the timing data of the benchmarks.

Alternatively, one can also run a subset of the benchmarks/examples/parsing by running separate scripts in the `scripts`
folder.

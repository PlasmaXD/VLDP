# Artifact Appendix

Paper title: **Efficient Verifiable Differential Privacy with Input Authenticity in the Local and Shuffle Model**

Artifacts HotCRP Id: **#1**

Requested Badge: **Reproduced**

## Description

This artifact contains all code used for running the experiments in our paper.
It contains a Jupyter notebook for creating the datasets for both use cases.
Next to this, it contains the code for running each of our three protocols and parsing the results into .csv files
(which form the basis of Table 1 and 2) or into the plots shown in Figure 7.

### Security/Privacy Issues and Ethical Concerns (All badges)

None

## Basic Requirements (Only for Functional and Reproduced badges)

See the subsections on software requirements and estimate time and storage consumption below.

### Hardware Requirements

None

### Software Requirements

The simplest way to run the artifacts in our code, is by means of Docker Compose. This should be OS independent.
The easiest way to get Docker and Docker Compose, is
by [installing Docker Desktop](https://www.docker.com/products/docker-desktop/).

In case you really wish to run things locally, we advise you to follow the section
on [Running locally](README.md#running-locally) in the README.

### Estimated Time and Storage Consumption

Estimated storage consumption: (experiments without running Jupyter Notebook) ~500 MB, Jupyter Notebook additionally
adds ~3-4 GB (to download open-source datasets).

Estimated computation time: Jupyter notebook should run in ~15 minutes max. (most time spent downloading, so speed
depends on network capacity.) The experiments themselves take between 1-10 hours, depending on CPU clock speed and
number of cores. The fast version of the experiments takes ~2.5 hours on a laptop with a recent i7, the full experiment
around takes approximately double time.

Provide an estimated value for the time the evaluation will take and the space on the disk it will consume.
This helps reviewers to schedule the evaluation in their time plan and to see if everything is running as intended.
More specifically, a reviewer, who knows that the evaluation might take 10 hours, does not expect an error if, after 1
hour, the computer is still calculating things. TODO

## Environment

Below, we describe how to access our code and set up the environment.

### Accessibility

The artifact can be accessed on GitHub, the version of the code for the paper has been
tagged [v1.1.0](https://github.com/xQiratNL/VLDP/tree/v1.1.0).

### Set up the environment

You can download the repository and checkout the appropriate tag using the following commands (on a Unix system, or
using Git Bash on Windows).

```bash
git clone git@github.com:xQiratNL/VLDP.git
cd VLDP
git checkout v1.1.0
```

Make sure you also have already installed Docker Desktop as described [above](#software-requirements). Alternatively one
can install Docker Engine and Docker Compose separately, as described at the top of the README
section [Running in docker](README.md/#running-in-docker),

### Testing the Environment

There are no specific tests to run to test the environment.

## Artifact Evaluation

Below, we describe all steps to take to reproduce the results from our paper.

### Main Results and Claims

Below, the two experiments that form the basis for the experiments in Section 7 of our paper.

#### Main Result 1: Dataset generation

The first experiment is used for generating the datasets. While this is not a direct result, it does form the basis of
the use cases in our runtime evaluation. The details of these datasets are described in the [paper](paper.pdf) in
Section 7.2 and Appendix D.1.

#### Main Result 2: Runtime evaluation

This is the main experiment for evaluating the runtime of the different protocols for different parameters. This
experiment also outputs .csv files containing the data as used in Table 1 and 2 in the paper, as well as the plots that
together form Figure 7 in the paper. The implementation details of this code are described in Section 7.1 of the paper,
the results of this experiment in Sections 7.3 and 7.4.

### Experiments

Below we describe the experiments in detail. In case of any unclarities in this description, we also advise to take a
look at the [README](README.md) and specifically the section on [Running with Docker](README.md#running-in-docker).

#### Experiment 1: Dataset Generation

Open up a terminal and navigate to inside the repositories main folder (generally called `VLDP`). Make sure you have
started up Docker Desktop (or alternatively the Docker Engine and Docker Compose are running). Now, run the following
command to run the docker container.

```bash
docker-compose up -d notebook --build
```

This will start op the container running a Jupyter notebook and forward all communication to port 8888 on you local
machine. In case this port is undesirable, it can be changed in the `compose.yaml` file, by changing any occurrence of
`8888:8888` by `<your port>:8888`.

Next, open a browser and navigate to `localhost:8888`. The notebook `LDP-Shuffle-Parameters.ipynb` can be found in
`resources/shuffle-model-parameters`. And all cells can be run one-by-one as usual, or by selecting `Run All` from the
`Run` menu. The notebooks progress and outputs are mounted to the local folder with the same path in your local
repository, so any changes there are also made locally (BE AWARE OF THIS!).

The expected result is that the datasets (as already contained in the folder), are re-generated. The `energy_data.csv`
file should be identical to the existing one. The `geolife-postcodes-condensed.csv` may slightly change (see
also [Limitations](#limitations)), but should have a similar nature.

The notebook also shows some basic information on the original datasets, and shows a trial run of regular LDP
randomizers without verifiability.

The expected runtime is around 15 minutes, depending on network capacity. And disk consumption is around 3-4GB (due to
downloading the original datasets).

#### Experiment 2: Runtime evaluation

All benchmarks and evaluations are run in this experiment, including data parsing and plot generation. We offer a
regular (like in the paper), and a fast (with 10 instead of 100 runs per experiment) version.
The fast version should take around half the runtime of the regular, as most time is spent in compilation of the
respective experiments. The regular version can take between 4-10 hours with a recent i7 laptop CPU. The generated data
consumes around 500 MB.

Whilst the exact numbers of reproducing this experiment will differ, the trends as observed in this paper for varying
the parameters should be similar, as well as the orders of magnitude. Moreover, message and key sizes should be
identical.

To run the regular experiment:

```bash
docker-compose up -d run_all --build
```

To run the fast experiment:

```bash
docker-compose up -d run_all_fast --build
```

Results of the experiment are made available on your local machine through a mount at `docker_mounts/run_all` resp.
`docker_mounts/run_all_fast`.

The results folder will contain a folder with `raw` results, `parsed` results, and `plots`. The parsed results form the
basis for Table 1 and 2 in the paper, as well as the plots. Specifically, the file `parsed\benches\<date--time>_medians`
is used for Table 1. The values in Table 2 are computed manually from these values (and thus not directly present in
these experiments). The files with `median` in the name in `additional_benches` are used to generate the plots in
`plots`, and the `geo_data` and `smart_meter` show example results of running a protocol on this use case (not directly
visible in the paper).

The folder `plots/merkle_tree` contains the plots for varying `d_MT` (some of which are shown in Figure 7 in the paper,
others are not shown in the paper).
The folder `plots/randomness` contains the plots for varying `|rho|` (some of which are shown in Figure 7 in the paper,
others are not shown in the paper).

Note, you can inspect the containers while they are running to see the progress, moreover, the mounted folders will grow
with results whilst running the experiments. This should give a good indication of any issues.

## Limitations

The GeoData dataset in Experiment 1 might turn out slightly different from the one we already include. This is due to
the
instability of the Reverse Lookup API, however the changes will be small, and do not hinder the experimental results in
any way.

The plots and .csv files generated as a result for Experiment 2 will be different from those in the paper. Due to the
runtime evaluation being highly dependent on the used hardware, the absolute value of these numbers will change. The
observed trends, however, should be similar in nature, to those in the paper. This should, in our eyes, be sufficient to
reproduce the results.

## Notes on Reusability

Next to allowing other researchers to reproduce our results and gain insight into the implementation, we have also aimed
to write the implementation of our schemes in a modular fashion. This makes it easy to switch out the primitives used (
by means of defining a different `Config` struct.) Moreover, the sizes of the data used can be easily controlled (as
visible in the constants used in the [benchmarks](benches)).

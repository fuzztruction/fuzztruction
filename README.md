# Fuzztruction
<p><a href="https://mu00d8.me/paper/bars2023fuzztruction.pdf"><img alt="Fuzztruction Paper Thumbnail" align="right" width="320" src="https://user-images.githubusercontent.com/1810786/204243236-9d0ddd3b-82c2-4b82-9859-d93ded3ea7e7.png"></a></p>



Fuzztruction is an academic prototype of a fuzzer that does not directly mutate inputs (as most fuzzers do) but instead uses a so-called generator application to produce an input for our fuzzing target. As programs generating data usually produce the correct representation, our fuzzer *mutates* the generator program (by injecting faults), such that the data produced is *almost* valid. Optimally, the produced data passes the parsing stages in our fuzzing target, called *consumer*, but triggers unexpected behavior in deeper program logic. This allows to even fuzz targets that utilize cryptography primitives such as encryption or message integrity codes. The main advantage of our approach is that it generates complex data without requiring heavyweight program analysis techniques, grammar approximations, or human intervention.

For more details, check out our [paper](https://mschloegel.me/paper/bars2023fuzztruction.pdf). To cite our work, you can use the following BibTeX entry:
```bibtex
@inproceedings{bars2023fuzztruction,
  title={Fuzztruction: Using Fault Injection-based Fuzzing to Leverage Implicit Domain Knowledge},
  booktitle = {32st USENIX Security Symposium (USENIX Security 23)},
  publisher = {USENIX Association},
  year={2023},
  author={Bars, Nils and Schloegel, Moritz and Scharnowski, Tobias and Schiller, Nico and Holz, Thorsten},
}
```

For instructions on how to reproduce the experiments from the paper, please read the [`fuzztruction-experiments`](https://github.com/fuzztruction/fuzztruction-experiments) submodule documentation *after* reading this document.

> <b><span style="color:red">Compatibility:</span></b> While we try to make sure that our prototype is as platform independent as possible, we are not able to test it on all platforms. Thus, if you run into issues, please use Ubuntu 22.04.1, which was used during development as the host system.





## Quickstart
```bash
# Clone the repository
git clone --recurse-submodules https://github.com/fuzztruction/fuzztruction.git

# Option 1: Get a pre-built version of our runtime environment.
# To ease reproduction of experiments in our paper, we recommend using our
# pre-built environment to avoid incompatibilities (~30 GB of data will be
# donwloaded)
# Do NOT use this if you don't want to reproduce our results but instead fuzz
# own targets (use the next command instead).
./env/pull-prebuilt.sh

# Option 2: Build the runtime environment for Fuzztruction from scratch.
# Do NOT run this if you executed pull-prebuilt.sh
./env/build.sh

# Spawn a container based on the image built/pulled before.
# To spawn a container using the prebuilt image (if pulled above),
# you need to set USE_PREBUILT to 1, e.g., `USE_PREBUILT=1 ./env/start.sh`
./env/start.sh

# Calling this script again will spawn a shell inside the container.
# (can be called multiple times to spawn multiple shells within the same
#  container).
./env/start.sh

# Runninge start.sh the second time will automatically build the fuzzer.

# See `Fuzzing a Target using Fuzztruction` below for further instructions.
```

## Components
Fuzztruction contains the following core components:

### ****Scheduler****
The scheduler orchestrates the interaction of the generator and the consumer. It governs the fuzzing campaign, and its main task is to organize the fuzzing loop. In addition, it also maintains a queue containing queue entries. Each entry consists of the seed input passed to the generator (if any) and all mutations applied to the generator. Each such queue entry represents a single test case. In traditional fuzzing, such a test case would be represented as a single file. The implementation of the scheduler is located in the [`scheduler`](./scheduler/) directory.

### ****Generator****
The generator can be considered a seed generator for producing inputs tailored to the fuzzing target, the consumer. While common fuzzing approaches mutate inputs on the fly through bit-level mutations, we mutate inputs indirectly by injecting faults into the generator program. More precisely, we identify and mutate data operations the generator uses to produce its output. To facilitate our approach, we require a program that generates outputs that match the input format the fuzzing target expects.

The implementation of the generator can be found in the [`generator`](./generator/) directory. It consists of two components that are explained in the following.

#### ****Compiler Pass****
The compiler pass ([`generator/pass`](./generator/pass/)) instruments the target using so-called [patch points](https://llvm.org/docs/StackMaps.html). Since the current (tested on LLVM12 and below) implementation of this feature is unstable, we patch LLVM to enable them for our approach. The patches can be found in the [`llvm`](https://github.com/fuzztruction/fuzztruction-llvm) repository (included here as submodule). Please note that the patches are experimental and not intended for use in production.

The locations of the patch points are recorded in a separate section inside the compiled binary. The code related to parsing this section can be found at [`lib/llvm-stackmap-rs`](https://github.com/fuzztruction/llvm-stackmap-rs), which we also published on [crates.io](https://crates.io/crates/llvm_stackmap).

During fuzzing, the scheduler chooses a target from the set of patch points and passes its decision down to the agent (described below) responsible for applying the desired mutation for the given patch point.

#### **Agent**
The agent, implemented in [`generator/agent`](./generator/agent/) is running in the context of the generator application that was compiled with the custom compiler pass. Its main tasks are the implementation of a forkserver and communicating with the scheduler. Based on the instruction passed from the scheduler via shared memory and a message queue, the agent uses a JIT engine to mutate the generator.

### ****Consumer****
The generator's counterpart is the consumer: It is the target we are fuzzing that consumes the inputs generated by the generator. For Fuzztruction, it is sufficient to compile the consumer application with AFL++'s compiler pass, which we use to record the coverage feedback. This feedback guides our mutations of the generator.

# Preparing the Runtime Environment (Docker Image)
Before using Fuzztruction, the runtime environment that comes as a Docker image is required. This image can be obtained by building it yourself locally or pulling a pre-built version. Both ways are described in the following. Before preparing the runtime environment, this repository, and all sub repositories, must be cloned:
```bash
git clone --recurse-submodules https://github.com/fuzztruction/fuzztruction.git
```

### ****Local Build****
The Fuzztruction runtime environment can be built by executing [`env/build.sh`](./env/build.sh). This builds a Docker image containing a complete runtime environment for Fuzztruction locally. By default, a [pre-built version](https://hub.docker.com/repository/docker/nbars/fuzztruction-llvm_debug) of our patched LLVM version is used and pulled from Docker Hub. If you want to use a locally built LLVM version, check the [`llvm`](https://github.com/fuzztruction/fuzztruction-llvm) directory.

### ****Pre-built****
In most cases, there is no particular reason for using the pre-built environment -- except if you want to reproduce the exact experiments conducted in the paper. The pre-built image provides everything, including the pre-built evaluation targets and all dependencies. The image can be retrieved by executing [`env/pull-prebuilt.sh`](./env/pull-prebuilt.sh).


The following section documents how to spawn a runtime environment based on either a locally built image or the prebuilt one. Details regarding the reproduction of the paper's experiments can be found in the [`fuzztruction-experiments`](https://github.com/fuzztruction/fuzztruction-experiments) submodule.


## Managing the Runtime Environment Lifecycle
After building or pulling a pre-built version of the runtime environment, the fuzzer is ready to use. The fuzzers environment lifecycle is managed by a set of scripts located in the [`env`](./env/) folder.

| Script | Description |
|--|---|
| [`./env/start.sh`](./env/start.sh)  | Spawn a new container or spawn a shell into an already running container. <b><span style="color:red">Prebuilt:</span></b> Exporting `USE_PREBUILT=1` spawns a container based on a pre-built environment. For switching from pre-build to local build or the other way around, `stop.sh` must be executed first.  |
| [`./env/stop.sh`](./env/stop.sh)  | This stops the container. Remember to call this after rebuilding the image.  |

Using [`start.sh`](./env/start.sh), an arbitrary number of shells can be spawned in the container. Using Visual Studio Codes' [Containers](https://code.visualstudio.com/docs/remote/containers) extension allows you to work conveniently inside the Docker container.

Several files/folders are mounted from the host into the container to facilitate data exchange. Details regarding the runtime environment are provided in the next section.


## Runtime Environment Details
This section details the runtime environment (Docker container) provided alongside Fuzztruction. The user in the container is named `user` and has passwordless `sudo` access per default.

> <b><span style="color:red">Permissions:</span></b> The Docker images' user is named `user` and has the same User ID (UID) as the user who initially built the image. Thus, mounts from the host can be accessed inside the container. However, in the case of using the pre-built image, this might not be the case since the image was built on another machine. This must be considered when exchanging data with the host.

Inside the container, the following paths are (bind) mounted from the host:

| Container Path |  Host Path | Note  |
|:--|---|----|
| `/home/user/fuzztruction`  | `./`  |<b><span style="color:red">Pre-built:</span></b> This folder is part of the image in case the pre-built image is used. Thus, changes are not reflected to the host.  |
| `/home/user/shared`  | `./`  | Used to exchange data with the host. |
| `/home/user/.zshrc`  | `./data/zshrc`  | -  |
|  `/home/user/.zsh_history` | `./data/zsh_history`  | - |
|  `/home/user/.bash_history` |  `./data/bash_history` | - |
| `/home/user/.config/nvim/init.vim`  |  `./data/init.vim` | - |
| `/home/user/.config/Code`  | `./data/vscode-data`  | Used to persist Visual Studio Code config between container restarts. |
| `/ssh-agent`  | `$SSH_AUTH_SOCK`  | Allows using the SSH-Agent inside the container if it runs on the host.  |
| `/home/user/.gitconfig`  | `/home/$USER/.gitconfig`  | Use gitconfig from the host, if there is any config.  |
| `/ccache`  | `./data/ccache`  | Used to persist `ccache` cache between container restarts. |

# Usage
After building the Docker runtime environment and spawning a container, the Fuzztruction binary itself must be built. After spawning a shell inside the container using [`./env/start.sh`](./env/start.sh), the build process is triggered automatically. Thus, the steps in the next section are primarily for those who want to rebuild Fuzztruction after applying modifications to the code.

## Building Fuzztruction
For building Fuzztruction, it is sufficient to call `cargo build` in `/home/user/fuzztruction`. This will build all components described in the [Components](#Components) section. The most interesting build artifacts are the following:


| Artifacts  |  Description  |
|--:|---|
|`./generator/pass/fuzztruction-source-llvm-pass.so` | The LLVM pass is used to insert the patch points into the generator application. <b><span style="color:red">Note:</span></b> The location of the pass is recorded in `/etc/ld.so.conf.d/fuzztruction.conf`; thus, compilers are able to find the pass during compilation. If you run into trouble because the pass is not found, please run `sudo ldconfig` and retry using a freshly spawned shell.  |
| `./generator/pass/fuzztruction-source-clang-fast`  | A compiler wrapper for compiling the generator application. This wrapper uses our custom compiler pass, links the targets against the agent, and injects a call to the agents' init method into the generator's main.  |
| `./target/debug/libgenerator_agent.so`  | The agent the is injected into the generator application.  |
| `./target/debug/fuzztruction`  | The fuzztruction binary representing the actual fuzzer. |

## Fuzzing a Target using Fuzztruction
We will use `libpng` as an example to showcase Fuzztruction's capabilities. Since `libpng` is relatively small and has no external dependencies, it is not required to use the pre-built image for the following steps. However, especially on mobile CPUs, the building process may take up to several hours for building the AFL++ binary because of the collision free coverage map encoding feature and compare splitting.

### **Building the Target**
 <b><span style="color:red">Pre-built: If the pre-built version is used, building is unnecessary and this step can be skipped.</span></b><br>
Switch into the `fuzztruction-experiments/comparison-with-state-of-the-art/binaries/` directory and execute `./build.sh libpng`. This will pull the source and start the build according to the steps defined in `libpng/config.sh`.

### **Benchmarking the Target**
Using the following command
```bash
sudo ./target/debug/fuzztruction fuzztruction-experiments/comparison-with-state-of-the-art/configurations/pngtopng_pngtopng/pngtopng-pngtopng.yml  --purge --show-output benchmark -i 100
```
allows testing whether the target works. Each target is defined using a `YAML` configuration file. The files are located in the `configurations` directory and are a good starting point for building your own config. The `pngtopng-pngtopng.yml` file is extensively documented.


### **Troubleshooting**
If the fuzzer terminates with an error, there are multiple ways to assist your debugging efforts.

- Passing `--show-output` to `fuzztruction` allows you to observe stdout/stderr of the generator and the consumer if they are not used for passing or reading data from each other.
- Setting AFL_DEBUG in the `env` section of the `sink` in the `YAML` config can give you a more detailed output regarding the consumer.
- Executing the generator and consumer using the same flags as in the config file might reveal any typo in the command line used to execute the application. In the case of using `LD_PRELOAD`, double check the provided paths.

### **Running the Fuzzer**
To start the fuzzing process, executing the following command is sufficient:
```bash
sudo ./target/debug/fuzztruction ./fuzztruction-experiments/comparison-with-state-of-the-art/configurations/pngtopng_pngtopng/pngtopng-pngtopng.yml fuzz -j 10 -t 10m
```
This will start a fuzzing run on 10 cores, with a timeout of 10 minutes. Output produced by the fuzzer is stored in the directory defined by the `work-directory` attribute in the target's config file. In case of `pngtopng`, the default location is `/tmp/pngtopng-pngtopng`.

If the working directory already exists, `--purge` must be passed as an argument to `fuzztruction` to allow it to rerun. The flag must be passed before the subcommand, i.e., before `fuzz` or `benchmark`.

### **Combining Fuzztruction and AFL++**
For running AFL++ alongside Fuzztruction, the `aflpp` subcommand can be used to spawn AFL++ workers that are reseeded during runtime with inputs found by Fuzztruction. Assuming that Fuzztruction was executed using the command above, it is sufficient to execute
```
sudo ./target/debug/fuzztruction ./fuzztruction-experiments/comparison-with-state-of-the-art/configurations/pngtopng_pngtopng/pngtopng-pngtopng.yml aflpp -j 10 -t 10m
```
for spawning 10 AFL++ processes that are terminated after 10 minutes. Inputs found by Fuzztruction and AFL++ are periodically synced into the `interesting` folder in the working directory. In case AFL++ should be executed independently but based on the same `.yml` configuration file, the `--suffix` argument can be used to append a suffix to the working directory of the spawned fuzzer.


### **Computing Coverage**
After the fuzzing run is terminated, the `tracer` subcommand allows to retrieve a list of covered basic blocks for all interesting inputs found during fuzzing. These traces are stored in the `traces` subdirectory located in the working directory. Each trace contains a zlib compressed JSON object of the addresses of all basic blocks (in execution order) exercised during execution. Furthermore, metadata to map the addresses to the actual ELF file they are located in is provided.

The `coverage` tool located at `./target/debug/coverage` can be used to process the collected data further. You need to pass it the top-level directory containing working directories created by Fuzztruction (e.g., `/tmp` in case of the previous example). Executing `./target/debug/coverage /tmp` will generate a `.csv` file that maps time to the number of covered basic blocks and a `.json` file that maps timestamps to sets of found basic block addresses. Both files are located in the working directory of the specific fuzzing run.

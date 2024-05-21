# eBPF Tutorial @TMA PhD School
This repository contains the material for the eBPF tutorial at the TMA PhD School.

In particular, the tutorial is divided into the following sections:
1. [Networking with eBPF](#networking-with-ebpf)
2. [Tracing with eBPF](#tracing-with-ebpf)

Before starting the tutorial, please make sure to have the following requirements installed.
You can find the installation instructions in the [Installation](#installation) section.

## Installation
To follow the tutorial, you can [manually install](#manual-installation) the required dependencies or use the [provided VMs](#provided-vms).

### 1. Manual Installation
To manually install the required dependencies, you need to have a Linux machine with a kernel version >= 5.15.
All the commands are tested on Ubuntu 22.04.

#### Dependencies
You can install the required dependencies by running the following commands:
```bash
$ sudo apt update
$ sudo apt install -y git clang llvm llvm-dev libelf-dev linux-headers-generic build-essential libc6-dev-i386 make
$ sudo apt install -y libbfd-dev libcap-dev libpcap-dev pkg-config net-tools libyaml-dev
```

At this point, you can start building the tutorial, following the instructions in the [Build](#build) section.

### 2. Provided VMs
To make it easier for you to follow the tutorial, we provide two VMs with all the required dependencies installed.

Depending on your machine's hardware architecture, the instructions and the VM you need to download will vary. 
We offer two distinct VMs tailored for x86\_64 and ARM64 architectures.

#### Windows, Linux or MacOS with Intel/AMD CPU
You can download the VirtualBox `nc-labs-x86.ova` image at the following URL:

[`nc-labs-x86.ova`](https://polimi365-my.sharepoint.com/:u:/g/personal/10457521_polimi_it/EUlmWu7qjuVJjpQKVTV1yOcBzhyXGdLe3ik2uWPfbhG83g?e=F6XCJx)

Before deploying the VM, you must install `VirtualBox`, compatible with Windows, Linux, and macOS. 
Download the VirtualBox binaries at the following URL:

[https://www.virtualbox.org/wiki/Downloads](https://www.virtualbox.org/wiki/Downloads)

Once installed, open the `nc-labs-x86.ova` file to boot the VM and access the lab environment.

#### MacOS with Apple Silicon (ARM64) CPU
You can download the VM `nc-labs-arm64.zip` image at the following URL:

[`nc-labs-arm64.zip`](https://polimi365-my.sharepoint.com/:u:/g/personal/10457521_polimi_it/EcykVwiqYSdHpx_WlO8qDwIBajDGURzxskLnpTBH9SyOLA?e=PIR2mf)

In this case, you need to install VMwareFusion, available at the following URL:

[https://www.vmware.com/products/fusion.html](https://www.vmware.com/products/fusion.html)

**Note:** A VMware Customer Connect account is necessary for the installation. You can register using your school address or a personal email. The VMware Fusion Player license is free for personal and student use. After installation, enter your account's license key.

#### Import VM into VMware Fusion
After downloading the `nc-labs-arm64.zip`, extract it to find the `nc-labs-arm64.vmwarevm` file.

Open VMware Fusion, navigate to *File* -> *Open*, select the `nc-labs-arm64.vmwarevm` file and start the VM.
When prompted whether the machine was moved or copied, choose **I copied it**.

#### Log into the lab VM
Log into the lab VM using the following credentials:

- **Username**: nc-labs
- **Password**: ncforever

## Build
To build the tutorial material, you can clone the repository and run the following commands:

```bash
git clone https://github.com/sebymiano/tma-ebpf-tutorial.git --recurse-submodules
cd tma-ebpf-tutorial
make
```

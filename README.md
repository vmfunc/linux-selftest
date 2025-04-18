## Building

```bash
# Debian/Ubuntu
sudo apt-get install linux-headers-$(uname -r)
# Fedora
sudo dnf install kernel-devel
# Arch
sudo pacman -S linux-headers
# Gentoo
sudo emerge sys-kernel/linux-headers

# Build
make
```

## Installation

```bash
sudo make install
sudo modprobe selftest
```

## Usage

1. Through sysfs:
```bash
cat /sys/kernel/selftest/test_results
```

2. Through debugfs:
```bash
cat /sys/kernel/debug/selftest/results
```

## Uninstalling

```bash
sudo rmmod selftest
```
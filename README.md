# torus
An x86/x86-64 experimental PoC for dumping the addresses & disassembly of kernel functions from userspace.

<div align="center">
    <img src="https://user-images.githubusercontent.com/105472509/177006259-e755f7a6-7756-4e3c-8012-98f4f71dfc9d.png" width="1000px"><br>
</div>

## Description
`torus` is an experimental PoC (Proof-Of-Concept) utility that performs reads specific bytes from a decompressed `vmlinuz` kernel image by using `System.map`, so that signature scanning can be performed to find the addresses of kernel functions within kernel virtual memory from userspace.

### Features
- Disassembly output
- Reports the addresses of the located kernel functions

### Built with
- C

## Getting started
### Compiling
To compile `torus`, simply execute the following script:
- `./build.sh`

### Decompressing vmlinuz
In order to decompress `vmlinuz` (located in `/boot`) so you can pass it to `torus` as an argument, download and run the script provided at:

- `https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux`

### Usage
- `./torus <decompressed_vmlinuz>`

## Credits
```
https://github.com/xmmword
```
### Contributions 🎉
###### All contributions are accepted, simply open an Issue / Pull request.

# torus
An x86/x86-64 experimental PoC for verifying the integrity of the kernel during runtime.

<div align="center">
    <img src="https://user-images.githubusercontent.com/105472509/176983932-3edca1ae-f248-41be-8037-3417a71447dc.png" width="750px"><br>
</div>

## Description
`torus` is an experimental PoC (Proof-Of-Concept) utility that compares static kernel code from a decompressed `vmlinuz` kernel image against the executable
segments of kernel virtual memory.

### Features
- Disassembly output
- Checks for anomalies/modifications within kernel code

### Built with
- C

## Getting started
### Compiling
To compile `torus`, simply execute the following script:
- `./build.sh`

### Usage
- `./torus <vmlinuz>`

## Credits
```
https://github.com/xmmword
```
### Contributions 🎉
###### All contributions are accepted, simply open an Issue / Pull request.

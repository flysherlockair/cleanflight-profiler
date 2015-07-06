# Cleanflight sampling profile decoder

This tool allows logs created by Cleanflight's profiler feature to be decoded.

Usage:

```
go run cleanflight_profiler.go --elf cleanflight_NAZE.elf --log PROF0001.TXT
```

## Requirements

You'll need [Go](https://golang.org/) and the `arm-none-eabi-addr2line` utility to be on your PATH. `arm-none-eabi-addr2line` 
is part of the  [GNU Tools for ARM Embedded Processors](https://launchpad.net/gcc-arm-embedded) project, which you'll also need installed in order to build Cleanflight with the profiler enabled and generate the .elf file needed for debug information.
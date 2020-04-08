# Shtreeba [![C++](https://img.shields.io/badge/language-C%2B%2B-%23f34b7d.svg?style=plastic)](https://en.wikipedia.org/wiki/C%2B%2B) [![Windows](https://img.shields.io/badge/platform-Windows-0078d7.svg)](https://en.wikipedia.org/wiki/Microsoft_Windows) [![x86](https://img.shields.io/badge/arch-x86-red.svg)](https://en.wikipedia.org/wiki/X86) [![License](https://img.shields.io/github/license/mdilai/Shtreeba.svg)](LICENSE) ![Windows](https://github.com/mdilai/Shtreeba/workflows/Windows/badge.svg?branch=master&event=push)

VAC-proof 32bit DLL injector written in C++, using memory mapping and thread hijacking techniques

## Features:
* **Library** - full-featured VAC-proof and VirusTotal-proof library for injecting third-party DLL's into 32-bit applications.
* **UI** - Simple interface for accessing Library as injector.

## Getting started

### Prerequisites

Written using **Microsoft Visual Studio 2019**, work with older versions not guaranteed.

### Automatic build
To download latest compilled commit, press on the [Actions](https://github.com/mdilai/Shtreeba/actions) button, then choice `Master` branch, click on latest commit and download binary from `Artifacts` section

### Compiling from source

Open **Shtreeba.sln** in Microsoft Visual Studio 2019. 
Make sure build configuration is set to `Release | x86` and build the solution. 

If everything went right you will find `Shtreeba.exe` and `Shtreeba.dll` files in Release folder.
Copy both files to some location and run `Shtreeba.exe` to generate default config

### Usage.
* Put your **DLL** to inject together with `Shtreeba.exe` and `Shtreeba.dll`
* Edit `Shtreeba.ini` to set **path** and **process name**
* Run `Shtreeba.exe` as **Administrator**

### Configuration
Configuration file Shtreeba.ini will be automatically created after first run. Here is default sample config:
```
[Library]
DLL=Jweega.bin
ProcessName=csgo.exe
[UI]
Silent=0
CloseDelay=3000
```
* **DLL** - Absolute or relative path to DLL for injection. By default is `Jweega.bin` at current work directory
* **ProcessName** - Name of process for injection into. By default is `csgo.exe`
* **Silent** - Disable non-critical notifications. By default is `0`.
* **CloseDelay** - Interval in milliseconds for automatical closing of UI Messagebox after injecting (when `Silent=0`)

## License

> Copyright (c) 2019-2020 Maksym Dilai

This project is licensed under the [GPL-3.0 License](https://opensource.org/licenses/GPL-3.0) - see the [LICENSE](LICENSE) file for details.

## See also
- [JweegaCSGO](https://github.com/mdilai/JweegaCSGO) - free and open source cheat for CS:GO based on [Osiris](https://github.com/danielkrupinski/Osiris)

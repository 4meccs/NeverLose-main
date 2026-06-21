# NeverLose

CS:GO cheat loader that takes a dumped NeverLose binary, maps it manually, and applies a ton of runtime fixes to make it actually work. Also comes with hardware spoofing, a local Rust backend, and an injector.

## What it does

- Manually maps the encrypted cheat binary (`nl.bin`) at a fixed address using NT API stuff
- Fixes the dumped binary at runtime — resolves 940+ imports, 830+ Source Engine interfaces, 175+ convars, and 390+ sigscanned functions
- Spoofs MAC addresses (7 fake adapters), disk geometry/serial, CPUID (emulates AMD Ryzen 7 7700X through VEH), PEB, KUSER_SHARED_DATA, and Windows version
- Hooks `getaddrinfo` to redirect all cheat traffic to `127.0.0.1:30030`
- Runs a local Rust server that serves configs, scripts, styles, translations, and builds modules with AES-128-CBC + LZ4
- Injects the DLL into CS:GO once it finds the `Valve001` window

## Structure

```
neverlose/          C++ cheat loader (builds as DLL or EXE)
injector/           C++ injector
server/rust-server/ Rust backend for configs/scripts/skins
libraries/          129 Lua scripts
detours/            Microsoft Detours
phnt/               Process Hacker NT headers
```

## Building

### Cheat Loader

Open `neverlose.sln` in Visual Studio 2022, or just run:

```
msbuild neverlose.sln /p:Configuration=Release /p:Platform=x86 /p:PlatformToolset=v143
```

Uses C++20, Windows 10 SDK, toolset v145 or v143.

### Rust Server

```bash
cd server/rust-server
cargo build --release
```

## Usage

1. Build the loader and injector
2. Start CS:GO
3. Run the injector as Administrator — it'll inject `neverlose.dll` into the game

## Dependencies

- **phnt** — NT API types
- **Microsoft Detours** — hooking
- **nlohmann/json** — JSON
- **Rust crates** — axum, tokio, flatbuffers, aes/cbc, lz4_flex, notify, rcgen, rustls

## Credits

bob and spiny

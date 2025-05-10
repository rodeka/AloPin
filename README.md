# AloPin

A tool for recovering (brute-forcing) the Family View PIN. This project was inspired by [SPPRT](https://github.com/Ne3tCode/SPPRTool), but I wanted to build my own version — so I guess you could call it PET

---

## Requirements

- **OS:** Windows (Steamworks SDK is Windows-only)
- **CMake:** ≥ 3.20
- **Compiler:** MSVC (Visual Studio 2019/2022)
- **Steamworks SDK:** DAutomatically cloned as a submodule into `external/SteamworksSDK`
  - Requires 64-bit redistributables: `redistributable_bin/win64/steam_api64.{dll,lib}`

---

## Building

1. Clone the repository and enter it:

   ```sh
   git clone --recurse-submodules https://github.com/rodeka/AloPin
   cd AloPin
   ```

2. Create and switch to a build directory:

   ```sh
   mkdir build && cd build
   ```

3. Configure with CMake:

   ```sh
   cmake .. -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release
   ```

4. Build:

   ```sh
   cmake --build . --config Release
   ```

   - Static libraries (`crypto.lib`, `proto.lib`) appear in `build/lib/Release/`.
   - The executable (`alopin.exe`) and DLLs are in `build/Release/`.

---

## Running

It is a requirement to have Steam running and be logged into the account.
```sh
cd build/bin/Release
./alopin.exe [options]
```

---

## Testing

```sh
cd build
ctest --output-on-failure
```

Runs all unit tests if built with `BUILD_TESTING=ON`.

---

## Dependencies

- **crypto** (internal): PBKDF2, scrypt, SHA-256, HMAC-SHA256
- **proto** (internal): simple serialization library
- **Steamworks SDK:** Steam API integration

---

## Disclaimer

_This software is not intended to gain unauthorized access to Steam account in any case. Use it at your own risk and only with the permission of the owner of the account._

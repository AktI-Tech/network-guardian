# Visual Studio Build Tools Installation

## Error
```
linker `link.exe` not found
```

This means you need the C++ build tools to compile Rust on Windows.

## Solution: Install Visual Studio Build Tools

1. **Download Visual Studio Build Tools**
   - Go to: https://visualstudio.microsoft.com/downloads/
   - Look for "Build Tools for Visual Studio 2022"
   - Click "Download"

2. **Run the installer**
   - Execute the downloaded `.exe` file
   - Click "Continue"

3. **Select "Desktop development with C++"**
   - Check the checkbox for "Desktop development with C++"
   - This should auto-select the MSVC compiler and linker
   - Click "Install"

4. **Wait for installation** (5-15 minutes)

5. **Restart your computer** (recommended)

6. **Try building again**
   ```bash
   cd C:\Users\aerok\NetworkGuardian
   C:\Users\aerok\.cargo\bin\cargo.exe build --release
   ```

## Alternative: Use GNU Toolchain

If you prefer, you can use the GNU/MinGW toolchain instead:

```bash
rustup target install x86_64-pc-windows-gnu
cd C:\Users\aerok\NetworkGuardian
C:\Users\aerok\.cargo\bin\cargo.exe build --release --target x86_64-pc-windows-gnu
```

But this requires MinGW to be installed and is generally slower.

---

**Recommended**: Install Visual Studio Build Tools as described above.

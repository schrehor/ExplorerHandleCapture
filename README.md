# ExplorerHandleCapture

An experimental x64 process-handle capture PoC for Windows written in C.

Hooks the `CreateProcessW` wrapper in Explorer and saves its stack pointer during process creation. The companion `HandleReader` uses the captured stack to find the child's process handle, duplicate it and attempt a memory read.

Instruction decoding uses the bundled Zydis library. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Build target

Windows x64. Visual Studio with the v145 C/C++ toolset and Windows SDK.

Open `ExplorerHandleCapture.slnx` and build both projects in Debug or Release x64.

## Usage

```powershell
.\x64\Release\ExplorerHandleCapture.exe --assess
.\x64\Release\ExplorerHandleCapture.exe <EXPLORER_PID>
.\x64\Release\HandleReader.exe <EXPLORER_PID> <RSP_SLOT_ADDRESS_HEX>
```

`--assess` checks the local wrapper layout. Capture mode prints the stack-pointer slot address for the reader.

Explorer is temporarily suspended when the hook fires. Run the reader from another console before pressing Enter in the controller to restore the hook and resume Explorer. Use an isolated, recoverable environment.

The hook depends on Windows-specific code and stack layouts. Successful live capture, handle reading and restoration have not been demonstrated end to end.

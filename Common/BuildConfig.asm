
# Determines which platform to target, retail or debug:
#.set RETAIL_BUILD,             1
#.set DEBUG_BUILD,              1

# Determines which game to target for the exploit:
#.set TONY_HAWK_AW,             1

# Sanity check compiler flags.
.ifdef RETAIL_BUILD
    .ifdef DEBUG_BUILD
        .error "RETAIL_BUILD and DEBUG_BUILD cannot be specified at the same time"
    .endif
.else
    .ifndef DEBUG_BUILD
        .error "Must specify one of RETAIL_BUILD or DEBUG_BUILD"
    .endif
.endif

.ifdef DEBUG_BUILD
    .ifdef RETAIL_BUILD
        .error "RETAIL_BUILD and DEBUG_BUILD cannot be specified at the same time"
    .endif
.else
    .ifndef RETAIL_BUILD
        .error "Must specify one of RETAIL_BUILD or DEBUG_BUILD"
    .endif
.endif


###########################################################
# Include kernel config for specified platform.
.ifdef RETAIL_BUILD
    .include "KernelConfig_Retail_17559.asm"
.else
    .include "KernelConfig_Debug.asm"
.endif

# Make sure the kernel version is specified which indicates the kernel address file was included.
.ifndef KRNL_VER
    .error "Kernel config not specified"
.endif


###########################################################
# Include game config for specified target.
.ifdef TONY_HAWK_AW
    .include "TonyHawk.asm"
.endif
.ifdef RB_BLITZ
    .include "RBBlitz.asm"
.endif

# Sanity check the game config.
.ifndef RuntimeDataSegmentAddress
    .error "Game config must define RuntimeDataSegmentAddress to a valid address"
.endif

# Xbox360BadUpdate
Bad Update is a non-persistent software only hypervisor exploit for Xbox 360 that works on the latest (17559) software version. This repository contains the exploit files that can be used on an Xbox 360 console to run unsigned code. This exploit can be triggered using one of the following games:
- Tony Hawk's American Wasteland (NTSC)
- Call of Duty: Modern Warfare (NTSC)

For information on how to use the exploit see the Quick Start section below. For information on how the exploit works or how to compile it from scratch see the relevant sections below.

# Quick Start
To run the Bad Update exploit you'll need one of the supported games listed above and a USB stick. The following steps give a brief overview of how to run the exploit, for more detailed steps please see the wiki.
1. Download the Xbox360BadUpdate-Retail-USB.zip file from the releases section and extract the files.
2. Format a USB stick to FAT32.
3. Copy the contents of the folder matching the game you want to use for the exploit to the root of the USB stick. Ex: if you're using Tony Hawk's American Wasteland copy the contents of the Tony Hawk's American Wasteland folder to the root of the USB stick. The root of the USB stick should contain the following files/folders: BadUpdatePayload, Content, name.txt.
4. Place the unsigned executable you want to run when the exploit triggers into the BadUpdatePayload folder on the USB stick and name it "default.xex" (replace any existing file in the folder). This xex file must be in retail format and have all restrictions removed (see the wiki for how to do this).
5. Insert the USB stick into your Xbox 360 console and power it on.
6. Sign into the Player 1 profile and run the game you're using to trigger the exploit.
7. Follow the instructions for the game you chose to load the hacked game save file and begin the exploit process.
8. The console's ring of light will flash different colors/segments during the exploit process to indicate progress. For information on what the different values mean see the following page.
9. Once the exploit triggers successfully the RoL should be fully lit in green. The hypervisor has now been patched to run unsigned executables and your unsigned default.xex file will be run.

The exploit has a 30% success rate and can take up to 20 minutes to trigger successfully. If after 20 minutes the exploit hasn't triggered you'll need to power off your Xbox 360 console and repeat the process from step 5.

# Compiling
Compiling the exploit is only required if you're an advanced user that wants to experiment with it. For general users there are precompiled versions of all the exploit files in the releases section. Compiling the exploit is a multi-step process and is explained in detail in the wiki.

# Explanation of the Exploit
Details of how the exploit works can be found in the wiki. For additional information on the Xbox 360 security system or how I found and wrote the exploit please see the following blog posts:
- [Hacking the Xbox 360 Hypervisor Part 1: System Overview](https://icode4.coffee/?p=1047)
- [Hacking the Xbox 360 Hypervisor Part 2: The Bad Update Exploit](https://icode4.coffee/?p=1081)

# FAQ
**Q: What does this provide over the RGH Hack/should I use this instead of RGH?**
A: This is a software only exploit that doesn't require you open your console or perform any soldering to use. Other than that it's inferior to the RGH exploit in every way and should be considered a "proof of concept" and not something you use in place of RGH.

**Q: Can this be turned into a softmod?**  
A: No, the Xbox 360 boot chain is very secure with no attack surface to try and exploit. There will never exist a software only boot-to-hacked-state exploit akin to a "softmod".

**Q: Does this work on winchester consoles?**  
A: I haven't personally tested it but I don't believe there's any reason it wouldn't work. Nothing in the exploit is hardware specific.

**Q: I ran the exploit and nothing happened?**  
A: The exploit has a 30% success rate. If after running for 20 minutes the exploit hasn't triggered you'll need to reboot your console and try again.

**Q: Why does the exploit only run a single unsigned xex?**  
A: My goal was to hack the hypervisor, not to develop a robust all-in-one homebrew solution. Someone else will need to develop a post-exploit executable that patches in all the quality of life things you would get from something like the RGH exploit.

**Q: Why does the exploit take so long to trigger/have a lot success rate?**  
A: The exploit is a race condition that requires precise timing and several other conditions to be met for it to trigger successfully. As such it can take a while for that to happen.

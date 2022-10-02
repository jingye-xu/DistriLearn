# DistriLearn: Unified Deployment

In this part of the project, we are merging the distributed portion into each individual access point using our proposed deliberation/collaborative algorithm.

In order to do so, we need to run these systems on the devices powered by OpenWRT. There are five methods we can use:
1. Using DebianWRT (i.e., debootstrap)
2. Using KVM & Qemu we use a device running a <i>normal</i> distribution such as Ubuntu to run OpenWRT
3. Using a device powered by OpenWRT, we can use it as a host to a KVM & QEMU. Then run our systems on something such as Debain or Ubuntu, etc, within the virtual environment.
4. Use Docker 
5. Type-2 virtual machine.

We choose to implement method #1. 

<ins>Notes</ins>: 
* Methods 1 and 3 are the most realistic and scalable to real-world routers running OpenWRT.
* All of these methods have added overhead; the Type-1 hypervisor (option 2) and option 1 are the closet to being as efficient as possible. Option 1 uses external filesystems located in a USB (if you don't use the SD card), which slows down access times. 

# Instructions to install Debian on OpenWRT

<b>What is DebainWRT / Debootstrap? and why?</b> 
* It is a way to install the Debian base system into an existing system without conflicts. 
* Since we can essentially run Debian alongside our OpenWRT system, this means we can easily install almost everything we need, whereas OpenWRT by itself is very limited.


For the following instructions, always keep in mind that <mountpoint> is the mount path to which your debian root is located.

<b> Steps for method 1 </b>
- Flash an OpenWRT-ext4 image to an SD card and increase the root partition size in GParted. (This may vary depending on what you deploy on)
- Load the router and configure it by following the GitHub instructions for access points on the main branch. I disable IPv6 and update opkg packages.
- Take the USB drive you want to use and use either fdisk or GParted to partition it into: ext4 and swap partitions (alternatively you can do this in the SD itself if you’re inclined).
- Install all necessary USB support with inclusion for block devices: **block-mount, kmod-usb-storage, kmod-usb-storage-extras, kmod-fs-ext4.**
- Then install dependencies for DebianWRT: binutils, debootstrap
- Create a new mount point, but you can use the entire mount folder; either way, you need to mount the USB ext4 partition so that the filesystem can be recognized.  Use `lsblk` or `block list` to see what the storage medium’s UUID and device number is.
- In `/etc/config/fstab` you should create a backup of the original file, then change the swap entry to point to the one for your external storage. You should add a mount point for the UUID of the USB’s ext4 partition to automatically mount on boot.
- I use the following command `debootstrap --arch=arm64 bullseye <ext4 mount point>` `https://deb.debian.org/debian/`
    - The architecture I choose is arm 64 bit (ensure the architecture matches what your processor can support).
    - The Debian version I want is bullseye (i.e. the most recent)
    - The ext4 mount point should be where in /mnt/ your ext4 partition has been mounted.
    - Debian has many mirrors, I choose this one.
    - **If the base system installs correctly, you should see “base system installed correctly”**
- execute the following:
    - `mount -t proc /proc <mountpoint>/proc/`
    - `mount -t sysfs /sys <mountpoint>/sys/`
    - `mount -o bind /dev <mountpoint>/dev/`
- execute `chroot <mountpoint> /bin/bash`
    - In my case, I created `/mnt/debroot` as my mount point so I did: `chroot /mnt/debroot /bin/bash`
- Set a password for the root system - as default I will use openwrt<br>

TODO: More instructions coming soon for automatic mounting and chrooting

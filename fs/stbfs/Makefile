STBFS_VERSION="0.1"

EXTRA_CFLAGS += -DSTBFS_VERSION=\"$(STBFS_VERSION)\"

obj-$(CONFIG_STB_FS) += stbfs.o

stbfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

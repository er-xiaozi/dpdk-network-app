#!/bin/bash

# DPDK网卡绑定脚本

# 1. 查网卡
echo "检查以太网卡..."
lspci | grep Ethernet

# 2. 关闭网卡
echo "关闭ens160网卡..."
sudo ifconfig ens160 down
if [ $? -ne 0 ]; then
    echo "错误：无法关闭ens160网卡"
    exit 1
fi

# 3. 加载UIO驱动并绑定网卡
echo "加载UIO驱动..."
sudo modprobe uio
if [ $? -ne 0 ]; then
    echo "错误：无法加载uio模块"
    exit 1
fi

echo "加载igb_uio驱动..."
cd /home/lwj/Desktop/dpdk-kmods/linux/igb_uio
make clean
make
sudo insmod ./igb_uio.ko intr_mode=legacy
if [ $? -ne 0 ]; then
    echo "错误：无法加载igb_uio模块"
    exit 1
fi

echo "绑定网卡到igb_uio..."
sudo dpdk-devbind.py --bind=igb_uio 0000:03:00.0
if [ $? -ne 0 ]; then
    echo "错误：无法绑定网卡"
    exit 1
fi

# 4. 返回DPDK目录
cd /home/lwj/Desktop/DPDK

echo "网卡绑定操作完成！"
# dpdk-network-app
使用DPDK实现TCP/UDP协议栈
开发测试环境 ：ubuntu22.04.5  dpdk22.11.8

### 一、DPDK版本升级

1、下载DPDK22.11.08版本tar压缩包 [地址](https://core.dpdk.org/download/)

2、删除旧版本DPDK

```
sudo pkill -f dpdk  # 终止所有DPDK相关进程
sudo rm -rf /usr/local/lib/libdpdk*      # 动态库
sudo rm -rf /usr/local/include/dpdk      # 头文件
sudo rm -f /usr/local/lib/pkgconfig/libdpdk.pc  # pkg-config文件
sudo rm -f /usr/local/bin/dpdk-*         # 示例程序（如dpdk-testpmd）
sudo rm -f /lib/modules/$(uname -r)/extra/dpdk/*.ko  # 内核模块路径
sudo depmod -a  # 更新模块依赖关系
sudo find /usr/local/include/ -type f -name "rte_*" -exec rm -f {} \;
```

清理环境变量

```
export RTE_SDK=/path/to/dpdk-20.11.10
export RTE_TARGET=x86_64-native-linux-gcc
```

```
source ~/.bashrc
sudo ldconfig  # 确保系统不再识别已删除的DPDK库
```

3、安装新版DPDK

```
sudo tar -xJf dpdk-22.11.8.tar.xz     
cd dpdk-stable-22.11.8
```

启用kni 编辑meson_options.txt文件，修改

| `disable_libs` | `'flow_classify,kni'` | 禁用指定的库。设为空（`''`）                                 |
| -------------- | --------------------- | ------------------------------------------------------------ |
| `enable_kmods` | `false`               | 是否编译内核模块（如 `rte_kni`）。需设为 `true` 并指定 `kernel_dir`。 |

```
sudo meson build
cd build
sudo ninja
sudo ninja install
sudo ldconfig
```
编译安装完成后通过下面的命令检查是否生成kni
find /lib/modules/$(uname -r) -name rte_kni.ko
手动加载kni
sudo insmod /lib/modules/6.8.0-60-generic/extra/dpdk/rte_kni.ko
ls /dev/kni -l
#### 二、VPP安装

```
git clone -b stable/2206 https://github.com/FDio/vpp.git
cd vpp
sudo ./extras/vagrant/build.sh && make //执行vpp自带的脚本，所有环境都会准备好
```
脚本运行成功后会在在vpp/build-root目录下生成.deb的安装包, 安装：

```
sudu dpkg -i build-root/*.deb
```
执行完成以后，检查:
etc/vpp/下生成startup.conf文件
/usr/lib/x86_64-linux-gnu/vpp_plugins目录下生成.so

#### VPP启动
down网卡，绑定igb驱动
```
sudo modprobe uio
cd /home/lwj/Desktop/dpdk-kmods/linux/igb_uio
make clean && make
sudo insmod ./igb_uio.ko intr_mode=legacy
sudo ifconfig ens160 down
sudo ifconfig ens192 down
sudo dpdk-devbind.py --bind=igb_uio 0000:03:00.0
sudo dpdk-devbind.py --bind=igb_uio 0000:0b:00.0
```
编辑vpp startup.conf文件
```
vim /etc/vpp/startup.conf
dpdk {
        dev 0000:03:00.0 { name ens160 }
        dev 0000:0b:00.0 { name ens192 }
      }
```
启动vpp
```
sudo vpp -c /etc/vpp/startup.conf
//新开一个终端
sudo vppctl
vpp# set int state ens160 up
vpp# set int ip address ens160 192.168.141.145/24 
```

暂未实现TCP的滑动窗口拥塞控制
 
### dpdk 安装注意事项



sudo ifconfig vEth0 192.168.141.145 up
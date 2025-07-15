# dpdk-network-app
使用DPDK实现TCP/UDP协议栈
开发测试环境 ：ubuntu22.04.5  dpdk22.11.8

### 使用方法
dpdk启动环境配置
``` 

./
```

暂未实现TCP的滑动窗口拥塞控制
 
### dpdk 安装注意事项
kni的编译
下载解压dpdk源代码后进入解压目录修改meson_ontions.txt
disable_libs禁用指定的库。设为（''）可启用 KNI。
enable_kmods是否编译内核模块（如rte_kni）。需设为 true 并指定 kernel_dir。

编译安装完成后通过下面的命令检查是否生成kn
find /lib/modules/$(uname -r) -name rte_kni.ko
手动加载kni
sudo insmod /lib/modules/6.8.0-60-generic/extra/dpdk/rte_kni.ko
ls /dev/kni -l
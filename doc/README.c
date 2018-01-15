Depends:
libcurl4-openssl-dev
libmysqlclient-dev
mysql-client
mysql-server
liblz4-dev
libtspi-dev
libsystemd-dev
libglib2.0-dev

人脸识别库放置位置：~/CCISServer/res/

/*
opencv编译和安装
请不要安装系统自带的opencv相关包，请使用opencv源码进行编译安装，源码包过大，需要
请从下面链接下载或联系:lixiang@kylinos.cn
服务器操作系统编译opencv需要安装的依赖：
sudo apt-get install cmake g++ libgtk2.0-dev libglib2.0-dev libgstreamer0.10-dev libdc1394-22-dev libv4l-dev libavcodec-dev libavformat-dev libavutil-dev libswscale-dev libtiff5-dev libjasper-dev
下载源码:
http://sourceforge.net/projects/opencvlibrary/files/opencv-unix/2.4.9/opencv-2.4.9.zip/download
解压:
  - unzip opencv-2.4.9.zip
安装:
  - cd opencv-2.4.9
  - cmake CMakeLists.txt
  - make
  - sudo make install
  - sudo vim /etc/ld.so.conf   (参考源码lib目录下ld.so.conf文件)
        add one line:
        include /usr/local/lib
  - sudo vim /etc/bash.bashrc  (参考源码lib目录下bash.bashrc文件)
        add two lines:
        PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig
        export PKG_CONFIG_PATH
使用下面的动态库管理命令ldconfig，让opencv的相关链接库被系统共享
  - sudo ldconfig -v
目前deb生成有依赖问题：
1)使用服务器之前，请先将源码目录下的FaceMatcherSDK-2.3文件夹拷贝到当前用户主目录下。
2)sudo cp lib/libFaceMatcherDll.so /usr/lib
3)sudo cp bin/CCISServer /usr/bin
*/

mysql数据操作：
sudo apt-get install mysql-server mysql-client libmysqlclient-dev
sudo service mysql restart
mysql -u root -p
导出数据库和表结构：mysqldump -uroot -p kylindb > test.sql
只导出表结构：mysqldump -uroot -p -d kylindb > test.sql

导入数据库:
方法一：
（1）选择数据库
mysql>use kylindb;
（2）设置数据库编码
mysql>set names utf8;
（3）导入数据（注意sql文件的路径）
mysql>source /home/lixiang/test.sql;
方法二：
mysql -u用户名 -p密码 数据库名 < 数据库名.sql
mysql -ulixiang -p kylindb < test.sql

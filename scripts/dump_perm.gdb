set pagination off
set confirm off
break *0x46f510
commands 1
  silent
  set $cfg = (char*)$rcx
  set $w = *(int*)($cfg+4)
  printf "UnpackLineRT width=%d scale=%d\n", $w, *(int*)$cfg
  eval "dump binary memory /home/bine/Developer/lab/vfs495/captures/perm_%d.bin $cfg+0x57c $cfg+0x57c+%d", $w, $w*2
  printf "dumped perm width=%d\n", $w
  detach
  quit
end
run getprintwait -doinit
quit

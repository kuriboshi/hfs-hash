# hfs-hash
Calculate hashes for files in HFS file systems to detect corruption

`hfs-hash` uses a simple config file in the home directory called `.hfs-hash.rc`.
It contains a list of directories to scan and extensions to consider.
Example:

```
scan = /Volumes/Disk/iTunes
scan = /Volumes/Disk/Pictures
scan = /Volumes/External/Movies
type = .cr2
type = .dng
type = .jpg
type = .mos
type = .m4p
type = .m4v
type = .mov
```

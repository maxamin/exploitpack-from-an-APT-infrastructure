PROT_READ           =0x1        # page can be read 
PROT_WRITE          =0x2        # page can be written 
PROT_EXEC           =0x4        # page can be executed 
PROT_SEM            =0x8        # page may be used for atomic ops 
PROT_NONE           =0x0        # page can not be accessed 
PROT_GROWSDOWN      =0x01000000 # mprotect flag: extend change to start of growsdown vma 
PROT_GROWSUP        =0x02000000 # mprotect flag: extend change to end of growsup vma 

MAP_SHARED          =0x01       # Share changes 
MAP_PRIVATE         =0x02       # Changes are private 
MAP_TYPE            =0x0f       # Mask for type of mapping 
MAP_FIXED           =0x10       # Interpret addr exactly 
MAP_ANONYMOUS       =0x20       # don't use a file 
MAP_DENYWRITE       =0x0800
MAP_EXECUTABLE      =0x1000

MS_ASYNC            =1          # sync memory asynchronously 
MS_INVALIDATE       =2          # invalidate the caches 
MS_SYNC             =4          # synchronous memory sync 

MADV_NORMAL         =0          # no further special treatment 
MADV_RANDOM         =1          # expect random page references 
MADV_SEQUENTIAL     =2          # expect sequential page references 
MADV_WILLNEED       =3          # will need these pages 
MADV_DONTNEED       =4          # don't need these pages 

MADV_REMOVE         =9          # remove these pages & resources 
MADV_DONTFORK       =10         # don't inherit across fork 
MADV_DOFORK         =11         # do inherit across fork 
MADV_HWPOISON       =100        # poison a page for testing 
MADV_SOFT_OFFLINE   =101        # soft offline page for testing 

MADV_MERGEABLE      =12         # KSM may merge identical pages 
MADV_UNMERGEABLE    =13         # KSM may not merge identical pages 

MADV_HUGEPAGE       =14         # Worth backing with hugepages 
MADV_NOHUGEPAGE     =15         # Not worth backing with hugepages 


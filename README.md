# Health-check

The health-check tool monitors processes in various ways to help identify
areas where it is consuming too many resources.  One can trace one or more
processes (including all their threads and child processes too) for a full
story of system activity.

## Health-check can monitor:
* CPU usage
* Kernel wake-up events
* File I/O activity (open,read,write,close)
* System call activity
* Excessive polling of timeout wait blocked system calls (such as poll, select, etc)
* Memory usage (such as heap and stack growth)
* Network connections (to spot rogue internet activity)
* Network usage (send/receive) accounting
*  Syncing data via fsync, fdatasync, syncfs and sync system calls
* Page fault accounting

..and can also dump the stats into a JSON formatted file for later analysis.

## Health-check command line options:

* -b brief (simple mode) output
* -c trace all child processes
* -d duration of the test in seconds
* -f follow fork/vfork/clone system calls
* -h show help information
* -p comma separated list of process IDs or process names to trace
* -m maximum number of system calls to trace before stopping (default 1 million)
* -o JSON output file
* -r resolve IP addresses (may take a while to do)
* -u run a command to trace as a specified user
* -v verbose output
* -w monitor wakelock counts (lightweight fnotify monitoring)
* -W monitor wakelock usage (expensive syscall inspection overhead)

Health check can be used to either attach to one or more existing running
processes using the -p option, or one can specify a command to be run and
it will executed and traced. The latter option also allows one to specify
the user id to run the command under.

## Example Output:
```
sudo health-check -p camera-app -c -d 60
CPU usage:
  PID  Process                USR%   SYS%  TOTAL%
  3585 camera-app            18.97  16.93  35.90 (medium load)

Wakeups:
  PID  Process               Wake/Sec Kernel Functions
  3608 camera-app               13.62 (add_timer, OSTimerCallbackWrapper) (high)
  3589 camera-app                3.17 (hrtimer_start_range_ns, hrtimer_wakeup) (moderate)
  3608 camera-app                0.37 (schedule_timeout_uninterruptible, process_timeout) (low)
  3585 camera-app                0.28 (hrtimer_start_range_ns, hrtimer_wakeup) (low)
 Total                          17.43

Context Switches:
  PID  Process                Voluntary   Involuntary     Total
                             Ctxt Sw/Sec  Ctxt Sw/Sec  Ctxt Sw/Sec
  3608 camera-app                1712.07       178.02      1890.09 (high)
  3585 camera-app                1498.67        10.72      1509.39 (high)
  3606 camera-app                 143.25        18.55       161.80 (quite high)
  3667 camera-app                 142.33        18.68       161.02 (quite high)
  3605 camera-app                 141.25        18.32       159.57 (quite high)
  3628 camera-app                 128.12        16.50       144.62 (quite high)
  3587 camera-app                 108.98         0.05       109.03 (quite high)
  3661 camera-app                   6.48        46.30        52.78 (moderate)
  3607 camera-app                  27.75         1.65        29.40 (moderate)
  3589 camera-app                  20.48         0.02        20.50 (moderate)
  3592 camera-app                   0.00         0.00         0.00 (idle)
  3590 camera-app                   0.00         0.00         0.00 (idle)
  3588 camera-app                   0.00         0.00         0.00 (idle)
 Total                           4238.19       308.80      3929.39

File I/O operations:
  PID  Process               Count  Op  Filename
  3585 camera-app               43    O /home/phablet/.config/user-dirs.dirs
  3585 camera-app               41   CW /home/phablet/Pictures/image20130905_0004.jpg
  3585 camera-app               22    W /tmp/Camera App.nS3585
  3585 camera-app               21    C /home/phablet/.config/user-dirs.dirs
  3585 camera-app               21    R /home/phablet/.config/user-dirs.dirs
  3585 camera-app                1  OCR /home/phablet/.config/user-dirs.dirs
 Total                         149

File I/O Operations per second:
  PID  Process                 Open   Close    Read   Write
  3585 camera-app              0.73    1.05    0.37    1.05

System calls traced:
  PID  Process              Syscall               Count    Rate/Sec
  3608 camera-app           ioctl                 25035     417.2470
  3585 camera-app           futex                 13713     228.5484
  3608 camera-app           futex                 12382     206.3652
  3585 camera-app           clock_gettime          9065     151.0823
  3585 camera-app           poll                   6098     101.6326
  3585 camera-app           read                   5929      98.8160
  3608 camera-app           clock_gettime          2949      49.1497
  3608 camera-app           mmap2                  2389      39.8164
  3628 camera-app           ioctl                  1532      25.5332
  3608 camera-app           poll                   1421      23.6832
  3608 camera-app           munmap                 1022      17.0332
  3587 camera-app           epoll_wait              927      15.4499
  3587 camera-app           recvfrom                926      15.4332
  3585 camera-app           stat64                  682      11.3666
  3628 camera-app           getpriority             409       6.8166
  3585 camera-app           recvmsg                 396       6.6000
  3585 camera-app           gettimeofday            319       5.3166
  3628 camera-app           munmap                  279       4.6500
  3585 camera-app           sendmsg                 242       4.0333
  3589 camera-app           futex                   231       3.8500
  3589 camera-app           nanosleep               190       3.1666
  3628 camera-app           clock_gettime           155       2.5833
  3585 camera-app           ioctl                    96       1.6000
  3585 camera-app           fstat64                  88       1.4667
  3628 camera-app           futex                    84       1.4000
  3608 camera-app           read                     82       1.3667
  3608 camera-app           open                     44       0.7333
  3661 camera-app           futex                    30       0.5000
  3585 camera-app           munmap                   24       0.4000
  3661 camera-app           poll                     23       0.3833
  3661 camera-app           read                     23       0.3833
  3661 camera-app           clock_gettime            23       0.3833
  3585 camera-app           fcntl64                  22       0.3667
  3608 camera-app           writev                   22       0.3667
  3585 camera-app           access                   22       0.3667
  3585 camera-app           open                     22       0.3667
  3661 camera-app           mmap2                    22       0.3667
  3585 camera-app           fork                     21       0.3500
  3587 camera-app           mprotect                 18       0.3000
  3587 camera-app           futex                    12       0.2000
  3628 camera-app           dup                      10       0.1667
  3628 camera-app           _llseek                   5       0.0833
  3628 camera-app           fcntl64                   5       0.0833
  3628 camera-app           stat64                    5       0.0833
  3628 camera-app           mmap2                     5       0.0833
  3628 camera-app           fstat64                   5       0.0833
  3628 camera-app           lstat64                   5       0.0833
  3628 camera-app           rename                    5       0.0833
  3628 camera-app           open                      5       0.0833
  3628 camera-app           unlink                    5       0.0833
  3661 camera-app           munmap                    1       0.0167
  3661 camera-app           restart_syscall           1       0.0167
  3592 camera-app           restart_syscall           1       0.0167
  3585 camera-app           restart_syscall           1       0.0167
 Total                                            87028    1450.4563

Top polling system calls:
  PID  Process              Syscall             Rate/Sec   Infinite   Zero     Minimum    Maximum    Average
                                                           Timeouts Timeouts   Timeout    Timeout    Timeout
  3585 camera-app           poll                  101.6326     2974     1853   0.0 sec   25.0 sec  788.5 msec
  3608 camera-app           poll                   23.6832        0     1421   0.0 sec    0.0 sec    0.0 sec
  3587 camera-app           epoll_wait             15.4499        0        0   5.0 sec    5.0 sec    5.0 sec
  3589 camera-app           nanosleep               3.1666        0        0 900.0 usec 900.0 usec 900.0 usec
  3661 camera-app           poll                    0.3833       22        1   0.0 sec    0.0 sec    0.0 sec
 Total                                            144.3156     2996     3275

Distribution of poll timeout times:
                                                            10.0  100.0    1.0   10.0  100.0    1.0   10.0  100.0
                                                    up to    to     to     to     to     to     to     to  or more
                                              Zero    9.9   99.9  999.9    9.9   99.9  999.9    9.9   99.9        Infinite
  PID  Process              Syscall            sec   usec   usec   usec   msec   msec   msec    sec    sec    sec   Wait
  3585 camera-app           poll              1853     -      -      -      29    178    864     24    176     -    2974
  3608 camera-app           poll              1421     -      -      -      -      -      -      -      -      -       0
  3587 camera-app           epoll_wait           0     -      -      -      -      -      -     927     -      -       0
  3589 camera-app           nanosleep            0     -      -     190     -      -      -      -      -      -       0
  3661 camera-app           poll                 1     -      -      -      -      -      -      -      -      -      22

Polling system call analysis:
 camera-app (3585), poll:
          2 immediate timed out calls with zero timeout (non-blocking peeks)
 camera-app (3608), poll:
       1339 immediate timed out calls with zero timeout (non-blocking peeks)
       1297 repeated immediate timed out polled calls with zero timeouts (heavy polling peeks)
Polling system call analysis:
 camera-app (3585), poll:
          2 immediate timed out calls with zero timeout (non-blocking peeks)
 camera-app (3608), poll:
       1339 immediate timed out calls with zero timeout (non-blocking peeks)
       1297 repeated immediate timed out polled calls with zero timeouts (heavy polling peeks)

Per Process Memory (K):
  PID  Process              Type        Size       RSS       PSS
  3585 camera-app           Stack        136        64        64
  3585 camera-app           Heap      130440     11476     11476
  3585 camera-app           Mapped    131308     44688     24811

Change in memory (K/second):
  PID  Process              Type        Size       RSS       PSS
  3585 camera-app           Heap        0.00      1.80      1.80 (growing)
  3585 camera-app           Mapped      0.00      0.40      0.37 (growing slowly)

Open Network Connections:
 None.
```

## Another example:

```
sudo health-check -u king dd if=/dev/zero of=test bs=1k count=100000
100000+0 records in
100000+0 records out
102400000 bytes (102 MB) copied, 7.85756 s, 13.0 MB/s
CPU usage (in terms of 1 CPU):
  PID  Process                USR%   SYS% TOTAL%   Duration
 22572 dd                     3.17  56.53  59.69       7.89  (high load)

Page Faults:
  PID  Process                 Minor/sec    Major/sec    Total/sec
 22572 dd                          32.83         0.00        32.83

Wakeups:
 No wakeups detected.
```


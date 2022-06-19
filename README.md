coffeesprout.ks-oemdrv
=========

So I actually bothered to read the documentation that Redhat still provides without a login and found that there is a kickstart option where you provide the ks.cfg to a local drive with the label OEMDRV; This local drive can also be an iso making this relatively painless.
After running this role you will have a tiny iso with a templated (yours or mine) ks.cfg and if you provide this iso together with one of the official install media you will have a hands free install.

Yes, no idea why after learning this people insist on hacking their ks files into the official iso's either.

Requirements
------------

None, this role will install genisoimage which is required to create iso files

Role Variables
--------------

Not that many, unless you define a lot in your template :-)

    ks_oemdrv_name: "custom"

This gets appended to the name of the iso, in case you want more than one.

    ks_oemdrv_dest: "{{ iso_workdir }}/OEMDRV-{{ ks_oemdrv_name }}.iso"

Where you need the iso to be installed. For example I favor the /var/lib/vz/template/iso folder on Proxmox

    ks_oemdrv_ks_dest: "{{ iso_workdir }}/ks.cfg"

Where to put the templated kickstart away

    iso_workdir: "{{ playbook_dir }}/files/isos"

In case you have no strong preference, you can run this locally and have the files show up in your playbook dir

    ks_oemdrv_template: ks.basic.j2

Not currently included because basic kickstarts are hard to find

    ks_oemdrv_packages:
    - genisoimage

Most linux systems provide the tooling by this name.


Example Playbook
----------------

Taken from the tests folder:

    - hosts: proxmox-machine
      pre_tasks:
      - name: borrow a simple kickstart from our good friend Geerlingguy <3
        get_url:
          url: https://raw.githubusercontent.com/geerlingguy/packer-boxes/master/rockylinux8/http/ks.cfg
          dest: "/tmp/geerlingguy.ks.j2"
        delegate_to: localhost
      roles:
      - role: coffeesprout.ks-oemdrv
        iso_workdir: "/var/lib/vz/template/iso/"
        ks_oemdrv_template: "/tmp/geerlingguy.ks.j2"    

License
-------

BSD

Author Information
------------------

Just reach out on Github

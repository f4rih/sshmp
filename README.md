# Master password for openSSH service
## SSHMP
Add 2-Step verification password for your openSSH service.

- Prevent brute force attacks
- SHA256 Encrypted password
- Logging system
- Support Linux, Mac OSX
- Easy installation script

## Requirements
- python 3.5.x or higher
- make sure openSSH is already installed

## Preview
![sshmp-preview](https://github.com/0x0ptim0us/images/raw/master/sshmp-2.png)

## Installation
```sh
$ git clone https://github.com/0x0ptim0us/sshmp.git
$ cd sshmp
$ python3 sshmp_mgr.py --install
```

![SSHMP](https://github.com/0x0ptim0us/images/raw/master/Screen%20Shot%202019-05-30%20at%209.02.42%20PM.png)

Run `sshmp_mgr.py` with `--help` switch for more info.
> Install sshmp service separately for each user, so we don't need root privilege
>
> if you want install sshmp for root too, then run installer as root via sudo command



## Uninstall
For uninstall just run:

```sh
$ python3 sshmp_mgr.py --uninstall
or
$ sshmpmgr --uninstall
```

## Change password
For updating password you need old password :

```sh
$ python3 sshmp_mgr.py --manage
or
$ sshmpmgr --manage
```

## Meta
Fardin Allahverdinazhand - [@0x0ptim0us](https://twitter.com/0x0ptim0us) - [0x0ptim0us@gmail.com](mailto:) Distributed under the MIT license. see [LICENSE](https://github.com/0x0ptim0us/sshmp/blob/master/LICENSE) for more information.

[https://github.com/0x0ptim0us/sshmp](https://github.com/0x0ptim0us/sshmp)



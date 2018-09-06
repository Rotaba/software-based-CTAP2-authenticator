The code was tested with Python 3.5+ using Debain 9/Ubuntu 16 desktop environment.
It uses the Yubiekey FIDO2 python libs https://github.com/Yubico/python-fido2
I've added the lib locally to be able to peek under it's hood; but you can also use the official one through pip3 install fido2

# v2f.py is a virtual FIDO2 device

Clone this source code repository

```bash
git clone https://projects.cispa.saarland/roman.tabachnikov/FIDO2_Token_emulator/
```
You have to tweak the permissions of some files before running v2f, which needs uhid and
hidraw.  An easy way to do that is just making `/dev/uhid` and `/dev/hidraw*`
device nodes universally read-writable - there's a simple .sh to help you

```bash
sudo bash hack-linux-for-v2f
```


Run v2f (default: store everything under ~/.v2f directory)

```bash
python3 v2f.py
```

Run v2f with a specified device information directory

```bash
python3 v2f.py ~/.my-v2f-info-dir
```
This
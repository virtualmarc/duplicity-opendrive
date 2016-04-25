# OpenDrive Duplicity Backend

This is a duplicity backend for the cloud storage service OpenDrive.

# Setup

```
# Linux
cp opendrivebackend.py /usr/lib/python2.7/dist-packages/duplicity/backends/

# Mac OS X
cp opendrivebackend.py /Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/duplicity/backends
```

# Usage
```
duplicity source_path opendrive://email@addr.tld:password@od/directoryid
```

# s3v2tov4-proxy

AWS S3 Signature V2 to Signature V4 proxy server released under Apache License v2.0.

## Overview

Legacy clients using Signature V2 mechanism for S3 API authentication should
use this proxy to talk to any AWS S3 Signature V4 only S3 compatible server.

Minio here is one such example which only supports AWS S3 Signature V4, you can
also use this proxy in front of new S3 regions which do not support legacy
Signature V2.

## Install from Source

If you do not have a working Golang environment, please follow [How to install Golang](https://docs.minio.io/docs/how-to-install-golang).


```sh

$ go get github.com/minio/s3v2tov4-proxy

```

## Run proxy

```sh

$ s3v2tov4-proxy -l :8000 -f http://localhost:9000 -access <ACCESSKEY> -secret <SECRETKEY>

```

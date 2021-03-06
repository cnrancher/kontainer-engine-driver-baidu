Kontainer Engine Baidu Driver
===============================

This repo contains the Baidu CCE(Baidu Cloud Container Engine) driver for the rancher server.

## Building

`make`

Will output driver binaries into the `dist` directory, these can be imported 
directly into Rancher and used as cluster drivers.  They must be distributed 
via URLs that your Rancher instance can establish a connection to and download 
the driver binaries.  For example, this driver is distributed via a GitHub 
release and can be downloaded from one of those URLs directly.


## Running

1. Go to the `Cluster Drivers` management screen in Rancher and click `Add Cluster Driver`.
2. Enter Download URL `https://cluster-driver.oss-cn-shenzhen.aliyuncs.com/baidu/linux/kontainer-engine-driver-baidu-linux`
3. Enter the Custom UI URL with value `https://cluster-driver.oss-cn-shenzhen.aliyuncs.com/baidu/ui/component.js`.
4. Add Whitelist Domains with value `*.aliyuncs.com` and `*.baidubce.com`.
5. Click `Create`, and wait for driver status to be `Active`.
6. Baidu Driver will be available to use on the `Add Cluster` screen.

## License
Copyright (c) 2018 [Rancher Labs, Inc.](http://rancher.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

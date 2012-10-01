GmoCloudAPI
===========

Java client for GMO Cloud API. http://www.gmocloud.com/service/api.html

Usage
-------------
```java
GmoCloud gmoCloud = new GmoCloud(ACCESS_KEY_ID, SECRET_KEY, "jp002");
String json = gmoCloud.listNodesJson();
gmoCloud.shutdownNodeJson("abcde123456789");
gmoCloud.resizeNodeJson("abcde123456789", null, null, 12, 64 * 1024); // Change instance to 12cpu and 64GB memory
gmoCloud.startupNodeJson("abcde123456789", null);
```

Dependency
-------------
* Apache HttpClient 4.x
* Apache Commons Codec
* Apache Commons Logging

License
-------------
Apache License 2.0

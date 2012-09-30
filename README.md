GmoCloudAPI
===========

Java client for GMO Cloud API. http://www.gmocloud.com/service/api.html

Usage
-------------
```java
GmoCloud gmoCloud = new GmoCloud(ACCESS_KEY_ID, SECRET_KEY, "jp002");
String json = gmoCloud.listNodesJson();
```

Dependency
-------------
* Apache HttpClient 4.x
* Apache Commons Codec
* Apache Commons Logging

License
-------------
New BSD License

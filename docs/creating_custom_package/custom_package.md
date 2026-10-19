
Create sub folder

Go mod init [package name]

import root project 

Normal: \
```go get github.com/markusnieminen1/goauth```

Custom version (e.g. to a branch that is not main): \
```go get github.com/markusnieminen1/goauth@v0.0.2```

In case of any errors with the version: \
```GOPROXY=direct GONOSUMDB=github.com/markusnieminen1/goauth go get github.com/markusnieminen1/goauth@v0.0.2```
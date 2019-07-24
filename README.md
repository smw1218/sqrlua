# sqrlua #
This package implements a SQRL user agent that can be used for testing. It does not implement
a SQRL Client which performs identity management. This package uses fake generated keys to
perform tests and does not attempt to keep any of the secrets for more permanent use.

Running the tests:

    go test .

Since these tests are targeted toward stateful SQRL servers (and may not be stable), it's 
useful to disable go's test cache:

    go test -count=1 .

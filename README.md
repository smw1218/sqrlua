# sqrlua #
This package implements a SQRL user agent that can be used for testing. It does not implement
a SQRL Client which performs identity management. This package uses fake generated keys to
perform tests and does not attempt to keep any of the secrets for more permanent use.

Since these tests are targeted toward stateful SQRL servers (and tests may not be stable), it's 
useful to disable go's test cache:

    go test -count=1 .

By default, the test expect the SSP server to be running on http://localhost:8000/.
This can be overridden with some command line options. If the cli.sqrl endpoint is
hosted at https://api.example.com/sqrl/cli.sqrl then this command would test that server:

    go test -count=1 -scheme https -host api.example.com -path /sqrl .

The default for path is the root (/) so path may be omitted if the SQRL API is served from
the root.

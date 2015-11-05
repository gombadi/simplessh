# simplessh
Simple SSH server that logs user/passwords used to try and connect. All connections are denied.

## Install

    $ go get github.com/gombadi/simplessh
Dependencies are handled by the Go vendor directory.
Note: This means the codebase requires Go 1.5 or higher and use of GO15VENDOREXPERIMENT=1



## Usage

Think Honeypot. You can never actually connect to this server but if anyone does it will display the SSH Keys and/or passwords used.


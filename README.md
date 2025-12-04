# simplessh
Simple SSH server that logs user/passwords used during connections. **All connections are denied.**

## Install

    $ go get github.com/gombadi/simplessh



## Usage

Think Honeypot. You can never actually connect to this server but if anyone does it will display the SSH Keys/passwords used during the attempt.


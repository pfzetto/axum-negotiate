
This Library allows using [Kerberos SPNEGO HTTP-Authentication](https://www.rfc-editor.org/rfc/rfc4559) with [axum](https://github.com/tokio-rs/axum). 

# Usage
The `NegotiateAuthLayer` forces every request to be authenticated.
Handlers can use the `Upn` extractor to get the user principal name.

# Examples
Take a look at the `examples` folder for examples.

# Limitations
Currently this library only supports two-pass SPNEGO as it doesn't require state across multiple requests on the server.

# Older Versions
All versions on [crates.io](https://crates.io) are available as git tags.
Additional all minor versions have their own branch (format `vX.Y` where `X` is the major and `Y` is the minor version) where bug fixes are implemented.
Examples for each version can be found there in the previously mentioned `examples` folder.

# Contributing
I'm happy about any contribution in any form.
Feel free to submit feature requests and bug reports using a GitHub Issue.
PR's are also appreciated.

# License
This Library is licensed under [LGPLv3](https://www.gnu.org/licenses/lgpl-3.0.en.html).


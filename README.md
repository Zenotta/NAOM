# Notarised Append Only Memory (NAOM)

The NAOM repo contains all the code needed to set up and interact with a local instance of the Zenotta blockchain. 
Other language options can be found here:

- [中文](https://gitlab.com/zenotta/naom/-/blob/main/README.zhs.md)
- [Deutsch](https://gitlab.com/zenotta/naom/-/blob/main/README.de.md)
- [Française](https://gitlab.com/zenotta/naom/-/blob/main/README.fr.md)
- [Afrikaans](https://gitlab.com/zenotta/naom/-/blob/main/README.af.md)

If you'd like to help with translations, or spot a mistake, feel free to open a new merge request.

..

## Development

For development NAOM requires the following installations:

- [Rust](https://www.rust-lang.org/tools/install)

You can clone this repo and run the tests as follows:

```
cargo build
cargo test
```

Before pushing any code up to this repo it's advised that you run `make` from root to format and lint the code for the CI.

..

## Use

Running `cargo run --bin main` will currently list all assets on the local instance. NAOM is not generally intended to be
used directly, and is instead intended to be used from other programs that require access to the blockchain data 
structure.
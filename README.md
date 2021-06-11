# Hyper-tls-hack.

An implementation of `hyper`'s `AddrIncoming` that generates `TlsStream`s.

## THIS REPOSITORY HAS BEEN ARCHIVED.

You can find an alternative that works with newer hyper versions here: [tls-listener](https://github.com/tmccombs/tls-listener).

## Location
This crate is not published on crates.io, because I am
not sure I will be able to maintain it at this time.

So to use this crate, add the following to you Cargo.toml:

```
[dependencies]
hyper-tls-hack = { git = "https://github.com/miquels/hyper-tls-hack" }
```

## Documentation

You can read it locally by cloning this github repo, then running:
```
cargo doc --lib --no-deps --open
```

Or [read it online](https://miquels.github.io/hyper-tls-hack/hyper_tls_hack/).

## The certificate + key file
Right now the only certificate file format that is supported
is the PKCS#12 format, for which usually the `.pfx` file
extention is used.

If all you have is a `.crt` and `.key` file, you can generate
a `.p12` file using the following command:
```
openssl pkcs12 -export -out cert.p12 -inkey cert.key -in cert.crt [-certfile chain.crt]
```
The `chain.crt` file is optional, only needed if you need to add
more than one certificate to the `.p12` file.


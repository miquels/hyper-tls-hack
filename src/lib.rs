//! An implementation of `hyper`'s `AddrIncoming` that generates `TlsStream`s.
//!
//! Right now the server part of `hyper` 0.12 does not support `TLS`. There
//! is not a simple and correct implementation available that just
//! "plugs in" to `hyper`.
//!
//! The latest `tokio_tls` does have an example how to use it with `hyper`,
//! but then you miss out on an important part of `hyper`, implemented in
//! `hyper::server::conn::AddrIncoming`, that retries when `accept()`
//! fails (which it intermittently can).
//! Otherwise your server might unexpectedly die at an inconvenient time.
//!
//! So, this crate is just a hack of `hyper`'s `AddrIncoming` that
//! supports `tokio_tls`.
//!
//! So why is it called `hyper-tls-hack`? Well for 3 reasons actually:
//! - this is my first crate
//! - I might be using unstable interfaces of `hyper` and it might stop
//!   working after the next `hyper` minor release
//! - I assume that soon there will be an "official" way to do this.
//!
//! Example server:
//!
//! ```no_run
//!
//! extern crate hyper;
//! extern crate hyper_tls_hack;
//!
//! use std::sync::Arc;
//!
//! use hyper::{Body, Response, Server};
//! use hyper::rt::Future;
//! use hyper::service::service_fn_ok;
//!
//! static TEXT: &str = "Hello, HTTPS World!\n";
//!
//! fn main() {
//!
//!     let addr = ([0, 0, 0, 0], 8445).into();
//!     let new_svc = || { service_fn_ok(|_req|{ Response::new(Body::from(TEXT)) }) };
//!
//!     let acceptor = Arc::new(hyper_tls_hack::acceptor_from_p12_file("cert.p12", "").unwrap());
//!     let mut ai = hyper_tls_hack::AddrIncoming::new(&addr, acceptor, None).expect("addrincoming error");
//!     ai.set_nodelay(true);
//!
//!     let server = Server::builder(ai)
//!			.serve(new_svc)
//!			.map_err(|e| eprintln!("server error: {}", e));
//!
//!     println!("Listening HTTPS on: {}", addr);
//!
//!     hyper::rt::run(server);
//! }
//! ```
#[macro_use]
extern crate log;
extern crate futures;
extern crate tokio_reactor;
extern crate tokio_tls;
extern crate tokio_tcp;
extern crate tokio_io;
extern crate tokio_timer;
extern crate native_tls;
extern crate bytes;

use std::fmt;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::time::{Duration, Instant};
use std::io::{self, Error, ErrorKind, Read};
use std::path::Path;
use std::sync::Arc;

use futures::prelude::*;
use futures::stream::{Stream, FuturesUnordered};
use tokio_reactor::Handle;
use tokio_tcp::{TcpStream, TcpListener};
use tokio_timer::Delay;
use tokio_tls::{TlsAcceptor,TlsStream};

/// A stream of TLS connections from binding to an address.
///
/// You pass this to `hyper::server::Server::builder()`. Note that
/// if you pass a custom `AddrIncoming` to `Server::builder`, the
/// `.tcp_keepalive()` and `.tcp_nodelay()` helpers from the builder
/// are not available anymore on the builder.
///
/// You can use them directly on the `AddrIncoming` though,
/// as `set_keepalive` and `set_nodelay`.
///
/// ```no_run
/// let mut ai = hyper_tls_hack::AddrIncoming::new(&addr, acceptor, None)?;
/// ai.set_nodelay(true)
///
/// let server = Server::builder(ai).....
/// ```
///
#[must_use = "streams do nothing unless polled"]
pub struct AddrIncoming {
    addr: SocketAddr,
    listener: TcpListener,
    sleep_on_errors: bool,
    tcp_keepalive_timeout: Option<Duration>,
    tcp_nodelay: bool,
    timeout: Option<Delay>,
    tls_acceptor: Arc<TlsAcceptor>,
    tls_queue: FuturesUnordered<tokio_tls::Accept<TcpStream>>,
}

impl AddrIncoming {

    /// Build a new `AddrIncoming` that that generates `TlsStream`s
    /// instead of `TcpStream`s.
    pub fn new(addr: &SocketAddr, tls_acceptor: Arc<TlsAcceptor>, handle: Option<&Handle>) -> io::Result<AddrIncoming> {
        let listener = if let Some(handle) = handle {
            let std_listener = StdTcpListener::bind(addr)?;
            TcpListener::from_std(std_listener, handle)?
        } else {
            TcpListener::bind(addr)?
        };

        let addr = listener.local_addr()?;

        Ok(AddrIncoming {
            addr: addr,
            listener: listener,
            sleep_on_errors: true,
            tcp_keepalive_timeout: None,
            tcp_nodelay: false,
            timeout: None,
            tls_acceptor: tls_acceptor,
            tls_queue: FuturesUnordered::new(),
        })
    }

    /// Create a new `AddrIncoming` from the standard library's TCP listener.
    ///
    /// This method can be used when the `AddrIncoming::new` method isn't
    /// sufficient, usually because some more configuration of the tcp socket
    /// is needed before the calls to bind and listen.
    ///
    /// This API is typically paired with the `net2` crate and the `TcpBuilder`
    /// type to build up and customize a `AddrIncoming` before it's used with
    /// `hyper::server::Server`. This allows configuration of options like
    /// SO_REUSEPORT, IPV6_V6ONLY, listen backlog length, etc.
    pub fn from_std_listener(std_listener: StdTcpListener, tls_acceptor: Arc<TlsAcceptor>, handle: Option<&Handle>) -> io::Result<AddrIncoming> {
        let listener = if let Some(handle) = handle {
            TcpListener::from_std(std_listener, handle)?
        } else {
            TcpListener::from_std(std_listener, &Handle::default())?
        };

        let addr = listener.local_addr()?;

        Ok(AddrIncoming {
            addr: addr,
            listener: listener,
            sleep_on_errors: true,
            tcp_keepalive_timeout: None,
            tcp_nodelay: false,
            timeout: None,
            tls_acceptor: tls_acceptor,
            tls_queue: FuturesUnordered::new(),
        })
    }

    /// Get the local address bound to this listener.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Set whether TCP keepalive messages are enabled on accepted connections.
    ///
    /// If `None` is specified, keepalive is disabled, otherwise the duration
    /// specified will be the time to remain idle before sending TCP keepalive
    /// probes.
    pub fn set_keepalive(&mut self, keepalive: Option<Duration>) -> &mut Self {
        self.tcp_keepalive_timeout = keepalive;
        self
    }

    /// Set the value of `TCP_NODELAY` option for accepted connections.
    pub fn set_nodelay(&mut self, enabled: bool) -> &mut Self {
        self.tcp_nodelay = enabled;
        self
    }

    /// Set whether to sleep on accept errors.
    ///
    /// Default is `true`.
    pub fn set_sleep_on_errors(&mut self, val: bool) {
        self.sleep_on_errors = val;
    }
}

impl Stream for AddrIncoming {
    type Item = TlsStream<TcpStream>;
    type Error = ::std::io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {

        // first see if any TlsStreams are ready.
        loop {
            match self.tls_queue.poll() {
                Ok(Async::Ready(Some(val))) => return Ok(Async::Ready(Some(val))),
                Ok(Async::Ready(None)) => break,
                Ok(Async::NotReady) => break,
                Err(err) => {
                    // handshake error, ignore, but keep polling.
                    error!("tls acceptor error: {}", err);
                }
            }
        }

        // Check if a previous timeout is active that was set by IO errors.
        if let Some(ref mut to) = self.timeout {
            match to.poll() {
                Ok(Async::Ready(())) => {}
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(err) => {
                    error!("sleep timer error: {}", err);
                }
            }
        }
        self.timeout = None;

        // Check the listening socket for incoming TCP connections.
        loop {
            match self.listener.poll_accept() {
                Ok(Async::Ready((socket, _addr))) => {
                    if let Some(dur) = self.tcp_keepalive_timeout {
                        if let Err(e) = socket.set_keepalive(Some(dur)) {
                            trace!("error trying to set TCP keepalive: {}", e);
                        }
                    }
                    if let Err(e) = socket.set_nodelay(self.tcp_nodelay) {
                        trace!("error trying to set TCP nodelay: {}", e);
                    }
                    // socket is ready, start TLS handshake.
                    let future = self.tls_acceptor.accept(socket);
                    self.tls_queue.push(future);
                    continue;
                },
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => {
                    if self.sleep_on_errors {
                        // Connection errors can be ignored directly, continue by
                        // accepting the next request.
                        if is_connection_error(&e) {
                            debug!("accepted connection already errored: {}", e);
                            continue;
                        }
                        // Sleep 1s.
                        let delay = Instant::now() + Duration::from_secs(1);
                        let mut timeout = Delay::new(delay);

                        match timeout.poll() {
                            Ok(Async::Ready(())) => {
                                // Wow, it's been a second already? Ok then...
                                error!("accept error: {}", e);
                                continue
                            },
                            Ok(Async::NotReady) => {
                                error!("accept error: {}", e);
                                self.timeout = Some(timeout);
                                return Ok(Async::NotReady);
                            },
                            Err(timer_err) => {
                                error!("couldn't sleep on error, timer error: {}", timer_err);
                                return Err(e);
                            }
                        }
                    } else {
                        return Err(e);
                    }
                },
            }
        }
    }
}

/// This function defines errors that are per-connection. Which basically
/// means that if we get this error from `accept()` system call it means
/// next connection might be ready to be accepted.
///
/// All other errors will incur a timeout before next `accept()` is performed.
/// The timeout is useful to handle resource exhaustion errors like ENFILE
/// and EMFILE. Otherwise, could enter into tight loop.
fn is_connection_error(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ConnectionRefused ||
    e.kind() == io::ErrorKind::ConnectionAborted ||
    e.kind() == io::ErrorKind::ConnectionReset
}

impl fmt::Debug for AddrIncoming {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AddrIncoming")
            .field("addr", &self.addr)
            .field("sleep_on_errors", &self.sleep_on_errors)
            .field("tcp_keepalive_timeout", &self.tcp_keepalive_timeout)
            .field("tcp_nodelay", &self.tcp_nodelay)
            .finish()
    }
}

/// Simple utility function that reads a certificate file, and returns
/// a TlsAcceptor. Useful for examples in documentation :)
///
/// If you have a cert in the form of a PEM .key and .crt file, you can
/// generate a .p12 file using openssl:
/// ```
///  openssl pkcs12 -export -out cert.p12 -inkey cert.key -in chained-cert.crt
/// ```
pub fn acceptor_from_p12_file(path: impl AsRef<Path>, password: &str) -> io::Result<TlsAcceptor> {
    let mut file = std::fs::File::open(path)?;
    let mut der = vec![];
    file.read_to_end(&mut der)?;
    let cert = native_tls::Identity::from_pkcs12(&der, password).map_err(|e| Error::new(ErrorKind::Other, e))?;
    let tls_cx = native_tls::TlsAcceptor::builder(cert).build().map_err(|e| Error::new(ErrorKind::Other, e))?;
    Ok(TlsAcceptor::from(tls_cx))
}


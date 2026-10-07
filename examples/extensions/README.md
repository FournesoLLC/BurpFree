# BurpFree extension examples

These extensions ship with BurpFree so new contributors have a working
reference. They are plain Rust modules that implement
`burpfree_extensions::Extension`.

* `host_tagger.rs` — attaches a tag with the observed host to every
  recorded transaction.
* `strip_powered_by.rs` — removes the `X-Powered-By` response header
  from inbound responses.
* `header_injector.rs` — prepends a custom `X-Audit-Session` header to
  every outbound request.

To ship your own extension, create a new crate that depends on
`burpfree_extensions`, implement the trait, and register it with the
host application (`burpfree-tauri` or `burpfree-cli`). A WASM loader
is on the roadmap.

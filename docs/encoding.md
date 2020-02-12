# Encoding

All messages exchanged by different components in Oasis Core are encoded using
[canonical CBOR as defined by RFC 7049](https://tools.ietf.org/html/rfc7049).

When describing different messages in the documentation, we use Go structs with
field annotations that specify how different fields translate to their encoded
form.

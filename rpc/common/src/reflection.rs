/// Descriptor of an RPC API method.
pub struct ApiMethodDescriptor {
    /// Method name.
    pub name: String,
    /// Whether the method call requires the client to be attested and therefore
    /// the method handler can assume client's MRENCLAVE is available.
    pub client_attestation_required: bool,
}

extern crate ekiden_edl;
extern crate ekiden_tools;

fn main() {
    ekiden_tools::build_trusted(ekiden_edl::edl());

    // Generate key manager contract identity. This determines what key manager the
    // contract will be using.
    ekiden_tools::generate_mod("src/generated", &[]);
    ekiden_tools::generate_contract_identity(
        "src/generated/key-manager.identity",
        "../../target/contract/ekiden-key-manager.so",
    );
}

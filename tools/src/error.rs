use error_chain::*;

error_chain! {
    foreign_links {
        Fmt(::std::fmt::Error);
        Io(::std::io::Error);
        TomlSerialize(super::toml::ser::Error);
        TomlDeserialize(super::toml::de::Error);
        Regex(super::regex::Error);
    }
}

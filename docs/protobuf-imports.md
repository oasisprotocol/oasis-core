# How to make imports in protobuf files work?

If you need to `import` some messages from a `.proto` file in some other
Ekiden crate in this repository, it's not obvious at first glance why it
doesn't work simply by adding the `import` directive to the `.proto` file
like this:

```protobuf
import "roothash/api/src/roothash.proto";
```

then using the imported messages as, for example, `roothash.Commitment`, etc.

You may get a similar error message to this one:

    error[E0433]: failed to resolve. Could not find `roothash` in `super`
       --> compute/api/src/generated/computation_group.rs:367:53
        |
    367 |     pub commit: ::protobuf::SingularPtrField<super::roothash::Commitment>,
        |                                                     ^^^^^^^^^ Could not find `roothash` in `super`

For this to work, you need to add a few additional things.

In the following examples, we will walk through everything that's needed to
be able to import messages from the `roothash` API into the `compute` API.


First, you need to add a dependency for the API you're trying to import into
the API where you want to use the imports.

To do this, you need to modify the API's `Cargo.toml` file like this:

```diff
diff --git a/compute/api/Cargo.toml b/compute/api/Cargo.toml
index 4937cf6..8efd2a6 100644
--- a/compute/api/Cargo.toml
+++ b/compute/api/Cargo.toml
@@ -9,6 +9,7 @@ build = "build.rs"

 [dependencies]
 ekiden-common-api = { path = "../../common/api", version = "0.2.0-alpha" }
+ekiden-roothash-api = { path = "../../roothash/api", version = "0.2.0-alpha" }
 protobuf = "~2.0"
 grpcio = { git = "https://github.com/oasislabs/grpc-rs", tag = "v0.3.0-ekiden2", features = ["openssl"] }
 futures = "0.1"
```

After that, you need to change the current API's `lib.rs` file to add a `use`
directive to make the imported API accessible in the files that `protoc`
generates.

This is as simple as adding an `extern crate` declaration and using it:

```diff
--- a/compute/api/src/lib.rs
+++ b/compute/api/src/lib.rs
@@ -3,10 +3,12 @@ extern crate grpcio;
 extern crate protobuf;

 extern crate ekiden_common_api;
+extern crate ekiden_roothash_api;

 mod generated;

 use ekiden_common_api as common;
+use ekiden_roothash_api as roothash;

 pub use generated::computation_group::*;
 pub use generated::computation_group_grpc::*;
```

But we're not done yet!  To make the new export available in the generated
files, we also need to add the module in the `build.rs` file of the current
API.

How to do this depends on whether the `build.rs` file already uses
`generate_mod_with_imports()` or the simpler `generate_mod()`.

In the first case, you simply add the additional dependency to the list
like this:

```diff
diff --git a/compute/api/build.rs b/compute/api/build.rs
index db26226..0e39719 100644
--- a/compute/api/build.rs
+++ b/compute/api/build.rs
@@ -6,7 +6,7 @@ fn main() {
     // Must be done first to create src/generated directory
     ekiden_tools::generate_mod_with_imports(
         "src/generated",
-        &["common"],
+        &["common", "roothash"],
         &[
             "computation_group",
             "computation_group_grpc",
```

In the second case, you need to transform the simple `generate_mod()` into
a `generate_mod_with_imports()`.  To do this, specify the imports in a vector
as the second argument (the third argument are the exported submodules as
before).  Note that after this, the root will be changed from the current
crate to the root of the Ekiden repository, so keep that in mind.


Now, finally, it will compile and work!

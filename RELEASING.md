Release Checklist
=================

* Make sure all changes to be released are on `main`
* Compare `main`'s commit history to the change log to ensure all public API changes are included as well as notable internal changes
* Sanity check the version number set in `Cargo.toml` with the change log. Remember, we use semver!
* Commit, push, and merge `Cargo.toml` (if needed) and `CHANGELOG.md`. 
* Run the [release action](https://github.com/IronCoreLabs/ironoxide/actions/workflows/release.yaml)
* Check crates.io and docs.rs sites for new version

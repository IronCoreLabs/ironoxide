Integration Testing
===================

Our integration tests require that we point to the IronCore staging environment. In order to swap that out at compile time we use a Rust feature flag to causes the SDK to point to stage. To prevent us from having to always pass `--features` when running our tests, we created an alias so that `cargo t` will automatically apply that feature flag. If you run `cargo test` you'll get failures that will hopefully clue you in that you need to use `cargo t` instead.

Running *only* the unit tests (IronOxide users - this is what you want):

`cargo t --lib`

Running *only* the integration tests:

`cargo t --test group_ops --test user_ops --test document_ops`

Running all the tests:

`cargo t`

#### Integration Tests

Integration tests are run as part of a PR build on Travis. These keys are stored as a Travis secret.

The integration test run against IronCore's staging environment and require some tests keys. These can be found in `tests/testkeys/rsa_private.pem.iron`. _Currently only IronCore devs have access to these keys._ The following ironhide command will decrypt the developer test keys. 

`$ ironhide file:decrypt rsa_private.pem.iron`

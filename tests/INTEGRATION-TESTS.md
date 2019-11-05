# Integration Testing

Our integration tests default to pointing to the IronCore staging environment, and will therefore need to be set up before use. However, unit tests can be run without prior setup.

To run _only_ the unit tests (IronOxide users - this is what you want):

`cargo t --lib`

To run _only_ the integration tests:

`cargo t --test group_ops --test user_ops --test document_ops`

To run all the tests:

`cargo t`

## Setting Up Integration Tests

In order to run the integration tests, you must provide IronOxide with an Identity Assertion Key file, an IronCore Config file, and the URL you would like to test against. This will require you to create a project, segment, and Identity Assertion Key using the admin console interface.

### Identity Assertion Key File

This file must be downloaded from the admin console interface immediately after creating a new Identity Assertion Key. It should be named `rsa_private.pem` and placed in `./tests/testkeys`.

### IronCore Config File

This file can be downloaded from the admin console on creation of the very first project. For subsequent projects, it will need to be created manually. The file is of the form:

```json
{
  "projectId": { YOUR_PROJECT_ID },
  "segmentId": "{YOUR_SEGMENT_ID}",
  "identityAssertionKeyId": { YOUR_IDENTITY_ASSERION_KEY_ID }
}
```

Note that case is significant for the key names.

This file must be named `ironcore-config.json` and placed in `./tests/testkeys`.

### Environment URL

By default, IronOxide will test against the staging build, but it can also test against dev, prod, or any other environment. This is specified with the environment variable `IRONCORE_ENV`, which can be set before running `cargo t`. There are several built-in environment URLs, or one can be specified. To do this, run the following:

    Development: `IRONCORE_ENV=dev cargo t`
    Staging:     `IRONCORE_ENV=stage cargo t`
    Production:  `IRONCORE_ENV=prod cargo t`
    Other:       `IRONCORE_ENV={URL} cargo t`

where `{URL}` is the environment you want to test against.

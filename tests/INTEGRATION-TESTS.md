# Integration Testing

Our integration tests default to pointing to the IronCore environment, and will therefore need to be set up before use. However, unit tests can be run without prior setup.

To run _only_ the unit tests (IronOxide users - this is what you want):

`cargo t --lib`

To run _only_ the integration tests:

`cargo t --test group_ops --test user_ops --test document_ops`

To run all the tests:

`cargo t`

## Testing against IronCore Dev, Stage, or Prod Environments

Integration tests run against IronCore environments require some test keys and configuration files. Pre-generated keys and config files can be found in `tests/testkeys/`. _Currently only IronCore devs have access to these keys._ The following ironhide command will decrypt the developer test keys.

`$ ironhide file:decrypt tests/testkeys/*.iron`

### Running the Tests

The environment you would like to test against is specified in the environment variable `IRONCORE_ENV`. This variable can be set to `stage` or `prod` - this will cause the tests to use one set of the pre-generated key and config files (i.e. iak-stage.pem and ironcore-config-stage.json). To test against these, run one of the following:

- Staging: `IRONCORE_ENV=stage cargo t`
- Production: `IRONCORE_ENV=prod cargo t`

## Testing against a different environment

IronOxide tests can be run against any other environment, with proper setup. To do this, you must provide an Identity Assertion Key file, an IronCore Config file, and the URL you would like to test against. This will require you to create a project, segment, and Identity Assertion Key using the admin console interface.

### Identity Assertion Key File

An Identity Assertion Key file must be downloaded from the admin console interface immediately after creating a new Identity Assertion Key. It must be named `iak.pem` and placed in `./tests/testkeys/`.

### IronCore Config File

An IronCore Config file can be downloaded from the admin console on creation of the very first project. For subsequent projects, it will need to be created manually. The file is of the form:

```javascript
{
  "projectId": YOUR_PROJECT_ID,
  "segmentId": "YOUR_SEGMENT_ID",
  "identityAssertionKeyId": YOUR_IDENTITY_ASSERTION_KEY_ID
}
```

Note that case is significant for the key names.

This file must be named `ironcore-config.json` and placed in `./tests/testkeys/`.

### Environment URL

The URL of the environment you would like to test against is specified in the environment variable `IRONCORE_ENV`. To specify this when running the tests, run the following:

    Manual URL: `IRONCORE_ENV={URL} cargo t`

where `{URL}` is the URL of the environment you want to test against.

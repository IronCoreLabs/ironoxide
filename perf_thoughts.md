# Initial profiling thoughts

## What I did

I used the [flame](https://github.com/llogiq/flame) library to instrument some pieces of our code. I considered using Linux's `perf`, but I was pretty sure the output would be really hard to read given rust mangling and our use of futures.

I started out by instrumenting major functions in the call path of "user create" and "group create", using the integration tests as the driver to exercise the code. Flame is able to dump out both HTML/JSON and text to stdout. The HTML view was useful for seeing the relative amount of time being taken, and for navigating around the results. The stdout information was useful for seeing actual timings and for seeing small things that were too difficult to navigate visually.

## Learnings

* we are executing our futures on a single thread. I think I knew this, but I re-rememberd.
* because much of our code is async, instrumenting it at a high level is somewhat difficult. It is certainly not sufficient to instrument at the function level, in many cases, as a Future may be created, but will not be executed until later on. This means wrapping the code inside each Future of interest with `flame::start` and `flame::end`
* In the case of `generate_new_device` there is a non-trivial block of time that is unaccounted for. This occurrs between when the top-level future has returned its `DeviceContext` and when `generate_new_device` exits. One idea is that the tokio Runtime may be cleaning up and/or shutting down. Curious enough, I didn't see this for `user_create` or `group_create`.
* Flame's text output would be decent way to get one-off timings for instrumented pieces of code.
* Creating a `Recrypt` is quite cheap
* Creating a `tokio::Runtime` is cheap. Cleaning it up may not be.
* I wasn't really able to say anything about our use of `reqwest` or our use of the async client
* The password hashing in `derive_key_from_password` is pretty slow.

## Possible Next steps
* It would be pretty easy to use `flame` to get basic timings for all the top level functions. For these to be directly comparable to the results from ironoxide-scala we would need to be able to run on the same machine as the stress-test.
* Could further invest in `flame` and have the integration tests writing out performance results to disk
* Maybe it would be easier to profile if ironoxide was upgraded to std::futures::Future and used async/await? This would also allow us to get rid of `tokio::Runtime` as I think std Futures can just run and block without a runtime.
  - If this ended up being clean enough it also might allow us to leave some minimal profiling in the code with a feature flag to turn it on. Right now it would be pretty messy to do this.
* We could create a criterion bench for some of the core crypto operations to see if we can speed them up (encrypt_user_master_key, derive_key_from_password, etc)
* Probably not advisable, but we could create a criteron bench for the SDK methods. 
* We could create a version of the stress test in pure Rust -- maybe there's a framwork out there that would make this easy.
* We could use `perf` or use the `CLion` editor to do a different style of profiling.
* We could build a rust version of ironoxide with some profiling baked in and embed that in an ironoxide-java/scala and use that in the stress test. This would give us a different way of exercising the code.

## Open Questions
* What impact is the tokio runtime having?
* What impact is the reqwest client having?
* What overhead is java/scala introducing?
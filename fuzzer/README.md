# Fuzzer for libupdate_engine_android
## Table of contents
+ [updateEngine_downloadAction_fuzzer](#updateEngine_downloadAction_fuzzer)

# <a name="updateEngine_downloadAction_fuzzer"></a> Fuzzer for download_action

## Plugin Design Considerations
The fuzzer plugin for libupdate_engine_android is designed based on the understanding of the library
 and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

libupdate_engine_android supports the following parameters:
1. Version (parameter name: `version`)
2. Already_Applied (parameter name: `already_applied`)
3. Is_Resume (parameter name: `is_resume`)
4. Interactive (parameter name: `interactive`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `version` | `String` | Value obtained from FuzzedDataProvider|
| `already_applied` | `true` or `false` | Value obtained from FuzzedDataProvider|
| `is_resume` | `true` or `false` | Value obtained from FuzzedDataProvider|
| `interactive` | `true` or `false` | Value obtained from FuzzedDataProvider|

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin feeds the entire input data to the libupdate_engine_android module.
This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build updateEngine_downloadAction_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) updateEngine_downloadAction_fuzzer
```
#### Steps to run

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/${TARGET_ARCH}/updateEngine_downloadAction_fuzzer/updateEngine_downloadAction_fuzzer
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz

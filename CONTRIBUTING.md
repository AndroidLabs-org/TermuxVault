# Contributing to Termux Vault

Thanks for taking a look. Please keep changes small and focused. This app handles secrets, so a
behaviour change needs a clear reason.

## Building

You need JDK 17 or newer, Android SDK Platform 37.0, and Build Tools 36.0.0 and 37.0.0.

```sh
./gradlew lintRelease
./gradlew assembleDebug
```

Dependency checksums and the Gradle wrapper checksum are committed. After changing a dependency,
regenerate `gradle/verification-metadata.xml` in the same change:

```sh
./gradlew --write-verification-metadata sha256 help
```

## Release builds and signing

Release signing uses local Gradle properties or a gitignored `.env` (copy `.env.example`). Signing
material must never be committed. Without it, the release artifact is deliberately unsigned.

```sh
./gradlew assembleRelease \
  -PvaultSigningStoreFile=/private/path/release.p12 \
  -PvaultSigningStorePassword=... \
  -PvaultSigningKeyAlias=... \
  -PvaultSigningKeyPassword=...
```

The release build must stay reproducible, because F-Droid compares its own build with the signed
APK. Do not add timestamps or other values that change from build to build. Build with JDK 17 or 21 (the release workflow uses Temurin 21; both give identical output). A much newer javac, such as 26, numbers lambdas differently and changes `classes.dex`. The build date shown
in Settings comes from `releaseDate` in `app/build.gradle.kts`; update it together with
`versionName` and `versionCode` at each release.

## Reporting problems

Open an issue for bugs and ideas. For anything security-related, follow [SECURITY.md](SECURITY.md)
instead of opening a public issue.

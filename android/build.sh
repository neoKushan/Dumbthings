#!/bin/bash
# Build the standalone OTM app with plain SDK tools (no Gradle).
#
# Requirements:
#   - Android SDK build-tools + a platform jar (android-35 used here)
#   - JDK 11+
#   - BouncyCastle 1.78.1 jars in ./libs:
#       bcprov-jdk18on-1.78.1.jar bctls-jdk18on-1.78.1.jar
#       bcpkix-jdk18on-1.78.1.jar bcutil-jdk18on-1.78.1.jar
#     (download from Maven Central; they are not committed)
#
# BouncyCastle MUST be on both the javac classpath and the d8 inputs, so that
# CapCrypto (which lives in BC's own package to override a package-private method)
# is dexed alongside it. The dex has no jar-signer check, so this loads on-device.
#
# Usage:  ANDROID_SDK=... JAVA_HOME=... ./build.sh [versionCode]
# On Windows (Git Bash) swap the classpath separator ':' for ';'.
set -e
: "${ANDROID_SDK:?set ANDROID_SDK to your SDK root}"
: "${JAVA_HOME:?set JAVA_HOME to a JDK 11+}"
BT="$ANDROID_SDK/build-tools/37.0.0"
AJAR="$ANDROID_SDK/platforms/android-35/android.jar"
SEP=":"; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) SEP=";";; esac
VCODE="${1:-1}"
CP="$AJAR${SEP}libs/bcprov-jdk18on-1.78.1.jar${SEP}libs/bctls-jdk18on-1.78.1.jar${SEP}libs/bcpkix-jdk18on-1.78.1.jar${SEP}libs/bcutil-jdk18on-1.78.1.jar"

rm -rf classes dexout base.apk aligned.apk app.apk res.zip; mkdir -p classes dexout
"$JAVA_HOME/bin/javac" -encoding UTF-8 -source 8 -target 8 -nowarn -cp "$CP" -d classes $(find src -name '*.java')
"$BT/d8" --lib "$AJAR" --min-api 31 --output dexout \
    $(find classes -name '*.class') \
    libs/bcprov-jdk18on-1.78.1.jar libs/bctls-jdk18on-1.78.1.jar \
    libs/bcpkix-jdk18on-1.78.1.jar libs/bcutil-jdk18on-1.78.1.jar
"$BT/aapt2" compile --dir res -o res.zip
"$BT/aapt2" link -o base.apk -I "$AJAR" --manifest AndroidManifest.xml \
    --min-sdk-version 31 --target-sdk-version 33 --version-code "$VCODE" --version-name "$VCODE.0" res.zip
python -c "import zipfile; z=zipfile.ZipFile('base.apk','a',zipfile.ZIP_DEFLATED); z.write('dexout/classes.dex','classes.dex'); z.close()"
"$BT/zipalign" -f 4 base.apk aligned.apk
[ -f debug.ks ] || "$JAVA_HOME/bin/keytool" -genkeypair -keystore debug.ks \
    -storepass android -keypass android -alias k -keyalg RSA -keysize 2048 \
    -validity 10000 -dname "CN=dumbthings"
"$BT/apksigner" sign --ks debug.ks --ks-pass pass:android --key-pass pass:android --out app.apk aligned.apk
echo "built app.apk (version-code $VCODE)"

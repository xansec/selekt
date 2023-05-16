FROM ubuntu AS builder

RUN apt update -y && DEBIAN_FRONTEND=noninteractive apt install -y zip unzip git cmake gcc g++ ninja-build build-essential gpg openjdk-17-jdk wget kotlin android-sdk sdkmanager libssl-dev tclsh
RUN wget https://services.gradle.org/distributions/gradle-8.1.1-bin.zip
RUN mkdir /opt/gradle
RUN unzip -d /opt/gradle gradle-8.1.1-bin.zip
ENV PATH=/opt/gradle/gradle-8.1.1/bin:$PATH
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV ANDROID_HOME=/usr/lib/android-sdk
ENV ANDROID_NDK_HOME=/usr/lib/android-sdk/ndk/25.2.9519653/
RUN mkdir /selekt
COPY . /selekt
WORKDIR /selekt
RUN yes | sdkmanager --licenses
WORKDIR /selekt/selekt-sqlite3/src/main/external
RUN rm -rf ./sqlcipher
RUN git clone https://github.com/sqlcipher/sqlcipher.git
WORKDIR /selekt
RUN gradle jar
WORKDIR /selekt/fuzz
RUN gradle shadowJar

FROM cifuzz/jazzer:latest

COPY --from=builder /selekt/fuzz/targets/build/libs/targets-all.jar /selekt-fuzz.jar
COPY ./mayhem/sql.dict /

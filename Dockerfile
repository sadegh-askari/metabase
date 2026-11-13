###################
# STAGE 1: builder
###################

FROM --platform=$BUILDPLATFORM eclipse-temurin:25-jdk-jammy AS jdk

FROM --platform=$BUILDPLATFORM node:22-bookworm AS builder

ARG MB_EDITION=oss
ARG VERSION

WORKDIR /home/node

COPY --from=jdk /opt/java/openjdk /opt/java/openjdk

ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="/opt/java/openjdk/bin:$PATH"

RUN apt-get update && apt-get install wget apt-transport-https curl git util-linux -y \
    && curl -O https://download.clojure.org/install/linux-install-1.12.0.1488.sh \
    && chmod +x linux-install-1.12.0.1488.sh \
    && ./linux-install-1.12.0.1488.sh \
    && curl -LsSf https://astral.sh/uv/install.sh | sh

ENV PATH="/root/.local/bin:$PATH"

COPY . .

# version is pulled from git, but git doesn't trust the directory due to different owners
RUN git config --global --add safe.directory /home/node

# install bun for frontend dependencies
RUN npm install -g bun

# install frontend dependencies
RUN bun install --frozen-lockfile

RUN --mount=type=cache,target=/root/.m2 \
    --mount=type=cache,target=/root/.gitlibs \
    taskset -c 0-3 env INTERACTIVE=false CI=true MB_EDITION=$MB_EDITION bin/build.sh "{:version \"${VERSION}\"}"

# ###################
# # STAGE 2: runner
# ###################

## Remember that this runner image needs to be the same as bin/docker/Dockerfile with the exception that this one grabs the
## jar from the previous stage rather than the local build

FROM eclipse-temurin:25-jre-alpine AS runner

ENV FC_LANG=en-US LC_CTYPE=en_US.UTF-8

# copy certs before the RUN so keytool can import them
COPY bin/docker/DigiCertGlobalRootG2.crt.pem /app/certs/DigiCertGlobalRootG2.crt.pem

# dependencies
RUN apk add -U bash fontconfig curl font-noto font-noto-arabic font-noto-hebrew font-noto-cjk java-cacerts && \
    apk upgrade && \
    rm -rf /var/cache/apk/* && \
    sed -i 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' /etc/ca-certificates.conf && \
    update-ca-certificates && \
    /opt/java/openjdk/bin/keytool -list -v -cacerts -storepass changeit | awk '/^Alias name:/{a=substr($0,13)} /^Owner: CN=emSign ECC Root CA - G3,/{print a}' | while read -r a; do /opt/java/openjdk/bin/keytool -delete -cacerts -storepass changeit -alias "$a"; done && \
    mkdir -p /app/certs && \
    curl https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem -o /app/certs/rds-combined-ca-bundle.pem  && \
    /opt/java/openjdk/bin/keytool -noprompt -import -trustcacerts -alias aws-rds -file /app/certs/rds-combined-ca-bundle.pem -keystore /etc/ssl/certs/java/cacerts -keypass changeit -storepass changeit && \
    /opt/java/openjdk/bin/keytool -noprompt -import -trustcacerts -alias azure-cert -file /app/certs/DigiCertGlobalRootG2.crt.pem -keystore /etc/ssl/certs/java/cacerts -keypass changeit -storepass changeit && \
    mkdir -p /plugins && chmod a+rwx /plugins

COPY bin/docker/blocked.certs /app/certs/
RUN cat /app/certs/blocked.certs >> /opt/java/openjdk/lib/security/blocked.certs

# add Metabase script and uberjar
COPY --from=builder /home/node/target/uberjar/metabase.jar /app/
COPY bin/docker/run_metabase.sh /app/

# expose our default runtime port
EXPOSE 3000

# run it
ENTRYPOINT ["/app/run_metabase.sh"]

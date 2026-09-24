# EU DSS (Digital Signature Service) validator for ETSI EN 319 102 conformance testing.
#
# Builds a minimal Java CLI that uses the official EU DSS library to validate
# PAdES, CAdES, and XAdES signatures per ETSI standards.
#
# Usage:
#   docker build -t simplesign-eu-dss interop/eu-dss
#   docker run --rm -v $(pwd)/samples:/in simplesign-eu-dss validate-pades /in/signed.pdf

FROM maven:3.9-eclipse-temurin-17@sha256:44512abb01061e282da7a8f86fd3c8e50609538ff9644cdb132e1ff9fccdaecb AS build
WORKDIR /build
COPY pom.xml .
# Download dependencies first (layer caching)
RUN mvn dependency:resolve -q
COPY src/ src/
RUN mvn package -q -DskipTests

FROM eclipse-temurin:17-jre@sha256:bd25c61779663bc2df8ced059f1cc114fafc073afe16125c13fcc3a37fecd845
WORKDIR /opt/dss
COPY --from=build /build/target/dss-validator-1.0.0.jar /opt/dss/validator.jar

ENTRYPOINT ["java", "-jar", "/opt/dss/validator.jar"]
CMD ["help"]

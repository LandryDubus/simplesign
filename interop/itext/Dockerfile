# iText 9 AGPL validator for PAdES interop testing.
#
# Uses iText Core 9 (AGPL) for independent PDF signature validation.
#
# Usage:
#   docker build -t simplesign-itext interop/itext
#   docker run --rm -v $(pwd)/samples:/in simplesign-itext validate-pdf /in/signed.pdf

FROM maven:3.9-eclipse-temurin-17@sha256:44512abb01061e282da7a8f86fd3c8e50609538ff9644cdb132e1ff9fccdaecb AS build
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:resolve -q
COPY src/ src/
RUN mvn package -q -DskipTests

FROM eclipse-temurin:17-jre@sha256:bd25c61779663bc2df8ced059f1cc114fafc073afe16125c13fcc3a37fecd845
WORKDIR /opt/itext
COPY --from=build /build/target/itext-validator-1.0.0.jar /opt/itext/validator.jar

ENTRYPOINT ["java", "-jar", "/opt/itext/validator.jar"]
CMD ["help"]

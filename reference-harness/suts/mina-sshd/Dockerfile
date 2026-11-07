FROM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS build
WORKDIR /build
COPY pom.xml Server.java ./
RUN mvn -B -q package dependency:copy-dependencies -DincludeScope=runtime

FROM eclipse-temurin:21-jre-alpine@sha256:ac05c3c42b7c2f1a52c9bd52f01041fa1958231b15ebeae7420429cbc5baf474
RUN mkdir -p /etc/psm && touch /etc/psm/authorized_keys
WORKDIR /app
COPY --from=build /build/target/classes/ ./
COPY --from=build /build/target/dependency/ ./lib/
EXPOSE 22
CMD ["java", "-cp", "/app:/app/lib/*", "Server"]

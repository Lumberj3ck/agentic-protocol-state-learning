FROM maven:3.9.11-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml Server.java ./
RUN mvn -B -q package dependency:copy-dependencies -DincludeScope=runtime

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /build/target/classes/ ./
COPY --from=build /build/target/dependency/ ./lib/
EXPOSE 22
CMD ["java", "-cp", "/app:/app/lib/*", "Server"]

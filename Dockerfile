# Use a slim official Java 17 image
FROM --platform=linux/amd64 openjdk:17-jdk-slim

# Set the working directory inside the container
WORKDIR /app

# Copy Maven wrapper + pom.xml first for dependency caching
COPY mvnw pom.xml ./
COPY .mvn .mvn

# Download dependencies
RUN ./mvnw dependency:go-offline

# Copy source code
COPY src ./src

# Build the application (skip tests for faster build)
RUN ./mvnw package -DskipTests

# Run the application
CMD ["java", "-jar", "target/auth-service-0.0.1-SNAPSHOT.jar"]

# Expose the port your app runs on
EXPOSE 8081
# zenkey-java-sdk
zenkey-java-sdk is a application that call discovery issuer api.
This application publishes the package in GitHub (https://github.com/MyZenKey).
To publish the package, in the terminal run "mvn clean deploy". Once it's done, 
it will create the package in GitHub.

To consume this package in other application, all you have to do copy and paste the dependency.
Ex.
    <dependency>
    <groupId>com.zenkey</groupId>
    <artifactId>zenkey-java-sdk</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    </dependency>

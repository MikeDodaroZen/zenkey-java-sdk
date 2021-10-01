# Java SDK Integration for ZenKey

The ZenKey Java SDK implements OAuth 2.0 protocol for Web sites with integration to mobile phone carriers.  A single Java interface named **AuthorizationHandler** supports two methods that application code uses to interact with wireless networks. 
 
```
public interface AuthorizationHandler {

    AuthorizationOidcResponse getAuthorization(String clientId, String mccmnc, String redirectUri, List scopes);
    AuthorizationOidcResponse getAuthorizationToken(String clientId, String mccmnc, String code, String clientKeyPairs, String keyPair);
}

```

## SDK as a Maven Dependency 

After purchasing the SDK, you will receive an email with the Maven dependency tag.

```
    <dependency>
       <groupId>com.zenkey</groupId>
       <artifactId>zenkey-java-sdk</artifactId>
       <version>0.0.1-SNAPSHOT</version>
    </dependency>
```

Insert the dependency tag into the *pom.xml* file of the application that will use the SDK.  It should be inside the `<dependencies>` tag along with other dependencies.

## Add ZenKey Repository to Maven settings.xml

The ZenKey Java SDK is not located on the Maven central repository, also known as Maven Central.  ZenKey has its own repository to host the Java SDK.  The repository needs to be added to your Maven settings.xml.  Either create the following settings.xml, or add the profiles and servers tags to your existing `settings.xml`.  The new or existing `settings.xml` is usually located either within your local `.m2` or within the `settings.xml` in your Maven installation `/conf` folder.  There is also the option of adding the profiles and servers tags directly in your application’s `pom.xml` file.

```
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
    <activeProfiles>
        <activeProfile>github</activeProfile>
    </activeProfiles>

    <profiles>
        <profile>
            <id>github</id>
            <repositories>
                <repository>
                    <id>central</id>
                    <url>https://repo1.maven.org/maven2</url>
                </repository>
                <repository>
                    <id>github</id>
                    <url>https://maven.pkg.github.com/MyZenKey/zenkey-java-sdk</url>
                    <snapshots>
                        <enabled>true</enabled>
                    </snapshots>
                </repository>
            </repositories>
        </profile>
    </profiles>

    <servers>
        <server>
            <id>github</id>
            <username>GarryZen</username>
            <password>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</password>
        </server>
    </servers>
</settings>
```

Replace the username and password property tag value content with the username and password that you receive in the email.  The id property tags can be whatever unique name you desire, but the two must have the same value.

## ZenKey Properties File Configuration Setup
  
  After purchase, among the downloadable artifacts customers will receive are ZenKey properties, key/value pairs, within both a *.properties* file and a *.yaml* file.  Both files have the same properties.  Use the file that applies to your specific existing application configuration setup.  For example, if you have a Spring Boot application, you will have either an existing *application.yaml* or *application.properties* file in the /resources folder.  All properties are customer-specific.  This is the reason these properties cannot be part of the SDK.  The following is an example of the properties as they would display within your .yaml file:

  ```
  #
  #  ZenKey Java SDK properties
  #
  clientId: ccid-h2vqzbtklfotaedl
  clientKeyPairs: "{ \"ccid-h2vqzbtklfotaedl\": \"ccid-h2vqzbtklfotaedl.1623943437897\" }"
  keyPair: "{
    \"ccid-h2vqzbtklfotaedl.1623943437897\": {
      \"alg\": \"RS256\",
      \"d\": \"DrzJpYM8ASgK4fQbZolBea5Yzk9hZkcMA8BMUn2-6z5JYYfLQRxKlHNP90CNC8h_nWEn7Kjn_JCYVRGjdiHL2IZV_ZGJcaXWoobCnMWJ_G4HFXyJtbovWS1LQXpNagONrTl8IBX61iglKBV2brnGqo_awmHwzAhD5JUyyElwda2vcl71VQ0Cyx1ohfDGWhzAypkRky8Oj8SSGCebpzgRtMaKXN-hs7zEXzXz-aDyRRDQF1MuzAT9ovsgOXjImk6stQD_sOq8OC5BqbV9r6v1u2hr2gm4KM6oksB794NZAH4pDM1Uz3SRxpK-ZEnPQzfB4rPWFnyBvKcHKPwxkRhooQ\",
      \"dp\": \"KmHp96ZQlKDbsxhteOeEQ1e-0aINAvb9OsDccoLq82Zr6a4UmBL_kqjZ4LJo99OL-dsef81KHc6x_KNBv-LpcRW2WjDcmd0uCNoSFa8rvTtPf_Taav370oD0EYmG1iWjJ0aLt-nkIPklwl2UPYxv3y66EkMznBcbNH_FSTcQjm0\",
      \"dq\": \"yGGLNvNQdo5MH72KfcmJDDHkyXsfDWcr_E86XRxCqcRbF0OjfWH-7ONFtBXZHBxqcM1h_gPo5Yth2mBUebcu1Gpam3wuqPcN259RBzuLTZmdKkDurn7sHccUCg-pw2zFKTgxbppClpXYfW_sh8W62EIMa_QrxXvEToJryYRaskE\",
      \"e\": \"AQAB\",
      \"ext\": true,
      \"key_ops\": [
                   \"sign\"
      ],
      \"kty\": \"RSA\",
      \"n\": \"s4GaLCvD3RBTQxzorGyG7fif7TsxkokEIjlLwTcqvKJ6f3qglK1QTd1wLF4j6fMR1QidQQUT-kVLDQwI6wCdDlVvkiqXXSb79A-MhUZIHpwGv7cijPZNMowJQEb_cK0bhoYh6TT8oeSR7yGUTJhtqysmLl3nmVAPI3pioSakOQdAd8OifSGFAhkDlHd5o-JmD6avbgl952241UBvCUrOe98vueJepS0v5Kb-2KOYrCifAsefQ_epHpFRIPytx2IxV2mEYVtdLgl6KEZrRqqIODGsMcDszTRPi3_KBbMCzog-muc801yWPebT5D132uZ7apI2TFwHTSP3EoK-EO7K_Q\",
      \"p\": \"24XNu-dSOR_0GjlE4K4aUceDuGUiZTPHTcE5Gm5LwaGU-Q9nAYy1ejEYNYALNqhzWlG0l6hPsnxswXJM5_UFPXgRUSLV_fjqp88tlBsj4U77T74r5q1eB5Uk7xkI9NIzNNISisk7W-akuNRUonBmNMcxU4ZR7T0l7XylrranMJ0\",
      \"q\": \"0VWOBPCY0o9oUdmJO1_mfpA3epvm7iCaO5ukN8DctcSF3MlOGdyMRjrjIV7Mz66saEUXATDwkpjUJ96Q6Bf_MtN93XjfH0ow3YXPPNRfAP3EUq8ZdAV-whvFzBeNny7XRjwYagQRuugwdbCQhYfK6OYKjYFqNix8t1Vesm0SBeE\",
      \"qi\": \"GDna8NLPlLl15qAXWacn6EXkeTryUOf1-cVs56wZvtRYSiaC3nPTUM2WUQTFkBjoDc0A-doNUikjShSmXs1fRfNRxd906KsVpmRMNoa5wbGMOuyqC_xF9zyPdSNJPvai_srqRasGkvYu--ikaX2BTIC33U3MN5GeWzP1DlsGSho\",
      \"kid\": \"ccid-h2vqzbtklfotaedl.1623943437897\"
    }
}"
  ```
  Since the above is a *.yaml* file, notice the use of double quotes around the keys and values.  Also, notice the escaped double quotes around the inner JSON Object keys and values.  The *.properties* file has slightly different formatting.  The properties will be used as input parameters for the two API calls explained in the next section.

  ## ZenKey Java SDK Interface Made Simple

  There is a single Java SDK interface that a service-provider developer will utilize:
```
  public interface AuthorizationHandler {

    AuthorizationOidcResponse getAuthorization(String clientId, String mccmnc, String redirectUri, List scopes);

  AuthorizationOidcResponse getAuthorizationToken(String clientId, String mccmnc, String code, String clientKeyPairs, String keyPair, String redirectUri);

  }
```
## Method: **getAuthorization**

The **getAuthorization** method, when successful, gets a registered user's `authorization code` and `mccmnc`, which will be used as input parameters for a subsequent call to the **getAuthorizationToken** method.  

If the user isn't registered and `mccmnc` isn't known, **getAuthorization** redirects the user to ZenKey's optimized *discovery-ui* and prompts user to select a phone number or scan a QR code if phone number isn't yet discovered. Then **getAuthorization** is called a second time with the correct mccmnc carrier.

The purpose of  automatic *discovery-ui* redirect is to obtain an authorization code.  The optimized *discovery-ui* allows the user to select the phone number they want to use, which will be used to determine the phone’s carrier.  The authorization code is obtained from the specific carrier for that user’s phone.

Optimized `discovery-ui`, which is an automatic redirect that is a brief interruption during **getAuthorization**, returns the following:
- authorization code (auth code)
- mccmnc (the mobile carrier)

- After the **getAuthorization** method returns, the UI then calls the **getAuthorizationToken** as explained below.

## Method: **getAuthorizationToken**
Within this call the remaining OAuth2 workflow steps are executed within the SDK.
    The following input parameters are required for the getAuthorizationToken() API method:
      - clientId - Obtained by SP during client registration.  It is the ID that begins with ‘ccid’.
      - mccmnc - This is a returned property obtained from the optimized discovery-ui process where the user is redirected to in order for the user’s phone carrier to be determined based on the user’s selected phone number.
      - code (authorization code) - This is obtained from the optimized discovery-ui process.  UI (Angular) code that is discussed below explains exactly how to obtain this property.
      - clientKeyPairs - This is a string property that will be provided to the SP when they download the Java SDK.
      - keyPair - This is a string property that will be provided to the SP when they download the Java SDK.
      - redirectUri - This is the publicly exposed URL of the SP’s application that is making this authorization request.

If successful, the user info is returned.  Again, this is handled by the SDK.

 - There are no interruptions or automatic redirects during this method execution.  Everything happens behind-the-scenes on the server-side before returning to the UI with the user info.

## Java Code Needed To Call Java SDK
The following code snippets in a customer app call the Java SDK **getAuthorization** and **getAuthorizationToken** methods in order to execute **OAuth 2.0** workflows and obtain `token` and `UserInfo`.

```
AuthorizationOidcResponse authorizationResponse = new AuthorizationOidcResponse();

try {
    AuthorizationHandler authHandler = new AuthorizationHandlerImpl();
    authorizationResponse = authHandler.getAuthorization(serviceConfiguration.getClientId(), mccmnc, redirectUri, scopes);
} catch (Exception ex) {
    String returnMessage = String.format("===> Authorization Failed: An error occurred when making getAuthorization SDK API call: %s”, ex.getMessage());
    log.error(returnMessage);
    authorizationResponse = constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null);
    return authorizationResponse;
}
return authorizationResponse;
```

The following code within the customer’s app calls the SDK’s **getAuthorizationToken**.

```
    AuthorizationOidcResponse authorizationResponse = new AuthorizationOidcResponse();

try {
    AuthorizationHandler authHandler = new AuthorizationHandlerImpl();
    authorizationResponse = authHandler.getAuthorizationToken(serviceConfiguration.getClientId(), mccmnc, code, serviceConfiguration.getClientKeyPairs(), serviceConfiguration.getKeyPair());
 } catch (Exception ex) {
    String returnMessage = String.format("===> AuthorizationToken Failed: An error occurred when making getAuthorizationToken SDK API call: %s”, ex.getMessage());
    log.error(returnMessage);
    authorizationResponse = constructAuthorizationOidcResponse(false, returnMessage, AuthorizationStatus.FAILED.name(), null);
    return authorizationResponse;
}
return authorizationResponse;
```
The previous code in this section is all of the Java code that is needed to call the two SDK methods.  Keep in mind that there will likely be a dynamic redirect, but workflow execution will continue seamlessly. 

## Properties of **AuthorizationOidcResponse**
- Boolean: isSuccess 
- Boolean: isCarrier - This is false if the `mccmnc` (carrier) is empty or could not be found.  A *false* value means that the optimized `discovery-ui` redirect is needed to determine the carrier.
- Boolean: isCustomerInfoFound - Not Supported at this time.
- Boolean: isRedirectForAuthorization - No longer supported at this time, since using optimized `discovery-ui`.
- String: status - This will have a value of either “SUCCESSFUL” or “FAILED”.
- String: message - This will have a text value providing either the specific reason either of the two API calls failed or if they succeeded.
- OidcUrlInfo:  oidcUrlInfo - Not supported.
- JsonNode: data - Contains the optimized discovery UI URL.
- String: sub - This will contain the value of the `sub` if the user has previously been authorized and the `sub` was persisted by the customer’s application.  If the customer's application is not persisting the `sub`, this may not be used.

## Necessary UI Code
The following example is Angular client-side code within the *login-page.component.ts* file. It handles the REST call to a **getAuthorization** server-side interface method and one optimized redirect to *discovery-ui*.  When the user clicks the *Sign In With ZenKey* button, it activates the button-click event.

```
    let movieAccountUserBody = {
      userName: (localStorage.getItem("username") != undefined) ? localStorage.getItem("username") : this.loginForm.value.username,
      mccmnc: this.mccmnc,
      scopes: this.scopesArray
    };

    this.authService.getAuthorization(movieAccountUserBody).pipe(shareReplay())
        .subscribe((returnedAuthorizationData: any) => {
            if (returnedAuthorizationData.isSuccess) {
              this.authorizationMessage = "Sub found in data store.  You are already authorized."
              localStorage.clear();
              this.showModal(authorizationSuccessfulSubFound);
              this.spinner.hide();
            } else if (!returnedAuthorizationData.isCarrier) {
              localStorage.setItem("username", this.loginForm.value.username);
              this.spinner.hide();              
              this.redirect(returnedAuthorizationData.data.optimized_discovery_url);
            } else if (returnedAuthorizationData.isServerInitiated) {
              if (returnedAuthorizationData.isServerInitiatedError) {
                this.authorizationMessage = returnedAuthorizationData.message;
                this.spinner.hide();
                this.showModal(failedTemplate);
              }
              localStorage.clear();
            } else {
              this.authorizationMessage = "Authorization Failed:  Check credentials and try again."
              localStorage.clear();
              this.showModal(failedTemplate);
              this.spinner.hide();
            }
        },
        error => {
          this.authorizationMessage = "Authorization Failed:  Check credentials and try again."
          this.isLoginFailed = true;
          localStorage.clear();
          this.showModal(failedTemplate);
          this.spinner.hide();
        });
```

The following code is called after a return from the **getAuthorization** method that may have been interrupted with an optimized `discovery-ui` redirect.  It makes a REST call to the **getAuthorizationToken** server-side interface method.
```
    private continueAuthorization(successfulAuthorizationTemplate) {
    
    this.spinner.show(undefined,
      {
        type: 'ball-triangle-path',
        size: 'medium',
        bdColor: 'rgba(0, 0, 0, 0.8)',
        color: '#fff',
        fullScreen: true
      });

    localStorage.setItem("mccmnc", this.mccmnc);

    const authorizationTokenRequestBody = {
      mccmnc: localStorage.getItem("mccmnc"),
      code: this.code,
    };

    this.authService.getAuthorizationToken(authorizationTokenRequestBody).pipe(shareReplay())
    .subscribe((returnedAuthorizationData: any) => {
      console.log("===> Entering getAuthorizationToken callback");
      if (returnedAuthorizationData.isSuccess) {
        this.authorizationMessage = returnedAuthorizationData.message;
        this.createAndFormatUserInfoData(returnedAuthorizationData);
        this.reInitializeLocalStorage();
        this.showModal(successfulAuthorizationTemplate);  
        this.router.navigate(['/pagemedia']);  
      } else {
        this.authorizationMessage = returnedAuthorizationData.message;
      }
      this.spinner.hide();
    },
    error => {
      this.authorizationMessage = "Authorization Token Failed"
      // this.showModal(failedTemplate);
      this.spinner.hide();
    });
  }
```
The following code handles intercepting the `mccmnc` and code from one redirect.  It belongs in the constructor of the component .ts file containing the ‘*Sign In With ZenKey* button.  The following code intercepts the route parameters and assigns them to component variables.

    if (this.route.queryParams != null) {
      this.route.queryParams.subscribe(
        params => this.mccmnc = params['mccmnc']);
      this.route.queryParams.subscribe(
        params => this.code = params['code']);
    }


The following client-side (Angular) code checks important variables populated after the return of one redirect and decides how to continue code execution.  Currently, this only involves checking for a valid auth code and calling **continueAuthorization** if the auth code exists to make the **getAuthorizationToken** REST call to the server.
```
  ngAfterViewInit() {
    if (this.route.queryParams != null) {
      
      if (this.code != undefined && this.code != "") {
        this.continueAuthorization(this.successfulAuthorizationTemplate);
      }
    }
  }
```
The following support method handles the redirect:
```
  redirect(url: string): void {
    window.open(url, '_self');
  }
```
The following two Angular service (HttpClient) methods call the two SDK interface methods via the customer application’s Spring Boot controller. 
```
  private getAuthorizationUrl = environment.serversideURL + environment.urls.getAuthorization;
  private getAuthorizationRedirectUrl = environment.serversideURL + environment.urls.getAuthorizationRedirect;
  private getAuthorizationTokenUrl = environment.serversideURL + environment.urls.getAuthorizationToken;

  getAuthorization(movieAccountUserBody) {

    let headers = new HttpHeaders().set('access-control-allow-origin',"*");

    return this.http.post<{any}>(this.getAuthorizationUrl, movieAccountUserBody, { 'headers': headers }).pipe(retry(0), catchError(this.handleError));
  }

  getAuthorizationToken(authorizationTokenRequestBody) {

    let headers = new HttpHeaders().set('access-control-allow-origin',"*");

    return this.http.post<{any}>(this.getAuthorizationTokenUrl, authorizationTokenRequestBody, { 'headers': headers }).pipe(retry(0), catchError(this.handleError));
  }


The *environment.ts* file that declares the URLs referenced above should have the following:

const dashboardServiceBaseUrl='http://localhost:8094';

export const environment = {
  production: false,
  serversideURL: 'http://localhost:8094',
  urls: {
    … 
    getAuthorization : '/authorization/getAuthorization',
    getAuthorizationToken : '/authorization/getAuthorizationToken',  },
    …
  client_id:'ccid-h2vqzbtklfotaedl’     // substitute this with your client_id acquired during SP registration
};
```

The following required variables are defined in a *global.ts*:
```
import { environment } from '../../environments/environment';

export class Globals {

    public static CLIENT_ID = environment.client_id;
    public static REDIRECT_URI_NEW_SP_APP = 'http://localhost:4200';
    public static MCCMNC = 'mccmnc';
    public static ACR_VALUES = {
        'Two Factor if not authenticated in last 30 minutes': 'a3', 'Single Factor': 'a1',
        'Two Factor Every Time': 'a2'
    };
}
```
All of the above client-side (Angular) code is within the *login-page.component.ts* file.

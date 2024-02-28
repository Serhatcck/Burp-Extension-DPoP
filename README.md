# DPoP Configurator Burp Extension

This Burp extension allows you to dynamically add or update the DPoP (Demonstrating Proof of Possession) HTTP header to outgoing HTTP requests based on configured criteria.

## Features

- Dynamically generate DPoP JWT (JSON Web Token) and add it to HTTP headers.
- Supports both RSA public and private keys in JWK (JSON Web Key) format.
- Configurable target URL or URL regex pattern for DPoP header injection.
- Lightweight and easy-to-use interface integrated into Burp Suite.

## Installation

1. Download the `DPoPConfigurator.jar` file from the [releases](../../releases) section.
2. Open Burp Suite.
3. Go to the **Extender > Extensions** tab.
4. Click on the "Add" button.
5. Select the `DPoPConfigurator.jar` file and click "Next".
6. Once loaded, you should see the "DPoP Configurator" tab in the Burp Suite interface.

## Usage

1. Navigate to the "DPoP Configurator" tab in Burp Suite.
2. Enter your RSA public and private keys in JWK format.
3. Configure the target URL or URL regex pattern.
4. Optionally, specify the HTTP header name for the DPoP token.
5. Click "Apply" to save your settings.
6. DPoP headers will be automatically added to outgoing requests based on the configured criteria.

## Screenshots

![image](https://github.com/Serhatcck/Burp-Extension-DPoP/assets/49496846/bd057e42-1c13-4d2c-8df8-ccc834647625)


## Contributing

Contributions are welcome! If you encounter any issues or have suggestions for improvements, please open an issue or submit a pull request.

 

| Domain         | Platform/API              | Key Type                | Target Regular Expression                                                                  | Source                                                                                                      |
| -------------- | ------------------------- | ----------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| Social Media   | Twitter                   | Access Token            | \[1-9\]\[ 0-9\]+-\[0-9a-zA-Z\]{40}                                                         |                                                                                                             |
| Social Media   | Twitter                   | Username                | /(^\|\[^@\\w\])@(\\w{1,15})\\b/                                                            | https://stackoverflow.com/a/13398311                                                                        |
| Social Media   | Facebook                  | Access Token            | EAACEdEose0cBA\[0-9A-Za-z\]+                                                               |                                                                                                             |
| Social Media   | Facebook                  | OAuth 2.0               | \[A-Za-z0-9\]{125} (counting letters \[2\])                                                | https://developers.facebook.com/docs/facebook-login/access-tokens/                                          |
| Social Media   | Instagram                 | OAuth 2.0               | \[0-9a-fA-F\]{7}.\[0-9a-fA-F\]{32}                                                         | https://www.instagram.com/developer/authentication/                                                         |
| Social Media   | Instagram                 | Username                | (?:@)([A-Za-z0-9\_](<?:(?:%5BA-Za-z0-9_%5D%7C(?:.(?!.)))%7B0,28%7D(?:%5BA-Za-z0-9_%5D)>)?) | https://blog.jstassen.com/2016/03/code-regex-for-instagram-username-and-hashtags/                           |
| Social Media   | Instagram                 | Hashtag                 | (?:#)([A-Za-z0-9\_](<?:(?:%5BA-Za-z0-9_%5D%7C(?:.(?!.)))%7B0,28%7D(?:%5BA-Za-z0-9_%5D)>)?) | https://blog.jstassen.com/2016/03/code-regex-for-instagram-username-and-hashtags/                           |
| Social Media   | Google                    | API Key                 | AIza\[0-9A-Za-z-\_\]{35}                                                                   |                                                                                                             |
| Social Media   | Google                    | OAuth 2.0 Secret        | \[0-9a-zA-Z-\_\]{24}                                                                       | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf                     |
| Social Media   | Google                    | OAuth 2.0 Auth Code     | 4/\[0-9A-Za-z-\_\]+                                                                        | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf                     |
| Social Media   | Google                    | OAuth 2.0 Refresh Token | 1/\[0-9A-Za-z-\_\]{43}\|1/\[0-9A-Za-z-\_\]{64}                                             | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf                     |
| Social Media   | Google                    | OAuth 2.0 Access Token  | ya29.\[0-9A-Za-z-\_\]+                                                                     | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf                     |
| Social Media   | GitHub                    | OAuth 2.0 ID            | \[A-Za-z0-9\_\]{255}                                                                       | https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/                               |
| Social Media   | Foursquare                | Client Key              | \[0-9a-zA-Z\_\]\[5,31\]                                                                    |                                                                                                             |
| Social Media   | Foursquare                | Secret Key              | R\_\[0-9a-f\]{32}                                                                          | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf                     |
| Finance        | Picatic                   | API Key                 | sk_live\_\[0-9a-z\]{32}                                                                    | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf                     |
| Finance        | Stripe                    | Standard API Key        | sk_live\_(0-9a-zA-Z\]{24}                                                                  | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf                     |
| Finance        | Stripe                    | Restricted API Key      | sk_live\_(0-9a-zA-Z\]{24}                                                                  | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf                     |
| Finance        | Square                    | Access Token            | sqOatp-\[0-9A-Za-z-\_\]{22}                                                                |                                                                                                             |
| Finance        | Square                    | OAuth Secret            | q0csp-\[ 0-9A-Za-z-\_\]{43}                                                                |                                                                                                             |
| Finance        | Paypal / Braintree        | Access Token            | access_token,production$\[0-9a-z\]{161\[0-9a,\]{32}                                        |                                                                                                             |
| Finance        | Amazon Marketing Services | Auth Token              | amzn.mws.\[0-9a-f\]{8}-\[0-9a-f\]{4}-10-9a-f1{4}-\[0-9a,\]{4}-\[0-9a-f\]{12}               |                                                                                                             |
| Communications | Twilio                    | API Key                 | 55\[0-9a-fA-F\]{32}                                                                        |                                                                                                             |
| Communications | MailGun                   | API Key                 | key-\[0-9a-zA-Z\]{32}                                                                      |                                                                                                             |
| Communications | MailChimp                 | API Key                 | \[0-9a-f\]{32}-us\[0-9\]{1,2}                                                              |                                                                                                             |
| Communications | Slack                     | API Key                 | xox\[baprs\]-\[0-9\]{12}-\[0-9\]{12}-\[0-9a-zA-Z\]{24}                                     |                                                                                                             |
| Communications | Slack                     | Access Token            | T\[a-zA-Z0-9\_\]{8}/B\[a-zA-Z0-9\_\]{8}/\[a-zA-Z0-9\_\]{24}                                | https://hooks.slack.com/services/T%5Ba-zA-Z0-9_%5D%7B8%7D/B%5Ba-zA-Z0-9_%5D%7B8%7D/%5Ba-zA-Z0-9_%5D%7B24%7D |
| Cloud          | Amazon Web Services       | Access Key ID           | AKIA\[0-9A-Z\]{16}                                                                         |                                                                                                             |
| Cloud          | Amazon Web Services       | Secret Key              | \[0-9a-zA-Z/+\]{40}                                                                        |                                                                                                             |
| Cloud          | Google Cloud Platform     | OAuth 2.0               | \[0-9a-fA-F\]{8}-\[0-9a-fA-F\]{4}-\[0-9a-fA-F\]{12}                                        |                                                                                                             |
| Cloud          | Google Cloud Platform     | API Key                 | \[A-Za-z0-9\_\]{21}--\[A-Za-z0-9\_\]{8}                                                    |                                                                                                             |
| Cloud          | Heroku                    | API Key                 | \[0-9a-fA-F\]{8}-\[0-9a-fA-F\]{4}-\[0-9a-fA-F\]{4}-\[0-9a-fA-F\]{4}-\[0-9a-fA-F\]{12}      | https://devcenter.heroku.com/articles/platform-api-quickstart                                               |
| Cloud          | Heroku                    | OAuth 2.0               | \[0-9a-fA-F\]{8}-\[0-9a-fA-F\]{4}-\[0-9a-fA-F\]{12}                                        |                                                                                                             |

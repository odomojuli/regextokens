| Platform/API | Type | Target Regular Expression | Source |
| --- | --- | --- | --- |
| Twitter | Access Token | [1-9][ 0-9]+-[0-9a-zA-Z]{40} | 
| Twitter | Username | /(^\|[^@\w])@(\w{1,15})\b/ | https://stackoverflow.com/a/13398311
| Twitter | Tweets | View source. | https://github.com/twitter/twitter-text/blob/master/rb/lib/twitter-text/regex.rb
| Facebook | Access Token | EAACEdEose0cBA[0-9A-Za-z]+ | https://grep.app/search?q=EAACEdEose0cBA%5B0-9A-Za-z%5D%2B&regexp=true
| Facebook | OAuth 2.0 | [A-Za-z0-9]{125} (counting letters [2]) | https://developers.facebook.com/docs/facebook-login/access-tokens/
| Instagram | OAuth 2.0 | [0-9a-fA-F]{7}\.[0-9a-fA-F]{32} | https://www.instagram.com/developer/authentication/
| Instagram | Username | (?:@)([A-Za-z0-9_]\(?:(?:[A-Za-z0-9_]\|(?:\.(?!\.))){0,28}(?:[A-Za-z0-9_]))?) | https://blog.jstassen.com/2016/03/code-regex-for-instagram-username-and-hashtags/
| Instagram | Hashtag | (?:#)([A-Za-z0-9_]\(?:(?:[A-Za-z0-9_]\|(?:\.(?!\.))){0,28}(?:[A-Za-z0-9_]))?) | https://blog.jstassen.com/2016/03/code-regex-for-instagram-username-and-hashtags/
| Google | API Key | AIza[0-9A-Za-z-_]{35} |
| Google | Firebase apiKey | AIza[0-9A-Za-z-_]{35} |
| Google | Firebase authDomain | ([a-z0-9-]){1,30}(\.firebaseapp\.com) |  |
| Google | Firebase databaseURL | `(http\|https):\/\/([a-z0-9-]){1,30}(\.firebaseio\.com)` or `(http\|https):\/\/([a-z0-9-]){1,30}(\.firebaseio\.com)` or `([a-z0-9-]){1,30}-(default-rtdb).((asia\|europe\|us\|australia)\|((north\|south)(america\|africa)))-((east\|west\|central\|north\|south)\|((north\|south)(east)))[0-9]{1,2}(\.firebasedatabase\.app)`
| Google | Firebase projectId | ([a-z0-9-]){1,30} |
| Google | Firebase storageBucket | `([a-z0-9-]){1,30}(\.appspot\.com)` or `([a-z0-9-]){1,30}(\.firebasestorage\.app)` |  |
| Google | Firebase locationId | ((asia\|europe\|us\|australia)\|((north\|south)(america\|africa)))-((east\|west\|central\|north\|south)\|((north\|south)(east))) |
| Google | Firebase messagingSenderId | (\d){10,20} |
| Google | Firebase appId | 1:(\d){10,20}:(android\|web\|ios):([a-f0-9]){10,22} |  |
| Google | Firebase measurementId | G-(\w{4,5}) |
| Google | OAuth 2.0 Secret | [0-9a-zA-Z\-_]{24} | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf
| Google | OAuth 2.0 Auth Code | 4/[0-9A-Za-z\-_]+ | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf
| Google | OAuth 2.0 Refresh Token | 1/[0-9A-Za-z\-_]{43}\|1/[0-9A-Za-z\-_]{64} | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf
| Google | OAuth 2.0 Access Token | ya29\.[0-9A-Za-z\-_]+ | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf
| GitHub | Personal Access Token (Classic) | ^ghp_[a-zA-Z0-9]{36}$ | https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token
| GitHub | Personal Access Token (Fine-Grained) | ^github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}$ |https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token#creating-a-fine-grained-personal-access-token
| GitHub | OAuth 2.0 Access Token | ^gho_[a-zA-Z0-9]{36}$ | https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
| GitHub | User-to-Server Access Token | ^ghu_[a-zA-Z0-9]{36}$ | https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-with-a-github-app-on-behalf-of-a-user
| GitHub | Server-to-Server Token | ^ghs_[a-zA-Z0-9]{36}$ | https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app#authenticating-as-an-installation
| GitHub | Refresh Token | ^ghr_[a-zA-Z0-9]{36}$ | https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokensox | Secret Key | ([s,p]k.eyJ1Ijoi[\w\.-]+) | https://grep.app/search?q=%28%5Bs%2Cp%5Dk.eyJ1Ijoi%5B%5Cw%5C.-%5D%2B%29&regexp=true
| Mapbox | Public Key | ([s,p]k.eyJ1Ijoi[\w\.-]+) | https://grep.app/search?q=%28%5Bs%2Cp%5Dk.eyJ1Ijoi%5B%5Cw%5C.-%5D%2B%29&regexp=true
| Mapbox | Secret Key | ([s,p]k.eyJ1Ijoi[\w\.-]+) | https://grep.app/search?q=%28%5Bs%2Cp%5Dk.eyJ1Ijoi%5B%5Cw%5C.-%5D%2B%29&regexp=true
| Foursquare | Client Key | `[0-9a-zA-Z_][5,31]` |  |
| Foursquare | Secret Key | R_[0-9a-f]{32} | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf |
| Picatic | API Key | sk_live_[0-9a-z]{32} | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf |
| Strapi | API Key | `[a-f0-9]{256}` | https://docs.strapi.io/dev-docs/configurations/api-tokens |
| Stripe | Standard API Key | sk_live_[0-9a-zA-Z]{24} | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf |
| Stripe | Restricted API Key | sk_live_[0-9a-zA-Z]{24} | https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf |
| Square | Access Token | sqOatp-[0-9A-Za-z\-_]{22} | https://developer.squareup.com/reference/square/oauth-api/obtaintoken |
| Square | OAuth Secret | q0csp-[ 0-9A-Za-z\-_]{43} | https://developer.squareup.com/reference/square/oauth-api/obtaintoken |
| Paypal / Braintree | Access Token | access_token\,production\$[0-9a-z]{161[0-9a,]{32} |  |
| Amazon Marketing Services | Auth Token | amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-10-9a-f1{4}-[0-9a,]{4}-[0-9a-f]{12} |  |
| Twilio | API Key | 55[0-9a-fA-F]{32} |  |
| MailGun | API Key | key-[0-9a-zA-Z]{32} |  |
| MailChimp | API Key | [0-9a-f]{32}-us[0-9]{1,2} |  |
| Slack | OAuth v2 Bot Access Token | xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24} | https://api.slack.com/authentication/oauth-v2
| Slack | OAuth v2 User Access Token | xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24} | https://api.slack.com/authentication/oauth-v2
| Slack | OAuth v2 Configuration Token | xoxe.xoxp-1-[0-9a-zA-Z]{166} | https://api.slack.com/authentication/rotation
| Slack | OAuth v2 Refresh Token | xoxe-1-[0-9a-zA-Z]{147} | https://api.slack.com/authentication/rotation
| Slack | Webhook | T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24} | https://api.slack.com/messaging/webhooks
| Amazon Web Services | Access Key ID | AKIA[0-9A-Z]{16} |  |
| Amazon Web Services | Secret Key | [0-9a-zA-Z/+]{40} |  |
| Google Cloud Platform | OAuth 2.0 | [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12} |  |
| Google Cloud Platform | API Key | [A-Za-z0-9_]{21}--[A-Za-z0-9_]{8} |  |
| Heroku | API Key | [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12} | https://devcenter.heroku.com/articles/platform-api-quickstart |
| Heroku | OAuth 2.0 | [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12} |  |

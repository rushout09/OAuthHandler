class ServiceProvider:
    name: str
    redirect_uri: str
    auth_url: str
    token_url: str
    refresh_url: str


class Google(ServiceProvider):
    name: str = 'google'
    redirect_uri: str = 'google-authorization-success'
    auth_url: str = 'https://accounts.google.com/o/oauth2/v2/auth'
    token_url: str = 'https://www.googleapis.com/oauth2/v4/token'
    refresh_url: str = 'https://www.googleapis.com/oauth2/v4/token'
    GDRIVE_API_URL: str = 'https://www.googleapis.com/drive/v3/files'
    GMAIL_API_URL: str = 'https://gmail.googleapis.com/gmail/v1/users/me/messages'


class Twitter(ServiceProvider):
    name: str = 'twitter'
    redirect_uri: str = 'twitter-authorization-success'
    auth_url: str = 'https://twitter.com/i/oauth2/authorize'
    token_url: str = 'https://api.twitter.com/2/oauth2/token'
    refresh_url: str = 'https://api.twitter.com/2/oauth2/token'


class Atlassian(ServiceProvider):
    name: str = 'atlassian'
    redirect_uri: str = 'atlassian-authorization-success'
    auth_url: str = 'https://auth.atlassian.com/authorize'
    token_url: str = 'https://auth.atlassian.com/oauth/token'
    refresh_url: str = 'https://auth.atlassian.com/oauth/token'
    CONFLUENCE_API_URL: str = 'https://api.atlassian.com/ex/confluence'
    JIRA_API_URL: str = 'https://api.atlassian.com/ex/jira'


class Slack(ServiceProvider):
    name: str = 'slack'
    redirect_uri = 'slack-authorization-success'
    auth_url: str = 'https://slack.com/oauth/v2/authorize'
    token_url: str = 'https://slack.com/api/oauth.v2.access'
    refresh_url: str = 'https://slack.com/api/oauth.v2.access'
    SLACK_API_URL: str = 'https://slack.com/api/search.all'

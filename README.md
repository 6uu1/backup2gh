## backup-to-github
English | [中文](https://github.com/laboratorys/backup2gh/blob/main/README_CN.md)
### Features
1. A zero-cost solution for cloud containers where data is lost after a restart, especially for applications based on SQLite.
2. Applicable scenarios: Suitable for cases where real-time data updates are not critical and the dataset is relatively small.
3. Automatically backs up data to a GitHub repository on a schedule.
4. Restores the most recent backup when the container restarts.
5. Auto-creates a private backup repository if it doesn't exist. The backup repository includes a GitHub Action that periodically cleans up commit history to prevent excessive storage usage.
### Environment Variables
| Variable Name               | Required | Description                                                                | Example                     |
|-------------------|------|----------------------------------------------------------------------------|------------------------|
| RUN_MODE          | No   | Running mode                                                               | 1-Standalone (default), 2-Web      |
| WEB_PORT          | No   | Web server port                                                            | Default: 8088               |
| WEB_PATH           | No   | Web request prefix for reverse proxy configuration (default: empty)        | /backup2gh             |
| WEB_PWD           | No   | Web interface password (default: admin:1234)                               | 1234                   |
| BAK_APP_NAME      | Yes  | Name of the application to back up (used for distinguishing different apps) | uptime                 |
| BAK_DATA_DIR      | Yes     | Directory of the application data to back up                               | /app/data              |
| BAK_GITHUB_TOKEN  | Yes     | Personal Access Token (`PAT`) for GitHub backup                              |                        |
| BAK_REPO          | Yes     | 	Backup repository name                                                                     | xxx_repo               |
| BAK_REPO_OWNER    | Yes     | Owner of the backup repository                                                                   | xxx                    |
| BAK_PROXY         | No   | Proxy for backup (not needed if there's no network issue)                                                           | http://localhost:10808 |
| BAK_CRON          | No   | Cron schedule for backups (default: 0 0 0/1 * * ?)                                                 |                        |
| BAK_MAX_COUNT     | No   | Maximum number of backup files to keep in the repository (default: 5)                                                       | 5                      |
| BAK_LOG           | No   | Enable logging (for debugging)                                                                  | 1                      |
| BAK_BRANCH        | No   | Delay restore after container startup (in minutes)                                                           | main                   |
| BAK_DELAY_RESTORE | No   | Pull the latest backup and restore on startup (default: enabled)                                                 | 1                      |
| START_WITH_RESTORE | No   | Pull the latest backup and restore on startup (default: enabled)                                                         | 1                      |
| EXEC_SQL_CRON | No    | Scheduled SQL Tasks (SQLite Only)     | 0 0 2 1 * ?                                                                 |
| EXEC_SQL | No    | Execute SQL                     | DELETE FROM service_histories WHERE created_at < datetime('now', '-7 days') |
| SQLITE_PATH | No    | SQLite Database File Path              | /app/data/sqlite.db                                                         |
### Usage
1. Standalone
Create a config.yaml file in the same directory as backup2gh, with keys matching the environment variable names in lowercase:
```
bak_app_name: test
bak_data_dir: /app/data
bak_github_token: ***
bak_repo: backup-xxx
bak_repo_owner: owner
```
Run the following command
```
nohup ./backup2gh > /dev/null 2>&1 &
```

2. Using in a Dockerfile 
Example using Uptime Kuma in a Dockerfile:
```
FROM alpine AS builder
RUN apk add --no-cache nodejs npm git curl tar libc6-compat

RUN npm install npm -g

RUN adduser -D app
USER app
WORKDIR /home/app

RUN curl -L "https://github.com/laboratorys/backup2gh/releases/latest/download/backup2gh-linux-amd64.tar.gz" -o /tmp/backup2gh.tar.gz \
    && tar -xzf /tmp/backup2gh.tar.gz \
    && rm /tmp/backup2gh.tar.gz


RUN git clone https://github.com/louislam/uptime-kuma.git
WORKDIR /home/app/uptime-kuma
RUN npm run setup

EXPOSE 3001
CMD ["sh", "-c", "nohup /home/app/backup2gh & node server/server.js"]
```
### FAQ
1. Dependency issues on Alpine Linux:
 - To ensure backup2gh runs properly on an Alpine-based image, install the required dependencies:
   ```shell
   apk add --no-cache curl tar libc6-compat
   ```
 - Ubuntu-based images do not require libc6-compat.

2. Running the backup program at startup:
 - The backup program is executed before the main application using CMD.
 - You can also use ENTRYPOINT instead.
3. Multiple applications in a single repository:
 - If backing up multiple applications in the same repository, stagger the backup schedules to avoid SHA conflicts that may cause failures.
4. Backup frequency and retention:
 - In most cases, frequent backups are unnecessary.
 - Keeping too many backup files is also not recommended.
5. Security warning for Web UI:
 - The Web interface is intended for temporary or testing use only.
 - Do not use the default admin account in a production environment.

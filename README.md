## backup-to-github
### 特性
1. 主要是针对一些云容器在重启后，数据会丢失的低成本解决方案，尤其是很多基于sqlite的应用。
2. 适用范围：数据实时性要求没那么高的场景。
3. 定时备份数据到GitHub仓库
4. 容器重启时还原最近一次数据备份。
5. 仓库不存在时自动创建备份仓库（私有），备份仓库自带`GitHub Action`，定时清理提交历史，避免占用仓库空间
### 环境变量
| 变量名               | 是否必填 | 说明                         | 示例                     |
|-------------------|------|----------------------------|------------------------|
| RUN_MODE          | 否    | 运行模式                       | 1-独立运行(默认), 2-web      |
| WEB_PORT          | 否    | web端口                      | 默认8088                 |
| WEB_PATH           | 否    | web请求前缀，用于反代路径配置,默认空       | /backup2gh             |
| WEB_PWD           | 否    | web密码，默认账号：admin, 密码：1234  | 1234                   |
| BAK_APP_NAME      | 是    | 备份应用名称，用于区分不同应用的备份数据       | uptime                 |
| BAK_DATA_DIR      | 是    | 计划备份的应用程序数据目录              | /app/data              |
| BAK_GITHUB_TOKEN  | 是    | 备份github账号的`PAT`           |                        |
| BAK_REPO          | 是    | 备份仓库名称                     | xxx_repo               |
| BAK_REPO_OWNER    | 是    | 备份仓库拥有者                    | xxx                    |
| BAK_PROXY         | 否    | 备份代理，无网络问题无需设置此项           | http://localhost:10808 |
| BAK_CRON          | 否    | 定时备份数据，默认值：  0 0 0/1 * * ? |                        |
| BAK_MAX_COUNT     | 否    | 备份文件在仓库中保留的最大数量，默认：5       | 5                      |
| BAK_LOG           | 否    | 开启日志，用于调试                  | 1                      |
| BAK_BRANCH        | 否    | 备份仓库对应分支，默认：main           | main                   |
| BAK_DELAY_RESTORE | 否    | 还原延迟，容器启动后延迟还原data, 单位是分钟  | 1                      |
| START_WITH_RESTORE | 否    | 启动时拉取最新备份还原，默认开启           | 1                      |
### 使用
1. 单独部署：新建`config.yaml`配置文件, 并置于`backup2gh`同级目录，**属性配置对应环境变量的小写KEY**
```
bak_app_name: test
bak_data_dir: /app/data
bak_github_token: ***
bak_repo: backup-xxx
bak_repo_owner: owner
```
执行命令`nohup ./backup2gh > /dev/null 2>&1 &`

2. Dockerfile中使用
以Uptime Kuma的Dockerfile作为示例
```
FROM alpine AS builder
RUN apk add --no-cache nodejs npm git curl tar libc6-compat

RUN npm install npm -g

RUN adduser -D app
USER app
WORKDIR /home/app

RUN curl -L "https://github.com/laboratorys/backup2gh/releases/download/v${BAK_VERSION}/backup2gh-linux-amd64.tar.gz" -o /tmp/backup2gh.tar.gz \
    && tar -xzf /tmp/backup2gh.tar.gz \
    && rm /tmp/backup2gh.tar.gz


RUN git clone https://github.com/louislam/uptime-kuma.git
WORKDIR /home/app/uptime-kuma
RUN npm run setup

EXPOSE 3001
CMD ["sh", "-c", "nohup /home/app/backup2gh & node server/server.js"]
```
### 常见问题
1. 为确保alpine镜像可以顺利执行`backup2gh`， 需要安装依赖`curl tar libc6-compat`，ubuntu等镜像不需要额外安装`libc6-compat`
2. CMD命令将备份程序执行在前，也可以使用`ENTRYPOINT`
3. 单仓库多应用时，定时执行的时间尽量错开，避免SHA变更导致的备份失败。
4. 大部分情况下，备份频率不用很高、备份文件不用保留很多。
5. WEB仅供临时或测试使用，请勿在生产环境长时间使用默认账号`admin`

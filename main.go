package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	crypto_rand "crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/avast/retry-go"
	"github.com/gin-gonic/gin"
	"github.com/google/go-github/v62/github"
	"github.com/robfig/cron/v3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/nacl/box"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	template2 "html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"time"
)

var cfg Cfg
var tmpPath = os.TempDir()
var cronManager = cron.New(cron.WithSeconds())

const readmeTemplate = `# {{.Title}}

**上一次更新：{{.LastUpdate}}**

## 应用列表

| {{range .Table.Headers}}{{.}} | {{end}}
| {{range .Table.Headers}}---| {{end}}
{{range .Table.Rows}}| {{range .}}{{.}} | {{end}}
{{end}}
`
const clearHistoryWorkflowYml = `
name: Clear Git History
on:
  schedule:
    - cron: '10 22 * * *'
  workflow_dispatch:
jobs:
  clear-history:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
          fetch-depth: 0  # Fetch all history for all branches and tags
          token: ${{ secrets.PAT_TOKEN }}
      - name: Get default branch
        id: default_branch
        run: echo "::set-output name=branch::$(echo ${GITHUB_REF#refs/heads/})"
      - name: Remove git history
        env:
          DEFAULT_BRANCH: ${{ steps.default_branch.outputs.branch }}
        run: |
          git config --local user.email "github-actions[bot]@users.noreply.github.com"
          git config --local user.name "github-actions[bot]"
          git checkout --orphan tmp
          git add -A				# Add all files and commit them
          git commit -m "Reset all files"
          git branch -D $DEFAULT_BRANCH		# Deletes the default branch
          git branch -m $DEFAULT_BRANCH		# Rename the current branch to defaul
      - name: Push changes
        uses: ad-m/github-push-action@master
        with:
          force: true
          branch: ${{ github.ref }}
          github_token: ${{ secrets.PAT_TOKEN }}
`

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

var logFile *os.File

func main() {
	initConfig()
	// 初始化日志文件
	initLogFile()
	if cfg.BakRepo != "" && cfg.BakRepoOwner != "" && cfg.BakGithubToken != "" {
		LogEnv()
		if cfg.StartWithRestore == "1" {
			if cfg.BakDelayRestore != "" {
				//启动时延时还原数据
				delay, _ := strconv.Atoi(cfg.BakDelayRestore)
				time.Sleep(time.Duration(delay) * time.Minute)
			}
			Restore()
		}
		//定时备份
		CronTask()
		if cfg.RunMode == "2" {
			if cfg.BakLog == "1" {
				gin.SetMode(gin.DebugMode)
			} else {
				gin.SetMode(gin.ReleaseMode)
			}
			r := gin.Default()
			t, _ := template2.New("custom").Delims("<<", ">>").ParseFS(templatesFS, "templates/*")
			r.SetHTMLTemplate(t)
			basePath := ""
			if cfg.WebPath != "/" {
				basePath = cfg.WebPath
			}
			r.StaticFS(basePath+"/fs", http.FS(staticFS))
			authorized := r.Group(basePath, gin.BasicAuth(gin.Accounts{
				"admin": cfg.WebPwd,
			}))
			authorized.GET("/", func(c *gin.Context) {
				c.HTML(http.StatusOK, "index.html", gin.H{
					"title":     "backup2gh",
					"base_path": basePath,
				})
				//test
				/*data, err := os.ReadFile("D:\\backup2gh\\templates\\index.html")
				if err != nil {
					fmt.Println(err)
					return
				}
				c.Data(http.StatusOK, "text/html; charset=utf-8", data)*/
			})
			authorized.GET("/config", func(c *gin.Context) {
				c.JSON(http.StatusOK, cfg)
			})
			authorized.GET("/backups", func(c *gin.Context) {
				c.JSON(http.StatusOK, getBackUps())
			})
			authorized.GET("/backup/run", func(c *gin.Context) {
				go Backup()
				c.JSON(http.StatusOK, gin.H{})
			})
			authorized.POST("/config", func(c *gin.Context) {
				_ = c.BindJSON(&cfg)
				c.JSON(http.StatusOK, gin.H{})
				LogEnv()
			})
			authorized.POST("/backup/delete", func(c *gin.Context) {
				content := github.RepositoryContent{}
				_ = c.BindJSON(&content)
				err := deleteBackup(content)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{})
				} else {
					c.JSON(http.StatusOK, gin.H{})
				}
			})
			authorized.POST("/backup/restore", func(c *gin.Context) {
				content := github.RepositoryContent{}
				_ = c.BindJSON(&content)
				RestoreFromContent(&content)
				c.JSON(http.StatusOK, gin.H{})
			})
			authorized.GET("/config/export", func(c *gin.Context) {
				exportType := c.Query("type")
				name := "config.yaml"
				if exportType == "1" {
					name = "env.txt"
				}
				c.Header("Content-Disposition", "attachment; filename="+url.QueryEscape(name))
				c.Header("Content-Transfer-Encoding", "binary")
				c.Data(http.StatusOK, "application/octet-stream", getConfigData(exportType))
			})
			_ = r.Run(fmt.Sprintf(":%s", cfg.WebPort))
		} else {
			defer cronManager.Stop()
			select {}
		}
	} else {
		debugLog("No Valid Config found!")
	}
	defer logFile.Close()
}

func initLogFile() {
	if cfg.BakLog == "1" {
		var err error
		logFile, err = os.OpenFile("debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("无法打开日志文件: %v", err)
		}
		mw := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
	}
	defer func() {
		if r := recover(); r != nil {
			debugLog("发生严重错误: %v\n", r)
		}
	}()
}

func getConfigData(exportType string) []byte {
	if exportType == "1" {
		v := reflect.ValueOf(cfg)
		t := v.Type()
		var envText string
		for i := 0; i < v.NumField(); i++ {
			key := t.Field(i).Tag.Get("yaml")
			value := fmt.Sprintf("%v", v.Field(i).Interface())
			key = strings.ToUpper(key)
			envText += fmt.Sprintf("%s=%s\n", key, value)
		}
		return []byte(envText)
	} else {
		data, err := yaml.Marshal(&cfg)
		if err != nil {
			debugLog("Error marshalling YAML:", err)
			return nil
		}
		return data
	}
}

func deleteBackup(dc github.RepositoryContent) error {
	ctx := context.Background()
	client, err := getClient()
	commitMessage := "Delete file by api."
	if err != nil {
		log.Printf("Delete backup err: %v", err)
		return err
	}
	_, _, err = client.Repositories.DeleteFile(ctx, cfg.BakRepoOwner, cfg.BakRepo, *dc.Path, &github.RepositoryContentFileOptions{
		Message: &commitMessage,
		SHA:     dc.SHA,
		Branch:  &cfg.BakBranch,
	})
	return err
}
func getClient() (*github.Client, error) {
	proxyURL, err := url.Parse(cfg.BakProxy)
	if err != nil {
		log.Printf("Failed to parse proxy URL: %v", err)
		return nil, err
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	// 创建带有代理的 HTTP 客户端
	httpClient := &http.Client{
		Transport: transport,
	}
	if cfg.BakProxy == "" {
		httpClient = nil
	}
	client := github.NewClient(httpClient).WithAuthToken(cfg.BakGithubToken)
	return client, nil
}

func initConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			viper.BindEnv("bak_app_name", "BAK_APP_NAME")
			viper.BindEnv("bak_cron", "BAK_CRON")
			viper.BindEnv("bak_branch", "BAK_BRANCH")
			viper.BindEnv("bak_data_dir", "BAK_DATA_DIR")
			viper.BindEnv("bak_github_token", "BAK_GITHUB_TOKEN")
			viper.BindEnv("bak_proxy", "BAK_PROXY")
			viper.BindEnv("bak_log", "BAK_LOG")
			viper.BindEnv("bak_max_count", "BAK_MAX_COUNT")
			viper.BindEnv("bak_repo", "BAK_REPO")
			viper.BindEnv("bak_repo_owner", "BAK_REPO_OWNER")
			viper.BindEnv("bak_delay_restore", "BAK_DELAY_RESTORE")
			viper.BindEnv("run_mode", "RUN_MODE")
			viper.BindEnv("web_port", "WEB_PORT")
			viper.BindEnv("web_pwd", "WEB_PWD")
			viper.BindEnv("start_with_restore", "START_WITH_RESTORE")
			viper.BindEnv("web_path", "WEB_PATH")
			viper.BindEnv("sqlite_path", "SQLITE_PATH")
			viper.BindEnv("exec_sql", "EXEC_SQL")
			viper.BindEnv("exec_sql_cron", "EXEC_SQL_CRON")
		}
	} else {
		debugLog("读取到config.yaml文件")
	}
	viper.SetDefault("bak_delay_restore", "0")
	viper.SetDefault("start_with_restore", "1")
	viper.SetDefault("bak_log", "0")
	viper.SetDefault("bak_max_count", "5")
	viper.SetDefault("bak_branch", "main")
	viper.SetDefault("bak_cron", "0 0 0/1 * * ?")
	viper.SetDefault("run_mode", "1")
	viper.SetDefault("web_port", "8088")
	viper.SetDefault("web_path", "")
	viper.SetDefault("web_pwd", "1234")
	viper.SetDefault("sqlite_path", "")
	viper.SetDefault("exec_sql", "")
	viper.SetDefault("exec_sql_cron", "0 0 2 1 * ?")
	_ = viper.Unmarshal(&cfg)
}

type Cfg struct {
	AppName          string `yaml:"bak_app_name" json:"bak_app_name" mapstructure:"bak_app_name"`
	BakCron          string `yaml:"bak_cron" json:"bak_cron" mapstructure:"bak_cron"`
	BakBranch        string `yaml:"bak_branch" json:"bak_branch" mapstructure:"bak_branch"`
	BakDataDir       string `yaml:"bak_data_dir" json:"bak_data_dir" mapstructure:"bak_data_dir"`
	BakGithubToken   string `yaml:"bak_github_token" json:"bak_github_token" mapstructure:"bak_github_token"`
	BakLog           string `yaml:"bak_log" json:"bak_log" mapstructure:"bak_log"`
	BakMaxCount      string `yaml:"bak_max_count" json:"bak_max_count" mapstructure:"bak_max_count"`
	BakProxy         string `yaml:"bak_proxy" json:"bak_proxy" mapstructure:"bak_proxy"`
	BakRepo          string `yaml:"bak_repo" json:"bak_repo" mapstructure:"bak_repo"`
	BakRepoOwner     string `yaml:"bak_repo_owner" json:"bak_repo_owner" mapstructure:"bak_repo_owner"`
	BakDelayRestore  string `yaml:"bak_delay_restore" json:"bak_delay_restore" mapstructure:"bak_delay_restore"`
	RunMode          string `yaml:"run_mode" json:"run_mode" mapstructure:"run_mode"`
	WebPort          string `yaml:"web_port" json:"web_port" mapstructure:"web_port"`
	WebPwd           string `yaml:"web_pwd" json:"web_pwd" mapstructure:"web_pwd"`
	StartWithRestore string `yaml:"start_with_restore" json:"start_with_restore" mapstructure:"start_with_restore"`
	WebPath          string `yaml:"web_path" json:"web_path" mapstructure:"web_path"`
	SqlitePath       string `yaml:"sqlite_path" json:"sqlite_path" mapstructure:"sqlite_path"`
	ExecSql          string `yaml:"exec_sql" json:"exec_sql" mapstructure:"exec_sql"`
	ExecSqlCron      string `yaml:"exec_sql_cron" json:"exec_sql_cron" mapstructure:"exec_sql_cron"`
}

func LogEnv() {
	debugLog("BAK_APP_NAME：%s", cfg.AppName)
	debugLog("BAK_REPO_OWNER：%s", cfg.BakRepoOwner)
	debugLog("BAK_REPO：%s", cfg.BakRepo)
	debugLog("BAK_GITHUB_TOKEN：%s", "***********")
	debugLog("BAK_DATA_DIR：%s", cfg.BakDataDir)
	debugLog("BAK_PROXY：%s", cfg.BakProxy)
	debugLog("BAK_CRON：%s", cfg.BakCron)
	debugLog("BAK_MAX_COUNT：%s", cfg.BakMaxCount)
	debugLog("BAK_LOG：%s", cfg.BakLog)
	debugLog("BAK_BRANCH：%s", cfg.BakBranch)
	debugLog("BAK_DELAY_RESTORE：%s", cfg.BakDelayRestore)
	debugLog("TMP_PATH：%s", tmpPath)
	debugLog("RUN_MODE：%s", cfg.RunMode)
	debugLog("WEB_PORT：%s", cfg.WebPort)
	debugLog("WEB_PWD：%s", "****")
	debugLog("WEB_PATH：%s", cfg.WebPath)
	debugLog("WEB_PATH：%s", cfg.WebPath)
	debugLog("SQLITE_PATH：%s", cfg.SqlitePath)
	debugLog("EXEC_SQL：%s", cfg.ExecSql)
	debugLog("EXEC_SQL_CRON：%s", cfg.ExecSqlCron)
}
func CronTask() {
	cronManager.AddFunc(cfg.BakCron, func() {
		retry.Do(
			func() error {
				return Backup()
			},
			retry.Delay(30*time.Second),
			retry.Attempts(4),
			retry.DelayType(retry.FixedDelay),
		)
	})
	if cfg.ExecSqlCron != "" {
		cronManager.AddFunc(cfg.ExecSqlCron, func() {
			retry.Do(
				func() error {
					return ExecSql()
				},
				retry.Delay(30*time.Second),
				retry.Attempts(4),
				retry.DelayType(retry.FixedDelay),
			)
		})
	}
	cronManager.Start()
}
func ExecSql() error {
	var err error
	db, err := gorm.Open(sqlite.Open(cfg.SqlitePath), &gorm.Config{})
	if err == nil {
		result := db.Exec(cfg.ExecSql)
		if result.Error != nil {
			debugLog("exec sql failed: %v", result.Error)
			err = result.Error
		} else {
			rowsAffected := result.RowsAffected
			debugLog("exec sql success: %d", rowsAffected)
		}
	}
	return err
}
func Restore() {
	lockFile := "restore.lock"
	if _, err := os.Stat(lockFile); err == nil {
		debugLog("Restore operation is already in progress by another process, skipping")
		return
	}

	// Create lock file
	if err := os.WriteFile(lockFile, []byte("locked"), 0644); err != nil {
		debugLog("Failed to create lock file: %v", err)
		return
	}
	defer func() {
		if err := os.Remove(lockFile); err != nil {
			debugLog("Failed to delete lock file: %v", err)
		}
	}()

	ctx := context.Background()
	client, err := getClient()
	if err != nil {
		debugLog("Failed to get client: %v", err)
		return
	}

	_, dirContents, _, err := client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, cfg.AppName, nil)
	if err != nil {
		debugLog("Failed to fetch repository contents: %v", err)
		return
	}

	if len(dirContents) > 0 {
		content := dirContents[len(dirContents)-1]
		RestoreFromContent(content)
	}
}

func RestoreFromContent(content *github.RepositoryContent) {
	debugLog("Get Last Backup File: %s， Size: %d，Url: %s", content.GetPath(), content.GetSize(), content.GetDownloadURL())
	dUrl := content.GetDownloadURL()
	//下载、解压文件
	zipFilePath := filepath.Join(tmpPath, *content.Name)
	err := DownloadFile(dUrl, zipFilePath)
	debugLog("DownloadFile: %s", zipFilePath)
	err = Unzip(zipFilePath, cfg.BakDataDir)
	err = os.Remove(zipFilePath)
	debugLog("Unzip && Remove: %s", zipFilePath)
	if err != nil {
		debugLog("RestoreFromContent error: %v", err)
	}
}

func debugLog(str string, v ...any) {
	if cfg.BakLog == "1" {
		if v != nil {
			log.Printf(str, v...)
		} else {
			log.Println(str)
		}
	}
}

func errLog(str string, v ...any) {
	if cfg.BakLog == "1" {
		str = "error: " + str
		if v != nil {
			log.Printf(str, v...)
		} else {
			log.Println(str)
		}
	}
}
func getBackUps() []*github.RepositoryContent {
	ctx := context.Background()
	client, _ := getClient()
	_, dirContents, _, _ := client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, cfg.AppName, &github.RepositoryContentGetOptions{Ref: cfg.BakBranch})
	return dirContents
}

func Backup() error {
	ctx := context.Background()
	chineseTimeStr(time.Now(), "200601021504")
	fileName := chineseTimeStr(time.Now(), "200601021504") + ".zip"
	zipFilePath := filepath.Join(tmpPath, fileName)
	debugLog("Start Zip File: %s", zipFilePath)
	tmpBakDir := filepath.Join(tmpPath, "data")
	er := CopyDir(cfg.BakDataDir, tmpBakDir)
	if er != nil {
		return er
	}
	Zip(tmpBakDir, zipFilePath)
	commitMessage := "Add File"
	fileContent, _ := os.ReadFile(zipFilePath)
	client, err := getClient()
	if err != nil {
		return err
	}
	_, resp, _ := client.Repositories.Get(ctx, cfg.BakRepoOwner, cfg.BakRepo)
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		if _, _, err = client.Repositories.Create(ctx, "", &github.Repository{
			Name:          github.String(cfg.BakRepo),
			Private:       github.Bool(true),
			DefaultBranch: github.String(cfg.BakBranch),
		}); err != nil {
			log.Printf("failed to create repo: %s", err)
		}
		debugLog("Create Repo: %s", cfg.BakRepo)
	}
	err = AddOrUpdateFile(client, ctx, cfg.BakBranch, cfg.AppName+"/"+fileName, fileContent)
	if err != nil {
		return err
	}
	err = os.Remove(zipFilePath)
	//查询仓库中备份文件数量
	count, err := strconv.Atoi(cfg.BakMaxCount)
	if err != nil {
		count = 5
	}
	_, dirContents, _, _ := client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, cfg.AppName, &github.RepositoryContentGetOptions{Ref: cfg.BakBranch})
	commitMessage = "clean file"
	if len(dirContents) > count {
		for i, dc := range dirContents {
			if i+1 <= len(dirContents)-count {
				client.Repositories.DeleteFile(ctx, cfg.BakRepoOwner, cfg.BakRepo, *dc.Path, &github.RepositoryContentFileOptions{
					Message: &commitMessage,
					SHA:     dc.SHA,
					Branch:  &cfg.BakBranch,
				})
			}

		}

	}
	_, dirContents, _, _ = client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, "", &github.RepositoryContentGetOptions{Ref: cfg.BakBranch})
	rows := [][]string{}
	isFirstInit := true
	if len(dirContents) > 0 {
		i := 0
		for _, dc := range dirContents {
			if dc.GetName() == ".github" {
				isFirstInit = false
			}
			if dc.GetType() == "dir" && dc.GetName() != ".github" {
				commits, _, _ := client.Repositories.ListCommits(ctx, cfg.BakRepoOwner, cfg.BakRepo, &github.CommitsListOptions{
					Path: dc.GetPath(),
					ListOptions: github.ListOptions{
						PerPage: 1,
					},
				})
				commitDate := commits[0].GetCommit().GetAuthor().GetDate()
				_, dcs, _, _ := client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, dc.GetPath(), &github.RepositoryContentGetOptions{Ref: cfg.BakBranch})
				row := []string{}
				i++
				row = append(row,
					fmt.Sprintf("%d", i),
					dc.GetName(),
					chineseTimeStr(commitDate.Time, "2006-01-02 15:04:05"),
					fmt.Sprintf("[%s](%s)", dcs[len(dcs)-1].GetName(), dcs[len(dcs)-1].GetDownloadURL()))
				rows = append(rows, row)
			}
		}
	}
	_, dirContents, _, err = client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, "", &github.RepositoryContentGetOptions{Ref: cfg.BakBranch})
	if len(rows) > 0 {
		readmeContent := ReadmeData{
			Title:      cfg.BakRepo,
			LastUpdate: chineseTimeStr(time.Now(), "2006-01-02 15:04:05"),
			Table: TableData{
				Headers: []string{"序号", "应用名称", "更新时间", "最近一次备份"},
				Rows:    rows,
			},
		}
		tmpl, _ := template.New("readme").Parse(readmeTemplate)
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, readmeContent)
		if err != nil {
			return err
		}
		readmeStr := buf.String()
		debugLog(readmeStr)
		_ = AddOrUpdateFile(client, ctx, cfg.BakBranch, "README.md", []byte(readmeStr))
	}
	if isFirstInit {
		_ = AddOrUpdateFile(client, ctx, cfg.BakBranch, ".github/workflows/clear-history.yml", []byte(clearHistoryWorkflowYml))
		input := &github.DefaultWorkflowPermissionRepository{
			DefaultWorkflowPermissions: github.String("write"),
		}
		_, _, _ = client.Repositories.EditDefaultWorkflowPermissions(ctx, cfg.BakRepoOwner, cfg.BakRepo, *input)
		_ = addRepoSecret(ctx, client, cfg.BakRepoOwner, cfg.BakRepo, "PAT_TOKEN", cfg.BakGithubToken)
	}
	return nil
}
func addRepoSecret(ctx context.Context, client *github.Client, owner string, repo, secretName string, secretValue string) error {
	publicKey, _, err := client.Actions.GetRepoPublicKey(ctx, owner, repo)
	if err != nil {
		return err
	}

	encryptedSecret, err := encryptSecretWithPublicKey(publicKey, secretName, secretValue)
	if err != nil {
		return err
	}

	if _, err := client.Actions.CreateOrUpdateRepoSecret(ctx, owner, repo, encryptedSecret); err != nil {
		return fmt.Errorf("Actions.CreateOrUpdateRepoSecret returned error: %v", err)
	}

	return nil
}

func encryptSecretWithPublicKey(publicKey *github.PublicKey, secretName string, secretValue string) (*github.EncryptedSecret, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey.GetKey())
	if err != nil {
		return nil, fmt.Errorf("base64.StdEncoding.DecodeString was unable to decode public key: %v", err)
	}

	var boxKey [32]byte
	copy(boxKey[:], decodedPublicKey)
	encryptedBytes, err := box.SealAnonymous([]byte{}, []byte(secretValue), &boxKey, crypto_rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("box.SealAnonymous failed with error %w", err)
	}

	encryptedString := base64.StdEncoding.EncodeToString(encryptedBytes)
	keyID := publicKey.GetKeyID()
	encryptedSecret := &github.EncryptedSecret{
		Name:           secretName,
		KeyID:          keyID,
		EncryptedValue: encryptedString,
	}
	return encryptedSecret, nil
}
func AddOrUpdateFile(client *github.Client, ctx context.Context, branch, filePath string, fileContent []byte) error {
	newFile := false
	fc, _, _, err := client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, filePath, &github.RepositoryContentGetOptions{Ref: branch})
	if err != nil {
		responseErr, ok := err.(*github.ErrorResponse)
		if !ok || responseErr.Response.StatusCode != 404 {
			newFile = false
		} else {
			newFile = true
		}
	}
	currentSHA := ""
	commitMessage := fmt.Sprintf("Add file: %s", filePath)
	if !newFile {
		currentSHA = *fc.SHA
		commitMessage = fmt.Sprintf("Update file: %s", filePath)
		_, _, err = client.Repositories.UpdateFile(ctx, cfg.BakRepoOwner, cfg.BakRepo, filePath, &github.RepositoryContentFileOptions{
			Message: &commitMessage,
			SHA:     &currentSHA,
			Content: fileContent,
			Branch:  &branch,
		})
	} else {
		_, _, err = client.Repositories.CreateFile(ctx, cfg.BakRepoOwner, cfg.BakRepo, filePath, &github.RepositoryContentFileOptions{
			Message: &commitMessage,
			Content: fileContent,
			Branch:  &branch,
		})
	}
	if err != nil {
		log.Println(err)
	}
	return err
}

func DownloadFile(downUrl, filePath string) error {

	tr := &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	}}
	if cfg.BakProxy != "" {
		proxyUrl, err := url.Parse(cfg.BakProxy)
		if err == nil {
			tr.Proxy = http.ProxyURL(proxyUrl)
		}
	}

	// 创建一个带有自定义 Transport 的 Client
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodGet, downUrl, nil)
	if err != nil {
		return err
	}
	r, err := client.Do(req)
	if err != nil {
		return err
	}
	if r != nil {
		defer r.Body.Close()
	}

	// 获得get请求响应的reader对象
	reader := bufio.NewReaderSize(r.Body, 32*1024)
	file, err := os.Create(filePath)
	defer file.Close()
	if err != nil {
		return err
	}
	// 获得文件的writer对象
	writer := bufio.NewWriter(file)

	_, err = io.Copy(writer, reader)
	return err
}

// CopyDir 递归复制文件夹
func CopyDir(src, dst string) error {
	// 校验源目录合法性
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("源目录不存在: %v", err)
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("%s 不是目录", src)
	}

	// 创建目标目录 (保留原目录权限)
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("创建目标目录失败: %v", err)
	}

	// 遍历源目录
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err // 优先处理遍历错误
		}

		// 计算相对路径
		relPath, _ := filepath.Rel(src, path)
		dstPath := filepath.Join(dst, relPath)

		// 处理目录
		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		// 处理常规文件
		return copyFile(path, dstPath, info)
	})
}

// copyFile 复制单个文件 (保留权限和时间戳)
func copyFile(src, dst string, info os.FileInfo) error {
	// 打开源文件
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("打开源文件失败: %v", err)
	}
	defer srcFile.Close()

	// 创建目标文件 (同权限)
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode())
	if err != nil {
		return fmt.Errorf("创建目标文件失败: %v", err)
	}
	defer dstFile.Close()

	// 复制内容
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("复制内容失败: %v", err)
	}

	// 保留修改时间
	if err := os.Chtimes(dst, info.ModTime(), info.ModTime()); err != nil {
		return fmt.Errorf("保留时间戳失败: %v", err)
	}

	return nil
}

// 打包成zip文件
func Zip(src_dir string, zip_file_name string) {
	// 预防：旧文件无法覆盖
	os.RemoveAll(zip_file_name)

	// 创建：zip文件
	zipfile, _ := os.Create(zip_file_name)
	defer zipfile.Close()

	// 打开：zip文件
	archive := zip.NewWriter(zipfile)
	defer archive.Close()

	// 遍历路径信息
	filepath.Walk(src_dir, func(path string, info os.FileInfo, _ error) error {
		// 如果是源路径，提前进行下一个遍历
		if path == src_dir {
			return nil
		}
		_, er := os.Stat(path)
		if er != nil {
			return nil
		}
		// 获取：文件头信息
		header, err := zip.FileInfoHeader(info)
		if err == nil {
			relPath, _ := filepath.Rel(src_dir, path)
			header.Name = filepath.ToSlash(relPath)

			// 判断：文件是不是文件夹
			if info.IsDir() {
				header.Name += "/"
			} else {
				// 设置：zip的文件压缩算法
				header.Method = zip.Deflate
			}
			// 创建：压缩包头部信息
			writer, _ := archive.CreateHeader(header)
			if !info.IsDir() {
				file, _ := os.Open(path)
				defer file.Close()
				io.Copy(writer, file)
			}
		}
		return nil
	})
}

func Unzip(zipPath, dstDir string) error {
	// open zip file
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, file := range reader.File {
		if err := unzipFile(file, dstDir); err != nil {
			return err
		}
	}
	return nil
}

func unzipFile(file *zip.File, dstDir string) error {
	// create the directory of file
	filePath := path.Join(dstDir, file.Name)
	if file.FileInfo().IsDir() {
		if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return err
	}

	// open the file
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	// create the file
	w, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer w.Close()

	// save the decompressed file content
	_, err = io.Copy(w, rc)
	return err
}

type TableData struct {
	Headers []string
	Rows    [][]string
}

type ReadmeData struct {
	Title      string
	LastUpdate string
	Table      TableData
}

func chineseTimeStr(t time.Time, layout string) string {
	loc := time.FixedZone("UTC+8", 8*60*60)
	currentTime := t.In(loc)
	formattedTime := currentTime.Format(layout)
	return formattedTime
}
